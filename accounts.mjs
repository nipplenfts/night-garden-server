import { createHash, randomBytes, randomInt, scrypt, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { promisify } from 'node:util';

const port = Number(process.argv[3] || process.env.NIGHT_GARDEN_PORT || process.env.PORT || 47839);
const bindHost = process.env.NIGHT_GARDEN_HOST || "127.0.0.1";
const databasePath = resolve(process.env.NIGHT_GARDEN_ACCOUNTS_DB || process.argv[2] || 'night-garden-accounts.sqlite');
const hours = 60 * 60 * 1000;
const derive = promisify(scrypt);
const hash = (value) => createHash('sha256').update(value).digest('hex');
mkdirSync(dirname(databasePath), { recursive: true });
const db = new DatabaseSync(databasePath);
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 3000;
  CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    login_key TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS leaderboard (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id),
    xp INTEGER NOT NULL,
    gold INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS leaderboard_xp ON leaderboard(xp DESC, account_id);
  CREATE INDEX IF NOT EXISTS leaderboard_gold ON leaderboard(gold DESC, account_id);
  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    message TEXT NOT NULL,
    sent_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS chat_sender ON chat_messages(account_id, id);
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    expires_at INTEGER NOT NULL
  );
`);

if (!db.prepare('PRAGMA table_info(chat_messages)').all().some((column) => column.name === 'profile')) {
  db.exec('ALTER TABLE chat_messages ADD COLUMN profile TEXT');
}

if (!db.prepare('PRAGMA table_info(leaderboard)').all().some((column) => column.name === 'profile')) {
  db.exec('ALTER TABLE leaderboard ADD COLUMN profile TEXT');
}

const chatFrames = new Set([
  'silver', 'silver_laurel', 'silver_filigree', 'silver_starlight', 'silver_crown', 'gold',
  'staff_copper', 'staff_silver', 'staff_amber', 'staff_blue', 'staff_emerald',
]);

function chatProfile(input, username) {
  const validInt = (value, min, max, fallback) =>
    Number.isSafeInteger(value) && value >= min && value <= max ? value : fallback;
  return {
    username,
    gender: input?.gender === 'male' ? 'male' : 'female',
    hair_style: validInt(input?.hair_style, 0, 2, 0),
    hair_color: validInt(input?.hair_color, 0, 3, 0),
    frame: chatFrames.has(input?.frame) ? input.frame : 'silver',
    level: validInt(input?.level, 1, 1000000000, null),
  };
}

const byUsername = db.prepare('SELECT * FROM accounts WHERE login_key = ?');
const byId = db.prepare('SELECT id FROM accounts WHERE id = ?');
const insertAccount = db.prepare('INSERT INTO accounts VALUES (?, ?, ?, ?, ?)');
const renameAccount = db.prepare('UPDATE accounts SET username = ?, login_key = ? WHERE id = ?');
const insertSession = db.prepare('INSERT INTO sessions VALUES (?, ?, ?)');
const getSession = db.prepare(`
  SELECT accounts.id, accounts.username FROM sessions JOIN accounts ON accounts.id = sessions.account_id
  WHERE sessions.token_hash = ? AND sessions.expires_at > ?
`);
const deleteSession = db.prepare('DELETE FROM sessions WHERE token_hash = ?');
const clearExpired = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
const recentChat = db.prepare(`
  SELECT chat_messages.id, accounts.username, message, sent_at, profile
  FROM chat_messages JOIN accounts ON accounts.id = chat_messages.account_id
  ORDER BY chat_messages.id DESC LIMIT 20
`);
function chatHistory() {
  return recentChat.all().reverse().map(({ profile, username, ...entry }) => {
    const snapshot = profile ? JSON.parse(profile) : null;
    return { ...entry, ...chatProfile(snapshot, snapshot?.username ?? username) };
  });
}
const lastChat = db.prepare('SELECT sent_at FROM chat_messages WHERE account_id = ? ORDER BY id DESC LIMIT 1');
const insertChat = db.prepare('INSERT INTO chat_messages (account_id, message, sent_at, profile) VALUES (?, ?, ?, ?)');
const trimChat = db.prepare('DELETE FROM chat_messages WHERE id <= ?');
const updateScore = db.prepare(`
  INSERT INTO leaderboard (account_id, xp, gold, profile) VALUES (?, ?, ?, ?)
  ON CONFLICT(account_id) DO UPDATE SET xp = MAX(xp, excluded.xp), gold = MAX(gold, excluded.gold),
    profile = COALESCE(excluded.profile, leaderboard.profile)
`);
const leaderboardQueries = Object.fromEntries(['level', 'gold'].map((metric) => {
  const column = metric === 'level' ? 'xp' : 'gold';
  return [metric, db.prepare(`
    SELECT standings.rank, accounts.username, standings.xp, standings.gold, standings.profile,
           standings.account_id = ? AS is_you
    FROM (
      SELECT account_id, xp, gold, profile,
             ROW_NUMBER() OVER (ORDER BY ${column} DESC, account_id) AS rank
      FROM leaderboard
    ) AS standings
    JOIN accounts ON accounts.id = standings.account_id
    WHERE standings.rank <= 20 OR standings.account_id = ?
    ORDER BY standings.rank
  `)];
}));
const dummySalt = randomBytes(16);
const attempts = new Map();
const throttleWindow = 60_000;
setInterval(() => {
  const now = Date.now();
  for (const [address, entry] of attempts) {
    if (entry.until <= now) attempts.delete(address);
  }
  clearExpired.run(now);
}, throttleWindow).unref();

function normalizedUsername(input) {
  const value = typeof input === 'string' ? input.normalize('NFC').trim() : '';
  if ([...value].length < 2 || [...value].length > 24 || !/^[\p{L}\p{M}\p{N} _.-]+$/u.test(value) || !/[\p{L}\p{N}]/u.test(value)) {
    return null;
  }
  return { value, key: value.toLowerCase().normalize('NFC') };
}

function validPassword(password) {
  return typeof password === 'string' && [...password].length >= 8 && [...password].length <= 128;
}

function derivePassword(password, salt) {
  return derive(password, salt, 64, { N: 32768, r: 8, p: 2, maxmem: 64 * 1024 * 1024 });
}

async function payload(request) {
  let bytes = 0;
  const chunks = [];
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > 8192) throw new Error('Invalid body');
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('Invalid body');
  return value;
}

function send(response, status, value) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(value));
}

function issueSession(response, id, username, remember) {
  const token = randomBytes(32).toString('hex');
  insertSession.run(hash(token), id, Date.now() + hours * (remember === true ? 720 : 12));
  send(response, 200, { id, username, token });
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === 'GET' && request.url === '/health') return send(response, 200, { ready: true, chat: true });
    if (request.method !== 'POST') return send(response, 404, { error: 'Unknown request.' });

    if (request.url === '/register' || request.url === '/login') {
      const address = request.socket.remoteAddress;
      const now = Date.now();
      let entry = attempts.get(address);
      if (!entry || entry.until <= now) {
        entry = { count: 0, until: now + throttleWindow };
        attempts.set(address, entry);
      }
      if (++entry.count > 20) return send(response, 429, { error: 'Too many sign-in attempts. Try again in a minute.' });
      const body = await payload(request);
      const name = normalizedUsername(body.username);
      if (request.url === '/register') {
        if (!name) return send(response, 400, { error: 'Use 2–24 characters: letters, numbers, spaces, dots, dashes or underscores.' });
        if (!validPassword(body.password)) return send(response, 400, { error: 'Use a password with 8–128 characters.' });
        const salt = randomBytes(16);
        const passwordHash = await derivePassword(body.password, salt);
        if (byUsername.get(name.key)) return send(response, 409, { error: 'That username is taken.' });
        let id;
        do id = '#' + String(randomInt(100_000_000)).padStart(8, '0'); while (byId.get(id));
        insertAccount.run(id, name.value, name.key, salt.toString('hex'), passwordHash.toString('hex'));
        return issueSession(response, id, name.value, body.remember);
      }
      const account = name ? byUsername.get(name.key) : null;
      const password = validPassword(body.password) ? body.password : '';
      const candidate = await derivePassword(password, account ? Buffer.from(account.salt, 'hex') : dummySalt);
      if (!account || !timingSafeEqual(candidate, Buffer.from(account.password_hash, 'hex'))) {
        return send(response, 401, { error: 'That username and password don’t match.' });
      }
      // A username changed during password verification is no longer a valid login.
      const current = byUsername.get(name.key);
      if (!current || current.id !== account.id) return send(response, 401, { error: 'That username and password don’t match.' });
      return issueSession(response, current.id, current.username, body.remember);
    }

    const token = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.authorization || '')?.[1];
    const digest = token ? hash(token) : '';
    const account = digest ? getSession.get(digest, Date.now()) : null;
    if (!account) return send(response, 401, { error: 'Your session ended. Sign in again.' });
    if (request.url === '/leaderboard') {
      const body = await payload(request);
      if (![body.xp, body.gold].every((score) => Number.isSafeInteger(score) && score >= 0)) {
        return send(response, 400, { error: 'Invalid leaderboard score.' });
      }
      if (body.metric !== undefined && !['level', 'gold'].includes(body.metric)) {
        return send(response, 400, { error: 'Unknown leaderboard.' });
      }
      const profile = body.profile ? JSON.stringify(chatProfile(body.profile, account.username)) : null;
      updateScore.run(account.id, body.xp, body.gold, profile);
      if (body.metric === undefined) return send(response, 200, { updated: true });
      const rows = leaderboardQueries[body.metric].all(account.id, account.id).map(({ xp, profile, ...row }) => ({
        ...row, ...chatProfile(profile ? JSON.parse(profile) : null, row.username),
        level: 1 + Math.floor(Math.sqrt(xp / 12)),
      }));
      return send(response, 200, { rows });
    }
    if (request.url === '/chat/messages') return send(response, 200, { messages: chatHistory() });
    if (request.url === '/chat/send') {
      const body = await payload(request);
      const message = typeof body.message === 'string' ? body.message.replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, ' ').trim() : '';
      if (!message || [...message].length > 200) return send(response, 400, { error: 'Enter a message of 1–200 characters.' });
      const now = Date.now();
      if (now - (lastChat.get(account.id)?.sent_at ?? 0) < 2500) {
        return send(response, 429, { error: 'Wait a moment before sending another message.' });
      }
      const result = insertChat.run(account.id, message, now, JSON.stringify(chatProfile(body.profile, account.username)));
      trimChat.run(Number(result.lastInsertRowid) - 100);
      return send(response, 200, { messages: chatHistory() });
    }
    if (request.url === '/session') return send(response, 200, account);
    if (request.url === '/logout') {
      deleteSession.run(digest);
      return send(response, 200, { signed_out: true });
    }
    if (request.url === '/rename') {
      const body = await payload(request);
      const name = normalizedUsername(body.username);
      if (!name) return send(response, 400, { error: 'Use 2–24 characters: letters, numbers, spaces, dots, dashes or underscores.' });
      const owner = byUsername.get(name.key);
      if (owner && owner.id !== account.id) return send(response, 409, { error: 'That username is taken.' });
      renameAccount.run(name.value, name.key, account.id);
      return send(response, 200, { id: account.id, username: name.value });
    }
    return send(response, 404, { error: 'Unknown request.' });
  } catch (error) {
    if (!response.headersSent && !response.destroyed) {
      send(response, error instanceof SyntaxError || error.message === 'Invalid body' ? 400 : 500,
        { error: error instanceof SyntaxError || error.message === 'Invalid body' ? 'Invalid request.' : 'The account server couldn’t complete the request.' });
    }
  }
});

server.on('error', (error) => {
  if (error.code !== 'EADDRINUSE' || bindHost !== '127.0.0.1') {
    process.stderr.write('The Night Garden account server could not start.\n');
    process.exitCode = 1;
  }
});
server.listen(port, bindHost);
