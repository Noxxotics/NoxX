const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace-this-with-a-long-random-secret';
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const DATA_DIR = process.env.DATA_DIR || __dirname;
require('fs').mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'chat.db'));
app.set('trust proxy', 1);

db.pragma('foreign_keys = ON');
function addColumn(table, definition) {
  try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${definition}`); } catch (e) {
    if (!String(e.message).includes('duplicate column name')) throw e;
  }
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS conversations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  type TEXT NOT NULL DEFAULT 'direct',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS conversation_members (
  conversation_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  alias TEXT,
  PRIMARY KEY (conversation_id, user_id),
  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id INTEGER NOT NULL,
  sender_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  encrypted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS contact_invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  one_time INTEGER NOT NULL DEFAULT 1,
  used_at TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
`);
addColumn('users', 'display_name TEXT');
addColumn('users', 'pin_hash TEXT');
addColumn('users', 'destructive_pin_hash TEXT');
addColumn('users', "theme TEXT NOT NULL DEFAULT 'dark'");
addColumn('users', 'compact_mode INTEGER NOT NULL DEFAULT 0');
addColumn('users', 'typing_indicators INTEGER NOT NULL DEFAULT 1');
addColumn('users', 'notification_sounds INTEGER NOT NULL DEFAULT 1');
addColumn('users', 'read_receipts INTEGER NOT NULL DEFAULT 0');
addColumn('users', 'disappearing_minutes INTEGER NOT NULL DEFAULT 0');
addColumn('messages', 'encrypted INTEGER NOT NULL DEFAULT 0');

app.use(express.json({ limit: '200kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const publicUser = (u) => ({
  id: u.id,
  username: u.username,
  displayName: u.display_name || u.username,
  settings: {
    theme: u.theme || 'dark', compactMode: !!u.compact_mode,
    typingIndicators: !!u.typing_indicators, notificationSounds: !!u.notification_sounds,
    readReceipts: !!u.read_receipts, disappearingMinutes: u.disappearing_minutes || 0
  }
});
const userById = (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
const createToken = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });
function tokenFrom(req) {
  const auth = req.headers.authorization;
  return auth?.startsWith('Bearer ') ? auth.slice(7) : req.cookies?.token;
}
function requireAuth(req, res, next) {
  try { req.auth = jwt.verify(tokenFrom(req), JWT_SECRET); req.user = userById(req.auth.id); if (!req.user) throw 0; next(); }
  catch { res.status(401).json({ error: 'Not authenticated.' }); }
}
const isMember = (cid, uid) => !!db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(cid, uid);
const validPin = (v) => /^\d{4,12}$/.test(String(v || ''));
const randomToken = () => crypto.randomBytes(24).toString('base64url');

app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const displayName = String(req.body.displayName || username).trim().slice(0, 40);
  const password = String(req.body.password || '');
  const pin = String(req.body.pin || '');
  const destructivePin = String(req.body.destructivePin || '');
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-20 letters, numbers, or underscores.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (!validPin(pin)) return res.status(400).json({ error: 'PIN must contain 4-12 digits.' });
  if (!validPin(destructivePin)) return res.status(400).json({ error: 'Destructive PIN must contain 4-12 digits.' });
  if (pin === destructivePin) return res.status(400).json({ error: 'Your destructive PIN must be different from your normal PIN.' });
  try {
    const [passwordHash, pinHash, destructiveHash] = await Promise.all([
      bcrypt.hash(password, 12), bcrypt.hash(pin, 12), bcrypt.hash(destructivePin, 12)
    ]);
    const result = db.prepare('INSERT INTO users (username,display_name,password_hash,pin_hash,destructive_pin_hash) VALUES (?,?,?,?,?)')
      .run(username, displayName || username, passwordHash, pinHash, destructiveHash);
    const user = userById(Number(result.lastInsertRowid));
    res.cookie('token', createToken(user), { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 86400000 });
    res.json({ user: publicUser(user) });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'That local account name is taken.' });
    res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/login', async (req, res) => {
  const row = db.prepare('SELECT * FROM users WHERE username=?').get(String(req.body.username || '').trim());
  const password = String(req.body.password || '');
  const pin = String(req.body.pin || '');
  const pinConfirm = String(req.body.pinConfirm || '');
  if (!row || !(await bcrypt.compare(password, row.password_hash))) {
    return res.status(401).json({ error: 'Invalid account name, password, or PIN.' });
  }

  const normalMatch = row.pin_hash && await bcrypt.compare(pin, row.pin_hash);
  if (normalMatch) {
    res.cookie('token', createToken(row), { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 86400000 });
    return res.json({ user: publicUser(row), destroyed: false });
  }

  const destructiveMatch = row.destructive_pin_hash && await bcrypt.compare(pin, row.destructive_pin_hash);
  if (!destructiveMatch) return res.status(401).json({ error: 'Invalid account name, password, or PIN.' });
  if (!pinConfirm || pinConfirm !== pin) {
    return res.status(400).json({ error: 'Enter the destructive PIN in both PIN fields to permanently wipe this account.' });
  }

  const conversationIds = db.prepare('SELECT conversation_id FROM conversation_members WHERE user_id=?').all(row.id).map(x => x.conversation_id);
  const wipe = db.transaction(() => {
    db.prepare('DELETE FROM users WHERE id=?').run(row.id);
    for (const cid of conversationIds) {
      const count = db.prepare('SELECT COUNT(*) n FROM conversation_members WHERE conversation_id=?').get(cid).n;
      if (count === 0) db.prepare('DELETE FROM conversations WHERE id=?').run(cid);
    }
  });
  wipe();
  io.to(`user:${row.id}`).emit('account_deleted');
  res.clearCookie('token');
  return res.json({ destroyed: true });
});
app.post('/api/logout', (_, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

app.patch('/api/settings', requireAuth, async (req, res) => {
  const currentPin = String(req.body.currentPin || '');
  if (!req.user.pin_hash || !(await bcrypt.compare(currentPin, req.user.pin_hash))) return res.status(403).json({ error: 'Your current PIN is required.' });
  const displayName = String(req.body.displayName ?? req.user.display_name ?? req.user.username).trim().slice(0, 40);
  const theme = ['dark','light','system'].includes(req.body.theme) ? req.body.theme : req.user.theme;
  const disappearing = [0, 5, 60, 1440, 10080].includes(Number(req.body.disappearingMinutes)) ? Number(req.body.disappearingMinutes) : req.user.disappearing_minutes;
  db.prepare(`UPDATE users SET display_name=?,theme=?,compact_mode=?,typing_indicators=?,notification_sounds=?,read_receipts=?,disappearing_minutes=? WHERE id=?`).run(
    displayName || req.user.username, theme, req.body.compactMode ? 1 : 0, req.body.typingIndicators ? 1 : 0,
    req.body.notificationSounds ? 1 : 0, req.body.readReceipts ? 1 : 0, disappearing, req.user.id
  );
  res.json({ user: publicUser(userById(req.user.id)) });
});

app.post('/api/settings/change-pin', requireAuth, async (req, res) => {
  if (!(await bcrypt.compare(String(req.body.currentPin || ''), req.user.pin_hash))) return res.status(403).json({ error: 'Current PIN is incorrect.' });
  const next = String(req.body.newPin || '');
  if (!validPin(next)) return res.status(400).json({ error: 'New PIN must contain 4-12 digits.' });
  if (await bcrypt.compare(next, req.user.destructive_pin_hash)) return res.status(400).json({ error: 'Normal and destructive PINs must be different.' });
  db.prepare('UPDATE users SET pin_hash=? WHERE id=?').run(await bcrypt.hash(next, 12), req.user.id);
  res.json({ ok: true });
});

app.post('/api/settings/change-destructive-pin', requireAuth, async (req, res) => {
  if (!(await bcrypt.compare(String(req.body.currentPin || ''), req.user.pin_hash))) return res.status(403).json({ error: 'Current normal PIN is incorrect.' });
  const next = String(req.body.newDestructivePin || '');
  if (!validPin(next)) return res.status(400).json({ error: 'New destructive PIN must contain 4-12 digits.' });
  if (await bcrypt.compare(next, req.user.pin_hash)) return res.status(400).json({ error: 'Normal and destructive PINs must be different.' });
  db.prepare('UPDATE users SET destructive_pin_hash=? WHERE id=?').run(await bcrypt.hash(next, 12), req.user.id);
  res.json({ ok: true });
});

app.delete('/api/account', requireAuth, async (req, res) => {
  const a = String(req.body.destructivePin || '');
  const b = String(req.body.destructivePinConfirm || '');
  if (a !== b) return res.status(400).json({ error: 'The destructive PIN entries do not match.' });
  if (!req.user.destructive_pin_hash || !(await bcrypt.compare(a, req.user.destructive_pin_hash))) return res.status(403).json({ error: 'Destructive PIN is incorrect.' });
  const conversationIds = db.prepare('SELECT conversation_id FROM conversation_members WHERE user_id=?').all(req.user.id).map(x => x.conversation_id);
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM users WHERE id=?').run(req.user.id);
    const delEmpty = db.prepare('DELETE FROM conversations WHERE id=? AND NOT EXISTS (SELECT 1 FROM conversation_members WHERE conversation_id=?)');
    conversationIds.forEach(id => delEmpty.run(id, id));
  });
  tx();
  io.to(`user:${req.user.id}`).emit('account_deleted');
  res.clearCookie('token');
  res.json({ ok: true });
});

app.post('/api/invites', requireAuth, (req, res) => {
  const oneTime = req.body.oneTime !== false;
  const token = randomToken();
  const hours = oneTime ? 24 : 24 * 30;
  db.prepare("INSERT INTO contact_invites (owner_id,token,one_time,expires_at) VALUES (?,?,?,datetime('now', ?))")
    .run(req.user.id, token, oneTime ? 1 : 0, `+${hours} hours`);
  res.json({ token, oneTime, url: `${req.protocol}://${req.get('host')}/?connect=${token}` });
});
app.get('/api/invites', requireAuth, (req, res) => {
  const invites = db.prepare("SELECT token,one_time,used_at,expires_at,created_at FROM contact_invites WHERE owner_id=? ORDER BY id DESC LIMIT 10").all(req.user.id);
  res.json({ invites });
});
app.post('/api/connect/:token', requireAuth, (req, res) => {
  const invite = db.prepare("SELECT * FROM contact_invites WHERE token=? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)").get(req.params.token);
  if (!invite || (invite.one_time && invite.used_at)) return res.status(404).json({ error: 'This invitation is invalid, expired, or already used.' });
  if (invite.owner_id === req.user.id) return res.status(400).json({ error: 'You cannot connect to your own invitation.' });
  const existing = db.prepare(`SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=? JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=? WHERE c.type='direct' AND (SELECT COUNT(*) FROM conversation_members x WHERE x.conversation_id=c.id)=2 LIMIT 1`).get(req.user.id, invite.owner_id);
  let id = existing?.id;
  if (!id) id = db.transaction(() => {
    const cid = Number(db.prepare("INSERT INTO conversations(type) VALUES('direct')").run().lastInsertRowid);
    db.prepare('INSERT INTO conversation_members(conversation_id,user_id) VALUES(?,?),(?,?)').run(cid, req.user.id, cid, invite.owner_id);
    return cid;
  })();
  if (invite.one_time) db.prepare('UPDATE contact_invites SET used_at=CURRENT_TIMESTAMP WHERE id=?').run(invite.id);
  io.to(`user:${invite.owner_id}`).emit('contact_connected', { conversationId: id, inviteToken: invite.token });
  const other = userById(invite.owner_id);
  res.json({ conversation: { id, name: other.display_name || other.username } });
});

app.get('/api/conversations', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.id,c.type,
      COALESCE((SELECT cm2.alias FROM conversation_members cm2 WHERE cm2.conversation_id=c.id AND cm2.user_id=?),
        (SELECT COALESCE(u.display_name,u.username) FROM users u JOIN conversation_members x ON x.user_id=u.id WHERE x.conversation_id=c.id AND u.id!=? LIMIT 1), c.name, 'Private chat') name,
      (SELECT CASE WHEN encrypted=1 THEN 'Encrypted message' ELSE content END FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) last_message,
      (SELECT created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.id DESC LIMIT 1) last_message_at
    FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id WHERE cm.user_id=?
    ORDER BY COALESCE(last_message_at,c.created_at) DESC`).all(req.user.id, req.user.id, req.user.id);
  res.json({ conversations: rows });
});
app.patch('/api/conversations/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id); if (!isMember(id, req.user.id)) return res.status(403).json({ error: 'Access denied.' });
  const alias = String(req.body.alias || '').trim().slice(0, 40) || null;
  db.prepare('UPDATE conversation_members SET alias=? WHERE conversation_id=? AND user_id=?').run(alias, id, req.user.id);
  res.json({ ok: true });
});
app.delete('/api/conversations/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id); if (!isMember(id, req.user.id)) return res.status(403).json({ error: 'Access denied.' });
  db.prepare('DELETE FROM conversation_members WHERE conversation_id=? AND user_id=?').run(id, req.user.id);
  db.prepare('DELETE FROM conversations WHERE id=? AND NOT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id=?)').run(id, id);
  res.json({ ok: true });
});
app.get('/api/conversations/:id/messages', requireAuth, (req, res) => {
  const id = Number(req.params.id); if (!isMember(id, req.user.id)) return res.status(403).json({ error: 'Access denied.' });
  if (req.user.disappearing_minutes > 0) db.prepare("DELETE FROM messages WHERE conversation_id=? AND created_at < datetime('now', ?)").run(id, `-${req.user.disappearing_minutes} minutes`);
  const messages = db.prepare(`SELECT m.id,m.conversation_id,m.sender_id,COALESCE(u.display_name,u.username) sender_username,m.content,m.encrypted,m.created_at FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=? ORDER BY m.id ASC LIMIT 300`).all(id);
  res.json({ messages });
});

const onlineUsers = new Map();
io.use((socket, next) => {
  try {
    const cookie = socket.handshake.headers.cookie || '';
    const m = cookie.match(/(?:^|; )token=([^;]+)/);
    socket.auth = jwt.verify(m ? decodeURIComponent(m[1]) : socket.handshake.auth?.token, JWT_SECRET);
    socket.user = userById(socket.auth.id); if (!socket.user) throw 0; next();
  } catch { next(new Error('Not authenticated')); }
});
io.on('connection', socket => {
  socket.join(`user:${socket.user.id}`);
  onlineUsers.set(socket.user.id, (onlineUsers.get(socket.user.id) || 0) + 1);
  db.prepare('SELECT conversation_id FROM conversation_members WHERE user_id=?').all(socket.user.id).forEach(x => socket.join(`conversation:${x.conversation_id}`));
  socket.on('join_conversation', cid => { if (isMember(Number(cid), socket.user.id)) socket.join(`conversation:${Number(cid)}`); });
  socket.on('send_message', (p, done=()=>{}) => {
    try {
      const cid = Number(p.conversationId), content = String(p.content || '').trim();
      const encrypted = p.encrypted === true;
      if (!isMember(cid, socket.user.id)) return done({ error: 'Access denied.' });
      if (!content || content.length > 12000) return done({ error: 'Encrypted message payload is invalid.' });
      if (encrypted) {
        try {
          const box = JSON.parse(content);
          if (box.v !== 1 || typeof box.iv !== 'string' || typeof box.ct !== 'string' || box.iv.length > 64 || box.ct.length > 11000) throw 0;
        } catch { return done({ error: 'Encrypted message payload is invalid.' }); }
      }
      const mid = Number(db.prepare('INSERT INTO messages(conversation_id,sender_id,content,encrypted) VALUES(?,?,?,?)').run(cid, socket.user.id, content, encrypted ? 1 : 0).lastInsertRowid);
      const msg = db.prepare(`SELECT m.id,m.conversation_id,m.sender_id,COALESCE(u.display_name,u.username) sender_username,m.content,m.encrypted,m.created_at FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(mid);
      io.to(`conversation:${cid}`).emit('new_message', msg); done({ ok: true });
    } catch { done({ error: 'Could not send message.' }); }
  });
  socket.on('typing', ({conversationId,isTyping}) => {
    const cid = Number(conversationId);
    if (socket.user.typing_indicators && isMember(cid, socket.user.id)) socket.to(`conversation:${cid}`).emit('typing', { conversationId: cid, name: socket.user.display_name || socket.user.username, isTyping: !!isTyping });
  });
  socket.on('disconnect', () => {
    const n = (onlineUsers.get(socket.user.id) || 1) - 1; n <= 0 ? onlineUsers.delete(socket.user.id) : onlineUsers.set(socket.user.id, n);
  });
});

app.get('/health', (_, res) => res.json({ ok: true }));
server.listen(PORT, '0.0.0.0', () => console.log(`Noxx Private Chat listening on port ${PORT}`));
