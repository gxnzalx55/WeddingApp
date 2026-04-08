const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

const DB_PATH = path.join(__dirname, 'wedding.db');
let db;

function saveDb() { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); }
function genId() { return crypto.randomBytes(6).toString('hex'); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }

function all(sql, params = []) {
  const stmt = db.prepare(sql); stmt.bind(params);
  const rows = []; while (stmt.step()) rows.push(stmt.getAsObject()); stmt.free();
  return rows;
}
function get(sql, params = []) { return all(sql, params)[0] || null; }
function run(sql, params = []) { db.run(sql, params); }

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  const session = get('SELECT user_id FROM sessions WHERE token = ?', [token]);
  if (!session) return res.status(401).json({ error: 'Token invalido' });
  const user = get('SELECT id, username, role FROM users WHERE id = ?', [session.user_id]);
  if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
  req.user = user; next();
}

function profileWithPhotos(row) {
  if (!row) return null;
  const photos = all('SELECT photo_data FROM photos WHERE profile_id = ? ORDER BY sort_order', [row.id]);
  return { ...row, photos: photos.map(p => p.photo_data) };
}

function getCoupleWedding(userId) {
  return get('SELECT * FROM weddings WHERE couple_user_id = ?', [userId]);
}

// ===================== AUTH =====================

app.post('/api/register', (req, res) => {
  const { username, password, role } = req.body;
  if (!username?.trim() || !password || !role) return res.status(400).json({ error: 'Faltan campos' });
  if (!['couple', 'guest'].includes(role)) return res.status(400).json({ error: 'Rol invalido' });
  if (password.length < 4) return res.status(400).json({ error: 'Contraseña muy corta (min. 4)' });
  if (get('SELECT id FROM users WHERE username = ?', [username.trim()]))
    return res.status(409).json({ error: 'Ese usuario ya existe' });

  const id = genId(), hash = bcrypt.hashSync(password, 10), token = genToken();
  run('INSERT INTO users (id, username, password_hash, role) VALUES (?,?,?,?)', [id, username.trim(), hash, role]);
  run('INSERT INTO sessions (token, user_id) VALUES (?,?)', [token, id]);
  saveDb();
  res.json({ token, user: { id, username: username.trim(), role } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });
  const user = get('SELECT * FROM users WHERE username = ?', [username.trim()]);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  const token = genToken();
  run('INSERT INTO sessions (token, user_id) VALUES (?,?)', [token, user.id]);
  saveDb();
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/logout', auth, (req, res) => {
  run('DELETE FROM sessions WHERE token = ?', [req.headers.authorization?.replace('Bearer ', '')]);
  saveDb(); res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => { res.json({ user: req.user }); });

// ===================== WEDDINGS =====================

app.post('/api/weddings', auth, (req, res) => {
  if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
  const { names, wedding_date, venue } = req.body;
  if (!names?.trim()) return res.status(400).json({ error: 'Falta el nombre' });
  if (getCoupleWedding(req.user.id)) return res.status(409).json({ error: 'Ya tienes una boda' });

  const id = genId(), code = genId();
  run('INSERT INTO weddings (id,code,names,couple_user_id,wedding_date,venue) VALUES (?,?,?,?,?,?)',
    [id, code, names.trim(), req.user.id, wedding_date || '', venue || '']);
  saveDb();
  res.json({ wedding: { id, code, names: names.trim(), wedding_date: wedding_date || '', venue: venue || '' } });
});

app.get('/api/weddings/mine', auth, (req, res) => {
  if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
  const wedding = getCoupleWedding(req.user.id);
  if (!wedding) return res.json({ wedding: null });

  const profiles = all('SELECT * FROM profiles WHERE wedding_id = ? AND status = ?', [wedding.id, 'approved']).map(profileWithPhotos);
  const pendingProfiles = all('SELECT * FROM profiles WHERE wedding_id = ? AND status = ?', [wedding.id, 'pending']).map(profileWithPhotos);
  const matchRows = all('SELECT * FROM matches WHERE wedding_id = ?', [wedding.id]);
  const matches = matchRows.map(m => ({
    p1: profileWithPhotos(get('SELECT * FROM profiles WHERE id = ?', [m.profile1_id])),
    p2: profileWithPhotos(get('SELECT * FROM profiles WHERE id = ?', [m.profile2_id]))
  })).filter(m => m.p1 && m.p2);

  // Stats
  const totalLikes = get('SELECT COUNT(*) as c FROM likes WHERE wedding_id = ?', [wedding.id])?.c || 0;
  const likesPerProfile = all(`
    SELECT p.id, p.name, COUNT(l.id) as likes_received FROM profiles p
    LEFT JOIN likes l ON l.to_profile_id = p.id AND l.wedding_id = ?
    WHERE p.wedding_id = ? AND p.status = 'approved'
    GROUP BY p.id ORDER BY likes_received DESC
  `, [wedding.id, wedding.id]);

  res.json({
    wedding: { ...wedding, profiles, pendingProfiles, matches,
      stats: { totalLikes, totalMatches: matches.length, totalProfiles: profiles.length, likesPerProfile }
    }
  });
});

app.put('/api/weddings/mine', auth, (req, res) => {
  if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
  const wedding = getCoupleWedding(req.user.id);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const { names, wedding_date, venue, require_approval } = req.body;
  run('UPDATE weddings SET names=?, wedding_date=?, venue=?, require_approval=? WHERE id=?',
    [names || wedding.names, wedding_date ?? wedding.wedding_date, venue ?? wedding.venue, require_approval !== undefined ? (require_approval ? 1 : 0) : wedding.require_approval, wedding.id]);
  saveDb();
  res.json({ ok: true });
});

app.get('/api/weddings/join/:code', auth, (req, res) => {
  const wedding = get('SELECT id, code, names, wedding_date, venue FROM weddings WHERE code = ?', [req.params.code]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const profile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  res.json({ wedding, profile: profile ? { ...profileWithPhotos(profile) } : null });
});

app.get('/api/weddings/guest-mine', auth, (req, res) => {
  const rows = all('SELECT p.*, w.code as wcode, w.names as wnames, w.wedding_date as wdate, w.venue as wvenue FROM profiles p JOIN weddings w ON w.id = p.wedding_id WHERE p.user_id = ?', [req.user.id]);
  const result = rows.map(p => ({
    wedding: { id: p.wedding_id, code: p.wcode, names: p.wnames, wedding_date: p.wdate, venue: p.wvenue },
    profile: profileWithPhotos(get('SELECT * FROM profiles WHERE id = ?', [p.id]))
  }));
  res.json({ weddings: result });
});

// ===================== PROFILES =====================

app.post('/api/profiles', auth, (req, res) => {
  const { wedding_code, name, age, gender, orientation, photos } = req.body;
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [wedding_code]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  if (get('SELECT id FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]))
    return res.status(409).json({ error: 'Ya tienes perfil en esta boda' });

  const id = genId();
  const initialStatus = wedding.require_approval ? 'pending' : 'approved';
  run('INSERT INTO profiles (id,user_id,wedding_id,name,age,gender,orientation,status) VALUES (?,?,?,?,?,?,?,?)',
    [id, req.user.id, wedding.id, name, age, gender, orientation, initialStatus]);
  if (photos?.length) photos.forEach((p, i) => run('INSERT INTO photos (profile_id,photo_data,sort_order) VALUES (?,?,?)', [id, p, i]));
  saveDb();
  const created = profileWithPhotos(get('SELECT * FROM profiles WHERE id = ?', [id]));
  res.json({ profile: { ...created, wedding_code: wedding.code, wedding_names: wedding.names } });
});

app.put('/api/profiles/:id', auth, (req, res) => {
  const profile = get('SELECT * FROM profiles WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!profile) return res.status(404).json({ error: 'Perfil no encontrado' });
  const { name, age, gender, orientation, photos } = req.body;
  run('UPDATE profiles SET name=?, age=?, gender=?, orientation=? WHERE id=?',
    [name || profile.name, age || profile.age, gender || profile.gender, orientation || profile.orientation, profile.id]);
  if (photos) {
    run('DELETE FROM photos WHERE profile_id = ?', [profile.id]);
    photos.forEach((p, i) => run('INSERT INTO photos (profile_id,photo_data,sort_order) VALUES (?,?,?)', [profile.id, p, i]));
  }
  saveDb();
  res.json({ profile: profileWithPhotos(get('SELECT * FROM profiles WHERE id = ?', [profile.id])) });
});

// Couple approves a pending profile
app.post('/api/profiles/:id/approve', auth, (req, res) => {
  if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
  const wedding = getCoupleWedding(req.user.id);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const profile = get('SELECT * FROM profiles WHERE id = ? AND wedding_id = ? AND status = ?', [req.params.id, wedding.id, 'pending']);
  if (!profile) return res.status(404).json({ error: 'Solicitud no encontrada' });
  run('UPDATE profiles SET status = ? WHERE id = ?', ['approved', profile.id]);
  saveDb();
  res.json({ ok: true });
});

// Couple rejects a pending profile
app.post('/api/profiles/:id/reject', auth, (req, res) => {
  if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
  const wedding = getCoupleWedding(req.user.id);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const profile = get('SELECT * FROM profiles WHERE id = ? AND wedding_id = ? AND status = ?', [req.params.id, wedding.id, 'pending']);
  if (!profile) return res.status(404).json({ error: 'Solicitud no encontrada' });
  run('DELETE FROM photos WHERE profile_id = ?', [profile.id]);
  run('DELETE FROM profiles WHERE id = ?', [profile.id]);
  saveDb();
  res.json({ ok: true });
});

// Couple deletes an approved guest
app.delete('/api/profiles/:id/from-wedding', auth, (req, res) => {
  if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
  const wedding = getCoupleWedding(req.user.id);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const profile = get('SELECT * FROM profiles WHERE id = ? AND wedding_id = ?', [req.params.id, wedding.id]);
  if (!profile) return res.status(404).json({ error: 'Perfil no encontrado' });
  run('DELETE FROM messages WHERE wedding_id = ? AND (from_profile_id = ? OR to_profile_id = ?)', [wedding.id, profile.id, profile.id]);
  run('DELETE FROM matches WHERE (profile1_id = ? OR profile2_id = ?) AND wedding_id = ?', [profile.id, profile.id, wedding.id]);
  run('DELETE FROM likes WHERE (from_profile_id = ? OR to_profile_id = ?) AND wedding_id = ?', [profile.id, profile.id, wedding.id]);
  run('DELETE FROM photos WHERE profile_id = ?', [profile.id]);
  run('DELETE FROM profiles WHERE id = ?', [profile.id]);
  saveDb(); res.json({ ok: true });
});

// ===================== SWIPE =====================

app.get('/api/profiles/compatible/:weddingCode', auth, (req, res) => {
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [req.params.weddingCode]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const myProfile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

  const likedIds = all('SELECT to_profile_id FROM likes WHERE wedding_id = ? AND from_profile_id = ?', [wedding.id, myProfile.id])
    .map(r => r.to_profile_id);
  const passedIds = all('SELECT to_profile_id FROM passes WHERE wedding_id = ? AND from_profile_id = ?', [wedding.id, myProfile.id])
    .map(r => r.to_profile_id);
  const seenIds = [...likedIds, ...passedIds];

  const compatible = all('SELECT * FROM profiles WHERE wedding_id = ? AND id != ? AND status = ?', [wedding.id, myProfile.id, 'approved'])
    .filter(p => !seenIds.includes(p.id))
    .filter(p => {
      const a1 = (myProfile.orientation === 'guys' && p.gender === 'male') || (myProfile.orientation === 'girls' && p.gender === 'female') || myProfile.orientation === 'both';
      const a2 = (p.orientation === 'guys' && myProfile.gender === 'male') || (p.orientation === 'girls' && myProfile.gender === 'female') || p.orientation === 'both';
      return a1 && a2;
    }).map(profileWithPhotos);

  res.json({ profiles: compatible, myProfile: profileWithPhotos(myProfile) });
});

app.post('/api/like', auth, (req, res) => {
  const { wedding_code, target_profile_id } = req.body;
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [wedding_code]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const myProfile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

  if (!get('SELECT id FROM likes WHERE wedding_id=? AND from_profile_id=? AND to_profile_id=?', [wedding.id, myProfile.id, target_profile_id]))
    run('INSERT INTO likes (wedding_id,from_profile_id,to_profile_id) VALUES (?,?,?)', [wedding.id, myProfile.id, target_profile_id]);

  // Remove from passes if was there
  run('DELETE FROM passes WHERE wedding_id=? AND from_profile_id=? AND to_profile_id=?', [wedding.id, myProfile.id, target_profile_id]);

  const mutual = get('SELECT id FROM likes WHERE wedding_id=? AND from_profile_id=? AND to_profile_id=?', [wedding.id, target_profile_id, myProfile.id]);
  let isMatch = false;
  if (mutual) {
    const exists = get('SELECT id FROM matches WHERE wedding_id=? AND ((profile1_id=? AND profile2_id=?) OR (profile1_id=? AND profile2_id=?))',
      [wedding.id, myProfile.id, target_profile_id, target_profile_id, myProfile.id]);
    if (!exists) { run('INSERT INTO matches (wedding_id,profile1_id,profile2_id) VALUES (?,?,?)', [wedding.id, myProfile.id, target_profile_id]); isMatch = true; }
  }
  saveDb();
  res.json({ isMatch, matchedProfile: isMatch ? profileWithPhotos(get('SELECT * FROM profiles WHERE id=?', [target_profile_id])) : null });
});

app.post('/api/pass', auth, (req, res) => {
  const { wedding_code, target_profile_id } = req.body;
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [wedding_code]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const myProfile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });
  if (!get('SELECT id FROM passes WHERE wedding_id=? AND from_profile_id=? AND to_profile_id=?', [wedding.id, myProfile.id, target_profile_id]))
    run('INSERT INTO passes (wedding_id,from_profile_id,to_profile_id) VALUES (?,?,?)', [wedding.id, myProfile.id, target_profile_id]);
  saveDb(); res.json({ ok: true });
});

app.post('/api/undo-swipe', auth, (req, res) => {
  const { wedding_code, target_profile_id, direction } = req.body;
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [wedding_code]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const myProfile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

  if (direction === 'right') {
    // Remove like and any match
    run('DELETE FROM matches WHERE wedding_id=? AND ((profile1_id=? AND profile2_id=?) OR (profile1_id=? AND profile2_id=?))',
      [wedding.id, myProfile.id, target_profile_id, target_profile_id, myProfile.id]);
    run('DELETE FROM likes WHERE wedding_id=? AND from_profile_id=? AND to_profile_id=?', [wedding.id, myProfile.id, target_profile_id]);
  } else {
    run('DELETE FROM passes WHERE wedding_id=? AND from_profile_id=? AND to_profile_id=?', [wedding.id, myProfile.id, target_profile_id]);
  }
  saveDb(); res.json({ ok: true });
});

// ===================== MATCHES =====================

app.get('/api/matches/:weddingCode', auth, (req, res) => {
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [req.params.weddingCode]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const myProfile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

  const rows = all(`SELECT CASE WHEN profile1_id=? THEN profile2_id ELSE profile1_id END as other_id
    FROM matches WHERE wedding_id=? AND (profile1_id=? OR profile2_id=?)`, [myProfile.id, wedding.id, myProfile.id, myProfile.id]);
  const result = rows.map(r => {
    const p = profileWithPhotos(get('SELECT * FROM profiles WHERE id=?', [r.other_id]));
    if (!p) return null;
    const lastMsg = get('SELECT text, created_at FROM messages WHERE wedding_id=? AND ((from_profile_id=? AND to_profile_id=?) OR (from_profile_id=? AND to_profile_id=?)) ORDER BY created_at DESC LIMIT 1',
      [wedding.id, myProfile.id, r.other_id, r.other_id, myProfile.id]);
    return { ...p, lastMessage: lastMsg?.text || null };
  }).filter(Boolean);
  res.json({ matches: result });
});

// ===================== MESSAGES =====================

app.get('/api/messages/:weddingCode/:otherProfileId', auth, (req, res) => {
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [req.params.weddingCode]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const myProfile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

  const messages = all(`SELECT * FROM messages WHERE wedding_id=? AND
    ((from_profile_id=? AND to_profile_id=?) OR (from_profile_id=? AND to_profile_id=?))
    ORDER BY created_at ASC`,
    [wedding.id, myProfile.id, req.params.otherProfileId, req.params.otherProfileId, myProfile.id]);

  res.json({ messages: messages.map(m => ({ ...m, mine: m.from_profile_id === myProfile.id })), myProfileId: myProfile.id });
});

app.post('/api/messages', auth, (req, res) => {
  const { wedding_code, to_profile_id, text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Mensaje vacio' });
  const wedding = get('SELECT * FROM weddings WHERE code = ?', [wedding_code]);
  if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
  const myProfile = get('SELECT * FROM profiles WHERE user_id = ? AND wedding_id = ?', [req.user.id, wedding.id]);
  if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

  // Verify they are matched
  const matched = get('SELECT id FROM matches WHERE wedding_id=? AND ((profile1_id=? AND profile2_id=?) OR (profile1_id=? AND profile2_id=?))',
    [wedding.id, myProfile.id, to_profile_id, to_profile_id, myProfile.id]);
  if (!matched) return res.status(403).json({ error: 'No teneis match' });

  run('INSERT INTO messages (wedding_id,from_profile_id,to_profile_id,text) VALUES (?,?,?,?)',
    [wedding.id, myProfile.id, to_profile_id, text.trim()]);
  saveDb();
  res.json({ ok: true });
});

// ===================== SERVE =====================

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'wedding-tinder.html')); });

// ===================== START =====================

async function start() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) { db = new SQL.Database(fs.readFileSync(DB_PATH)); }
  else { db = new SQL.Database(); }

  run('PRAGMA foreign_keys = ON');

  run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  run(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  run(`CREATE TABLE IF NOT EXISTS weddings (id TEXT PRIMARY KEY, code TEXT UNIQUE NOT NULL, names TEXT NOT NULL, couple_user_id TEXT NOT NULL, wedding_date TEXT DEFAULT '', venue TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  run(`CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, wedding_id TEXT NOT NULL, name TEXT NOT NULL, age INTEGER NOT NULL, gender TEXT NOT NULL, orientation TEXT NOT NULL, status TEXT DEFAULT 'approved', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, wedding_id))`);
  run(`CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id TEXT NOT NULL, photo_data TEXT NOT NULL, sort_order INTEGER DEFAULT 0)`);
  run(`CREATE TABLE IF NOT EXISTS likes (id INTEGER PRIMARY KEY AUTOINCREMENT, wedding_id TEXT NOT NULL, from_profile_id TEXT NOT NULL, to_profile_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(wedding_id, from_profile_id, to_profile_id))`);
  run(`CREATE TABLE IF NOT EXISTS matches (id INTEGER PRIMARY KEY AUTOINCREMENT, wedding_id TEXT NOT NULL, profile1_id TEXT NOT NULL, profile2_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  run(`CREATE TABLE IF NOT EXISTS passes (id INTEGER PRIMARY KEY AUTOINCREMENT, wedding_id TEXT NOT NULL, from_profile_id TEXT NOT NULL, to_profile_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(wedding_id, from_profile_id, to_profile_id))`);
  run(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, wedding_id TEXT NOT NULL, from_profile_id TEXT NOT NULL, to_profile_id TEXT NOT NULL, text TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);

  // Migrations for existing DBs
  try { run('ALTER TABLE weddings ADD COLUMN wedding_date TEXT DEFAULT ""'); } catch {}
  try { run('ALTER TABLE weddings ADD COLUMN venue TEXT DEFAULT ""'); } catch {}
  try { run('ALTER TABLE profiles ADD COLUMN status TEXT DEFAULT "approved"'); } catch {}
  try { run('ALTER TABLE weddings ADD COLUMN require_approval INTEGER DEFAULT 1'); } catch {}

  saveDb();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Wedding Match running on: ${PORT}`));
}

start().catch(err => { console.error('Error:', err); process.exit(1); });
