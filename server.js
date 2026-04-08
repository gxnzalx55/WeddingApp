const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

function genId() { return crypto.randomBytes(6).toString('hex'); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }

async function all(sql, params = []) {
  const res = await pool.query(sql, params);
  return res.rows;
}
async function get(sql, params = []) {
  const rows = await all(sql, params);
  return rows[0] || null;
}
async function run(sql, params = []) {
  await pool.query(sql, params);
}

function auth(handler) {
  return async (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    const session = await get('SELECT user_id FROM sessions WHERE token = $1', [token]);
    if (!session) return res.status(401).json({ error: 'Token invalido' });
    const user = await get('SELECT id, username, role FROM users WHERE id = $1', [session.user_id]);
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    req.user = user;
    await handler(req, res);
  };
}

async function profileWithPhotos(row) {
  if (!row) return null;
  const photos = await all('SELECT photo_data FROM photos WHERE profile_id = $1 ORDER BY sort_order', [row.id]);
  return { ...row, photos: photos.map(p => p.photo_data) };
}

async function getCoupleWedding(userId) {
  return get('SELECT * FROM weddings WHERE couple_user_id = $1', [userId]);
}

// ===================== AUTH =====================

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username?.trim() || !password || !role) return res.status(400).json({ error: 'Faltan campos' });
    if (!['couple', 'guest'].includes(role)) return res.status(400).json({ error: 'Rol invalido' });
    if (password.length < 4) return res.status(400).json({ error: 'Contraseña muy corta (min. 4)' });
    if (await get('SELECT id FROM users WHERE username = $1', [username.trim()]))
      return res.status(409).json({ error: 'Ese usuario ya existe' });

    const id = genId(), hash = bcrypt.hashSync(password, 10), token = genToken();
    await run('INSERT INTO users (id, username, password_hash, role) VALUES ($1,$2,$3,$4)', [id, username.trim(), hash, role]);
    await run('INSERT INTO sessions (token, user_id) VALUES ($1,$2)', [token, id]);
    res.json({ token, user: { id, username: username.trim(), role } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });
    const user = await get('SELECT * FROM users WHERE username = $1', [username.trim()]);
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const token = genToken();
    await run('INSERT INTO sessions (token, user_id) VALUES ($1,$2)', [token, user.id]);
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
});

app.post('/api/logout', auth(async (req, res) => {
  await run('DELETE FROM sessions WHERE token = $1', [req.headers.authorization?.replace('Bearer ', '')]);
  res.json({ ok: true });
}));

app.get('/api/me', auth(async (req, res) => { res.json({ user: req.user }); }));

// ===================== WEDDINGS =====================

app.post('/api/weddings', auth(async (req, res) => {
  try {
    if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
    const { names, wedding_date, venue } = req.body;
    if (!names?.trim()) return res.status(400).json({ error: 'Falta el nombre' });
    if (await getCoupleWedding(req.user.id)) return res.status(409).json({ error: 'Ya tienes una boda' });

    const id = genId(), code = genId();
    await run('INSERT INTO weddings (id,code,names,couple_user_id,wedding_date,venue) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, code, names.trim(), req.user.id, wedding_date || '', venue || '']);
    res.json({ wedding: { id, code, names: names.trim(), wedding_date: wedding_date || '', venue: venue || '' } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.get('/api/weddings/mine', auth(async (req, res) => {
  try {
    if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
    const wedding = await getCoupleWedding(req.user.id);
    if (!wedding) return res.json({ wedding: null });

    const profileRows = await all('SELECT * FROM profiles WHERE wedding_id = $1 AND status = $2', [wedding.id, 'approved']);
    const profiles = await Promise.all(profileRows.map(profileWithPhotos));
    const pendingRows = await all('SELECT * FROM profiles WHERE wedding_id = $1 AND status = $2', [wedding.id, 'pending']);
    const pendingProfiles = await Promise.all(pendingRows.map(profileWithPhotos));
    const matchRows = await all('SELECT * FROM matches WHERE wedding_id = $1', [wedding.id]);
    const matches = (await Promise.all(matchRows.map(async m => ({
      p1: await profileWithPhotos(await get('SELECT * FROM profiles WHERE id = $1', [m.profile1_id])),
      p2: await profileWithPhotos(await get('SELECT * FROM profiles WHERE id = $1', [m.profile2_id]))
    })))).filter(m => m.p1 && m.p2);

    const totalLikes = (await get('SELECT COUNT(*) as c FROM likes WHERE wedding_id = $1', [wedding.id]))?.c || 0;
    const likesPerProfile = await all(`
      SELECT p.id, p.name, COUNT(l.id) as likes_received FROM profiles p
      LEFT JOIN likes l ON l.to_profile_id = p.id AND l.wedding_id = $1
      WHERE p.wedding_id = $2 AND p.status = 'approved'
      GROUP BY p.id, p.name ORDER BY likes_received DESC
    `, [wedding.id, wedding.id]);

    res.json({
      wedding: { ...wedding, profiles, pendingProfiles, matches,
        stats: { totalLikes: parseInt(totalLikes), totalMatches: matches.length, totalProfiles: profiles.length, likesPerProfile }
      }
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.put('/api/weddings/mine', auth(async (req, res) => {
  try {
    if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
    const wedding = await getCoupleWedding(req.user.id);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const { names, wedding_date, venue, require_approval } = req.body;
    await run('UPDATE weddings SET names=$1, wedding_date=$2, venue=$3, require_approval=$4 WHERE id=$5',
      [names || wedding.names, wedding_date ?? wedding.wedding_date, venue ?? wedding.venue, require_approval !== undefined ? (require_approval ? 1 : 0) : wedding.require_approval, wedding.id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.get('/api/weddings/join/:code', auth(async (req, res) => {
  try {
    const wedding = await get('SELECT id, code, names, wedding_date, venue FROM weddings WHERE code = $1', [req.params.code]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const profile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    res.json({ wedding, profile: profile ? await profileWithPhotos(profile) : null });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.get('/api/weddings/guest-mine', auth(async (req, res) => {
  try {
    const rows = await all('SELECT p.*, w.code as wcode, w.names as wnames, w.wedding_date as wdate, w.venue as wvenue FROM profiles p JOIN weddings w ON w.id = p.wedding_id WHERE p.user_id = $1', [req.user.id]);
    const result = await Promise.all(rows.map(async p => ({
      wedding: { id: p.wedding_id, code: p.wcode, names: p.wnames, wedding_date: p.wdate, venue: p.wvenue },
      profile: await profileWithPhotos(await get('SELECT * FROM profiles WHERE id = $1', [p.id]))
    })));
    res.json({ weddings: result });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

// ===================== PROFILES =====================

app.post('/api/profiles', auth(async (req, res) => {
  try {
    const { wedding_code, name, age, gender, orientation, photos } = req.body;
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [wedding_code]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    if (await get('SELECT id FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]))
      return res.status(409).json({ error: 'Ya tienes perfil en esta boda' });

    const id = genId();
    const initialStatus = wedding.require_approval ? 'pending' : 'approved';
    await run('INSERT INTO profiles (id,user_id,wedding_id,name,age,gender,orientation,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, req.user.id, wedding.id, name, age, gender, orientation, initialStatus]);
    if (photos?.length) {
      for (let i = 0; i < photos.length; i++) {
        await run('INSERT INTO photos (profile_id,photo_data,sort_order) VALUES ($1,$2,$3)', [id, photos[i], i]);
      }
    }
    const created = await profileWithPhotos(await get('SELECT * FROM profiles WHERE id = $1', [id]));
    res.json({ profile: { ...created, wedding_code: wedding.code, wedding_names: wedding.names } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.put('/api/profiles/:id', auth(async (req, res) => {
  try {
    const profile = await get('SELECT * FROM profiles WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (!profile) return res.status(404).json({ error: 'Perfil no encontrado' });
    const { name, age, gender, orientation, photos } = req.body;
    await run('UPDATE profiles SET name=$1, age=$2, gender=$3, orientation=$4 WHERE id=$5',
      [name || profile.name, age || profile.age, gender || profile.gender, orientation || profile.orientation, profile.id]);
    if (photos) {
      await run('DELETE FROM photos WHERE profile_id = $1', [profile.id]);
      for (let i = 0; i < photos.length; i++) {
        await run('INSERT INTO photos (profile_id,photo_data,sort_order) VALUES ($1,$2,$3)', [profile.id, photos[i], i]);
      }
    }
    res.json({ profile: await profileWithPhotos(await get('SELECT * FROM profiles WHERE id = $1', [profile.id])) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.post('/api/profiles/:id/approve', auth(async (req, res) => {
  try {
    if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
    const wedding = await getCoupleWedding(req.user.id);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const profile = await get('SELECT * FROM profiles WHERE id = $1 AND wedding_id = $2 AND status = $3', [req.params.id, wedding.id, 'pending']);
    if (!profile) return res.status(404).json({ error: 'Solicitud no encontrada' });
    await run('UPDATE profiles SET status = $1 WHERE id = $2', ['approved', profile.id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.post('/api/profiles/:id/reject', auth(async (req, res) => {
  try {
    if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
    const wedding = await getCoupleWedding(req.user.id);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const profile = await get('SELECT * FROM profiles WHERE id = $1 AND wedding_id = $2 AND status = $3', [req.params.id, wedding.id, 'pending']);
    if (!profile) return res.status(404).json({ error: 'Solicitud no encontrada' });
    await run('DELETE FROM photos WHERE profile_id = $1', [profile.id]);
    await run('DELETE FROM profiles WHERE id = $1', [profile.id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.delete('/api/profiles/:id/from-wedding', auth(async (req, res) => {
  try {
    if (req.user.role !== 'couple') return res.status(403).json({ error: 'Solo novios' });
    const wedding = await getCoupleWedding(req.user.id);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const profile = await get('SELECT * FROM profiles WHERE id = $1 AND wedding_id = $2', [req.params.id, wedding.id]);
    if (!profile) return res.status(404).json({ error: 'Perfil no encontrado' });
    await run('DELETE FROM messages WHERE wedding_id = $1 AND (from_profile_id = $2 OR to_profile_id = $3)', [wedding.id, profile.id, profile.id]);
    await run('DELETE FROM matches WHERE (profile1_id = $1 OR profile2_id = $2) AND wedding_id = $3', [profile.id, profile.id, wedding.id]);
    await run('DELETE FROM likes WHERE (from_profile_id = $1 OR to_profile_id = $2) AND wedding_id = $3', [profile.id, profile.id, wedding.id]);
    await run('DELETE FROM photos WHERE profile_id = $1', [profile.id]);
    await run('DELETE FROM profiles WHERE id = $1', [profile.id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

// ===================== SWIPE =====================

app.get('/api/profiles/compatible/:weddingCode', auth(async (req, res) => {
  try {
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [req.params.weddingCode]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const myProfile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

    const likedIds = (await all('SELECT to_profile_id FROM likes WHERE wedding_id = $1 AND from_profile_id = $2', [wedding.id, myProfile.id]))
      .map(r => r.to_profile_id);
    const passedIds = (await all('SELECT to_profile_id FROM passes WHERE wedding_id = $1 AND from_profile_id = $2', [wedding.id, myProfile.id]))
      .map(r => r.to_profile_id);
    const seenIds = [...likedIds, ...passedIds];

    const allProfiles = await all('SELECT * FROM profiles WHERE wedding_id = $1 AND id != $2 AND status = $3', [wedding.id, myProfile.id, 'approved']);
    const compatible = await Promise.all(
      allProfiles
        .filter(p => !seenIds.includes(p.id))
        .filter(p => {
          const a1 = (myProfile.orientation === 'guys' && p.gender === 'male') || (myProfile.orientation === 'girls' && p.gender === 'female') || myProfile.orientation === 'both';
          const a2 = (p.orientation === 'guys' && myProfile.gender === 'male') || (p.orientation === 'girls' && myProfile.gender === 'female') || p.orientation === 'both';
          return a1 && a2;
        })
        .map(profileWithPhotos)
    );

    res.json({ profiles: compatible, myProfile: await profileWithPhotos(myProfile) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.post('/api/like', auth(async (req, res) => {
  try {
    const { wedding_code, target_profile_id } = req.body;
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [wedding_code]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const myProfile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

    if (!(await get('SELECT id FROM likes WHERE wedding_id=$1 AND from_profile_id=$2 AND to_profile_id=$3', [wedding.id, myProfile.id, target_profile_id])))
      await run('INSERT INTO likes (wedding_id,from_profile_id,to_profile_id) VALUES ($1,$2,$3)', [wedding.id, myProfile.id, target_profile_id]);

    await run('DELETE FROM passes WHERE wedding_id=$1 AND from_profile_id=$2 AND to_profile_id=$3', [wedding.id, myProfile.id, target_profile_id]);

    const mutual = await get('SELECT id FROM likes WHERE wedding_id=$1 AND from_profile_id=$2 AND to_profile_id=$3', [wedding.id, target_profile_id, myProfile.id]);
    let isMatch = false;
    if (mutual) {
      const exists = await get('SELECT id FROM matches WHERE wedding_id=$1 AND ((profile1_id=$2 AND profile2_id=$3) OR (profile1_id=$4 AND profile2_id=$5))',
        [wedding.id, myProfile.id, target_profile_id, target_profile_id, myProfile.id]);
      if (!exists) { await run('INSERT INTO matches (wedding_id,profile1_id,profile2_id) VALUES ($1,$2,$3)', [wedding.id, myProfile.id, target_profile_id]); isMatch = true; }
    }
    res.json({ isMatch, matchedProfile: isMatch ? await profileWithPhotos(await get('SELECT * FROM profiles WHERE id=$1', [target_profile_id])) : null });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.post('/api/pass', auth(async (req, res) => {
  try {
    const { wedding_code, target_profile_id } = req.body;
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [wedding_code]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const myProfile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });
    if (!(await get('SELECT id FROM passes WHERE wedding_id=$1 AND from_profile_id=$2 AND to_profile_id=$3', [wedding.id, myProfile.id, target_profile_id])))
      await run('INSERT INTO passes (wedding_id,from_profile_id,to_profile_id) VALUES ($1,$2,$3)', [wedding.id, myProfile.id, target_profile_id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.post('/api/undo-swipe', auth(async (req, res) => {
  try {
    const { wedding_code, target_profile_id, direction } = req.body;
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [wedding_code]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const myProfile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

    if (direction === 'right') {
      await run('DELETE FROM matches WHERE wedding_id=$1 AND ((profile1_id=$2 AND profile2_id=$3) OR (profile1_id=$4 AND profile2_id=$5))',
        [wedding.id, myProfile.id, target_profile_id, target_profile_id, myProfile.id]);
      await run('DELETE FROM likes WHERE wedding_id=$1 AND from_profile_id=$2 AND to_profile_id=$3', [wedding.id, myProfile.id, target_profile_id]);
    } else {
      await run('DELETE FROM passes WHERE wedding_id=$1 AND from_profile_id=$2 AND to_profile_id=$3', [wedding.id, myProfile.id, target_profile_id]);
    }
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

// ===================== MATCHES =====================

app.get('/api/matches/:weddingCode', auth(async (req, res) => {
  try {
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [req.params.weddingCode]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const myProfile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

    const rows = await all(`SELECT CASE WHEN profile1_id=$1 THEN profile2_id ELSE profile1_id END as other_id
      FROM matches WHERE wedding_id=$2 AND (profile1_id=$3 OR profile2_id=$4)`, [myProfile.id, wedding.id, myProfile.id, myProfile.id]);
    const result = (await Promise.all(rows.map(async r => {
      const p = await profileWithPhotos(await get('SELECT * FROM profiles WHERE id=$1', [r.other_id]));
      if (!p) return null;
      const lastMsg = await get('SELECT text, created_at FROM messages WHERE wedding_id=$1 AND ((from_profile_id=$2 AND to_profile_id=$3) OR (from_profile_id=$4 AND to_profile_id=$5)) ORDER BY created_at DESC LIMIT 1',
        [wedding.id, myProfile.id, r.other_id, r.other_id, myProfile.id]);
      return { ...p, lastMessage: lastMsg?.text || null };
    }))).filter(Boolean);
    res.json({ matches: result });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

// ===================== MESSAGES =====================

app.get('/api/messages/:weddingCode/:otherProfileId', auth(async (req, res) => {
  try {
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [req.params.weddingCode]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const myProfile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

    const messages = await all(`SELECT * FROM messages WHERE wedding_id=$1 AND
      ((from_profile_id=$2 AND to_profile_id=$3) OR (from_profile_id=$4 AND to_profile_id=$5))
      ORDER BY created_at ASC`,
      [wedding.id, myProfile.id, req.params.otherProfileId, req.params.otherProfileId, myProfile.id]);

    res.json({ messages: messages.map(m => ({ ...m, mine: m.from_profile_id === myProfile.id })), myProfileId: myProfile.id });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

app.post('/api/messages', auth(async (req, res) => {
  try {
    const { wedding_code, to_profile_id, text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Mensaje vacio' });
    const wedding = await get('SELECT * FROM weddings WHERE code = $1', [wedding_code]);
    if (!wedding) return res.status(404).json({ error: 'Boda no encontrada' });
    const myProfile = await get('SELECT * FROM profiles WHERE user_id = $1 AND wedding_id = $2', [req.user.id, wedding.id]);
    if (!myProfile) return res.status(404).json({ error: 'No tienes perfil' });

    const matched = await get('SELECT id FROM matches WHERE wedding_id=$1 AND ((profile1_id=$2 AND profile2_id=$3) OR (profile1_id=$4 AND profile2_id=$5))',
      [wedding.id, myProfile.id, to_profile_id, to_profile_id, myProfile.id]);
    if (!matched) return res.status(403).json({ error: 'No teneis match' });

    await run('INSERT INTO messages (wedding_id,from_profile_id,to_profile_id,text) VALUES ($1,$2,$3,$4)',
      [wedding.id, myProfile.id, to_profile_id, text.trim()]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error interno' }); }
}));

// ===================== SERVE =====================

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'wedding-tinder.html')); });

// ===================== START =====================

async function start() {
  await run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS weddings (id TEXT PRIMARY KEY, code TEXT UNIQUE NOT NULL, names TEXT NOT NULL, couple_user_id TEXT NOT NULL, wedding_date TEXT DEFAULT '', venue TEXT DEFAULT '', require_approval INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, wedding_id TEXT NOT NULL, name TEXT NOT NULL, age INTEGER NOT NULL, gender TEXT NOT NULL, orientation TEXT NOT NULL, status TEXT DEFAULT 'approved', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, wedding_id))`);
  await run(`CREATE TABLE IF NOT EXISTS photos (id SERIAL PRIMARY KEY, profile_id TEXT NOT NULL, photo_data TEXT NOT NULL, sort_order INTEGER DEFAULT 0)`);
  await run(`CREATE TABLE IF NOT EXISTS likes (id SERIAL PRIMARY KEY, wedding_id TEXT NOT NULL, from_profile_id TEXT NOT NULL, to_profile_id TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(wedding_id, from_profile_id, to_profile_id))`);
  await run(`CREATE TABLE IF NOT EXISTS matches (id SERIAL PRIMARY KEY, wedding_id TEXT NOT NULL, profile1_id TEXT NOT NULL, profile2_id TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS passes (id SERIAL PRIMARY KEY, wedding_id TEXT NOT NULL, from_profile_id TEXT NOT NULL, to_profile_id TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(wedding_id, from_profile_id, to_profile_id))`);
  await run(`CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, wedding_id TEXT NOT NULL, from_profile_id TEXT NOT NULL, to_profile_id TEXT NOT NULL, text TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Wedding Match running on: ${PORT}`));
}

start().catch(err => { console.error('Error:', err); process.exit(1); });
