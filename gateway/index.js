const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const db = require('../shared/db');
const cfg = require('../shared/config');
const { decide } = require('./policy');

const app = express();
app.use((req, res, next) => { delete req.headers.expect; next(); });
app.use(express.json());

/* ---------- Helper ---------- */
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function audit(req, subject, result, reason) {
  db.prepare(
    'INSERT INTO audit_log (waktu,subjek,endpoint,device,hasil,alasan) VALUES (?,?,?,?,?,?)'
  ).run(
    new Date().toISOString(),
    subject || 'anonim',
    `${req.method} ${req.originalUrl}`,
    req.get('X-Device-ID') || '-',
    result,
    reason
  );
}

function tolak(req, res, status, reason, subject) {
  audit(req, subject, 'deny', reason);
  return res.status(status).json({ error: reason });
}

function deviceTerdaftar(userId, deviceId) {
  if (!deviceId) return false;
  return !!db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=?').get(userId, deviceId);
}

const buatAccessToken = (user) =>
  jwt.sign({ sub: String(user.id), role: user.role }, cfg.JWT_SECRET, { expiresIn: '10m' });

/* ---------- Endpoint /auth/* (ditangani gateway sendiri) ---------- */

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username || '');
  if (!user || !bcrypt.compareSync(password || '', user.password_hash))
    return tolak(req, res, 401, 'Kredensial salah', username);
  if (!deviceTerdaftar(user.id, req.get('X-Device-ID')))
    return tolak(req, res, 403, 'Device tidak terdaftar', username);

  const refreshToken = crypto.randomBytes(48).toString('hex');
  db.prepare('INSERT INTO refresh_tokens (token_hash,user_id,expires_at) VALUES (?,?,?)')
    .run(sha256(refreshToken), user.id, Date.now() + 24 * 60 * 60 * 1000); // 1 hari

  audit(req, username, 'allow', 'Login berhasil');
  res.json({ accessToken: buatAccessToken(user), refreshToken });
});

app.post('/auth/refresh', (req, res) => {
  const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash=?')
    .get(sha256((req.body || {}).refreshToken || ''));
  if (!row || row.revoked || row.expires_at < Date.now())
    return tolak(req, res, 401, 'Refresh token tidak valid / dicabut / kedaluwarsa');
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(row.user_id);
  audit(req, user.username, 'allow', 'Refresh berhasil');
  res.json({ accessToken: buatAccessToken(user) });
});

app.post('/auth/logout', (req, res) => {
  const r = db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?')
    .run(sha256((req.body || {}).refreshToken || ''));
  if (r.changes === 0) return tolak(req, res, 400, 'Refresh token tidak ditemukan');
  audit(req, 'user', 'allow', 'Logout, refresh token dicabut');
  res.json({ message: 'Logout berhasil' });
});

app.post('/auth/service', (req, res) => {
  const { client_id, client_secret } = req.body || {};
  const c = db.prepare('SELECT * FROM service_clients WHERE client_id=?').get(client_id || '');
  if (!c || !bcrypt.compareSync(client_secret || '', c.secret_hash))
    return tolak(req, res, 401, 'Client ID / secret salah', client_id);
  const token = jwt.sign({ sub: c.client_id, role: 'service' }, cfg.JWT_SECRET, { expiresIn: '5m' });
  audit(req, c.client_id, 'allow', 'Token service diterbitkan');
  res.json({ accessToken: token });
});

/* ---------- Penjaga (PEP): semua selain /auth/* lewat sini ---------- */
function guard(req, res, next) {
  const auth = req.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return tolak(req, res, 401, 'Token tidak ada');

  let user;
  try {
    user = jwt.verify(token, cfg.JWT_SECRET);
  } catch {
    return tolak(req, res, 401, 'Token tidak valid / kedaluwarsa');
  }

  if (user.role !== 'service' && !deviceTerdaftar(Number(user.sub), req.get('X-Device-ID')))
    return tolak(req, res, 403, 'Device tidak terdaftar untuk user ini', user.sub);

  const hasil = decide({ user, method: req.method, path: req.path, query: req.query });
  if (!hasil.allow) return tolak(req, res, 403, hasil.reason, user.sub);

  audit(req, user.sub, 'allow', hasil.reason);
  next();
}
app.use(guard);

/* ---------- Teruskan ke service + tambah X-Gateway-Secret ---------- */
const proxyOpts = (target, pathFilter) => ({
  target,
  pathFilter,
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('X-Gateway-Secret', cfg.GATEWAY_SECRET);
      fixRequestBody(proxyReq, req);
    },
  },
});
app.use(createProxyMiddleware(proxyOpts(cfg.NILAI_URL, ['/nilai', '/kelas'])));
app.use(createProxyMiddleware(proxyOpts(cfg.TRANSKRIP_URL, ['/transkrip'])));

app.listen(3000, () => console.log('Gateway (PEP) jalan di port 3000'));