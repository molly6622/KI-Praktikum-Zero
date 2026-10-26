const jwt = require('jsonwebtoken');
const cfg = require('./config');

// Lapis 1: request harus datang dari gateway
function requireGateway(req, res, next) {
  if (req.get('X-Gateway-Secret') !== cfg.GATEWAY_SECRET) {
    return res.status(403).json({ error: 'Akses langsung ke service ditolak' });
  }
  next();
}

// Lapis 2: token harus valid (tanda tangan + belum kedaluwarsa)
function requireToken(req, res, next) {
  const auth = req.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token tidak ada' });
  try {
    req.user = jwt.verify(token, cfg.JWT_SECRET); // { sub, role, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token tidak valid / kedaluwarsa' });
  }
}

module.exports = { requireGateway, requireToken };