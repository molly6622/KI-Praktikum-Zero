const express = require('express');
const db = require('../shared/db');
const cfg = require('../shared/config');
const { requireGateway, requireToken } = require('../shared/verify');

const app = express();
app.use(express.json());
app.use(requireGateway);
app.use(requireToken);

app.get('/nilai', (req, res) => {
  const { role, sub } = req.user;
  if (role === 'mahasiswa') {
    return res.json(db.prepare(
      'SELECT id,kelas_id,nilai,final FROM nilai WHERE mahasiswa_id=?').all(Number(sub)));
  }
  if (role === 'dosen') {
    const k = db.prepare('SELECT 1 FROM kelas WHERE id=? AND dosen_id=?')
      .get(req.query.kelas_id, Number(sub));
    if (!k) return res.status(403).json({ error: 'Bukan kelas Anda' });
    return res.json(db.prepare(
      'SELECT id,mahasiswa_id,nilai,final FROM nilai WHERE kelas_id=?').all(req.query.kelas_id));
  }
  res.status(403).json({ error: 'Role tidak berhak' });
});

app.put('/nilai/:id', (req, res) => {
  if (req.user.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });
  const { nilai } = req.body || {};
  if (typeof nilai !== 'number' || nilai < 0 || nilai > 100)
    return res.status(400).json({ error: 'nilai harus angka 0-100' });

  const row = db.prepare(`
    SELECT n.* FROM nilai n JOIN kelas k ON k.id=n.kelas_id
    WHERE n.id=? AND k.dosen_id=?`).get(req.params.id, Number(req.user.sub));
  if (!row) return res.status(403).json({ error: 'Bukan kelas Anda' });
  if (row.final) return res.status(409).json({ error: 'Nilai sudah final' });

  db.prepare('UPDATE nilai SET nilai=? WHERE id=?').run(nilai, row.id);
  res.json({ message: 'Nilai diubah' });
});

app.post('/kelas/:id/finalisasi', async (req, res) => {
  if (req.user.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });
  const kelasId = Number(req.params.id);
  const k = db.prepare('SELECT 1 FROM kelas WHERE id=? AND dosen_id=?')
    .get(kelasId, Number(req.user.sub));
  if (!k) return res.status(403).json({ error: 'Bukan kelas Anda' });

  db.prepare('UPDATE nilai SET final=1 WHERE kelas_id=?').run(kelasId);

  try {
    // 1) Minta token service ke gateway
    const t = await fetch(`${cfg.GATEWAY_URL}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: cfg.SERVICE_CLIENT_ID,
        client_secret: cfg.SERVICE_CLIENT_SECRET,
      }),
    });
    if (!t.ok) throw new Error('Gagal ambil token service');
    const { accessToken } = await t.json();

    // 2) Kirim nilai ke transkrip, tetap lewat gateway
    const items = db.prepare(`
      SELECT u.nim, n.kelas_id, n.nilai FROM nilai n
      JOIN users u ON u.id=n.mahasiswa_id WHERE n.kelas_id=?`).all(kelasId);

    const s = await fetch(`${cfg.GATEWAY_URL}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ items }),
    });
    if (!s.ok) throw new Error('Sinkron ke transkrip ditolak');

    res.json({ message: 'Kelas difinalisasi dan transkrip disinkronkan' });
  } catch (e) {
    // gagal sinkron: batalkan finalisasi agar data konsisten
    db.prepare('UPDATE nilai SET final=0 WHERE kelas_id=?').run(kelasId);
    res.status(502).json({ error: e.message });
  }
});

app.listen(3001, () => console.log('Service Nilai jalan di port 3001'));