const express = require('express');
const db = require('../shared/db');
const { requireGateway, requireToken } = require('../shared/verify');

const app = express();
app.use(express.json());
app.use(requireGateway); // lapis 1
app.use(requireToken);   // lapis 2

app.post('/transkrip/sinkron', (req, res) => {
  if (req.user.role !== 'service')
    return res.status(403).json({ error: 'Hanya token service' });

  const { items } = req.body || {};
  if (!Array.isArray(items)) return res.status(400).json({ error: 'items wajib array' });

  const upsert = db.prepare(`
    INSERT INTO transkrip (nim,kelas_id,nilai) VALUES (?,?,?)
    ON CONFLICT(nim,kelas_id) DO UPDATE SET nilai=excluded.nilai`);
  db.transaction(() => items.forEach((i) => upsert.run(i.nim, i.kelas_id, i.nilai)))();

  res.json({ message: `${items.length} nilai masuk ke transkrip` });
});

app.get('/transkrip/:nim', (req, res) => {
  const { role, sub } = req.user;
  if (role === 'mahasiswa') {
    const me = db.prepare('SELECT nim FROM users WHERE id=?').get(Number(sub));
    if (!me || me.nim !== req.params.nim)
      return res.status(403).json({ error: 'Bukan NIM Anda' });
  } else if (role !== 'admin') {
    return res.status(403).json({ error: 'Role tidak berhak' });
  }
  const rows = db.prepare(`
    SELECT t.nim, k.nama AS mata_kuliah, t.nilai
    FROM transkrip t JOIN kelas k ON k.id=t.kelas_id WHERE t.nim=?`).all(req.params.nim);
  res.json(rows);
});

app.listen(3002, () => console.log('Service Transkrip jalan di port 3002'));