const db = require('../shared/db');
const cfg = require('../shared/config');

const allow = (reason) => ({ allow: true, reason });
const deny = (reason) => ({ allow: false, reason });

function dalamJamAkses(now = new Date()) {
  const h = now.getHours();
  return h >= cfg.JAM_BUKA && h < cfg.JAM_TUTUP;
}

function dosenMengampu(dosenId, kelasId) {
  return !!db.prepare('SELECT 1 FROM kelas WHERE id=? AND dosen_id=?').get(kelasId, dosenId);
}

function decide({ user, method, path, query }) {
  const uid = Number(user.sub);
  let m;

  // GET /nilai
  if (method === 'GET' && path === '/nilai') {
    if (user.role === 'mahasiswa') return allow('Mahasiswa melihat nilai sendiri');
    if (user.role === 'dosen') {
      if (!query.kelas_id) return deny('Dosen wajib menyebut kelas_id');
      return dosenMengampu(uid, query.kelas_id)
        ? allow('Dosen melihat kelas yang diampu')
        : deny('Kelas bukan yang diampu dosen ini');
    }
    return deny('Role tidak berhak melihat nilai');
  }

  // PUT /nilai/:id
  if ((m = path.match(/^\/nilai\/(\d+)$/)) && method === 'PUT') {
    if (user.role !== 'dosen') return deny('Hanya dosen yang boleh mengubah nilai');
    const row = db.prepare('SELECT * FROM nilai WHERE id=?').get(m[1]);
    if (!row) return deny('Data nilai tidak ditemukan');
    if (!dosenMengampu(uid, row.kelas_id)) return deny('Kelas bukan yang diampu dosen ini');
    if (row.final) return deny('Nilai sudah final');
    if (!dalamJamAkses()) return deny('Di luar jam akses');
    return allow('Dosen mengubah nilai kelasnya');
  }

  // POST /kelas/:id/finalisasi
  if ((m = path.match(/^\/kelas\/(\d+)\/finalisasi$/)) && method === 'POST') {
    if (user.role !== 'dosen') return deny('Hanya dosen yang boleh finalisasi');
    if (!dosenMengampu(uid, m[1])) return deny('Kelas bukan yang diampu dosen ini');
    if (!dalamJamAkses()) return deny('Di luar jam akses');
    return allow('Dosen memfinalisasi kelasnya');
  }

  // POST /transkrip/sinkron (harus sebelum /transkrip/:nim)
  if (method === 'POST' && path === '/transkrip/sinkron') {
    return user.role === 'service'
      ? allow('Token service sah')
      : deny('Hanya token service yang boleh sinkron');
  }

  // GET /transkrip/:nim
  if ((m = path.match(/^\/transkrip\/(\w+)$/)) && method === 'GET') {
    if (user.role === 'admin') return allow('Admin melihat semua transkrip');
    if (user.role === 'mahasiswa') {
      const me = db.prepare('SELECT nim FROM users WHERE id=?').get(uid);
      return me && me.nim === m[1]
        ? allow('Mahasiswa melihat transkrip sendiri')
        : deny('Mahasiswa hanya boleh melihat NIM sendiri');
    }
    return deny('Role tidak berhak melihat transkrip');
  }

  return deny('Tidak ada kebijakan untuk endpoint ini (default deny)');
}

module.exports = { decide };