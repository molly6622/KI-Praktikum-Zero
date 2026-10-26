const bcrypt = require('bcryptjs');
const db = require('./shared/db');
const cfg = require('./shared/config');

db.exec(`
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS transkrip;
DROP TABLE IF EXISTS nilai;
DROP TABLE IF EXISTS kelas;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS service_clients;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  nim TEXT
);
CREATE TABLE devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  device_id TEXT NOT NULL
);
CREATE TABLE kelas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nama TEXT NOT NULL,
  dosen_id INTEGER NOT NULL
);
CREATE TABLE nilai (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id INTEGER NOT NULL,
  mahasiswa_id INTEGER NOT NULL,
  nilai REAL NOT NULL,
  final INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE transkrip (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nim TEXT NOT NULL,
  kelas_id INTEGER NOT NULL,
  nilai REAL NOT NULL,
  UNIQUE (nim, kelas_id)
);
CREATE TABLE refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE service_clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL
);
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  waktu TEXT, subjek TEXT, endpoint TEXT,
  device TEXT, hasil TEXT, alasan TEXT
);
`);

const hash = bcrypt.hashSync('password123', 10);
const addUser = db.prepare('INSERT INTO users (username,password_hash,role,nim) VALUES (?,?,?,?)');
const addDev = db.prepare('INSERT INTO devices (user_id,device_id) VALUES (?,?)');

const users = [
  ['admin1', 'admin', null, 'DEV-ADMIN1'],
  ['dosen1', 'dosen', null, 'DEV-DOSEN1'],
  ['dosen2', 'dosen', null, 'DEV-DOSEN2'],
  ['mhs1', 'mahasiswa', '2210001', 'DEV-MHS1'],
  ['mhs2', 'mahasiswa', '2210002', 'DEV-MHS2'],
  ['mhs3', 'mahasiswa', '2210003', 'DEV-MHS3'],
];
const id = {};
for (const [u, role, nim, dev] of users) {
  id[u] = addUser.run(u, hash, role, nim).lastInsertRowid;
  addDev.run(id[u], dev);
}

// 2 kelas, dosen berbeda
db.prepare('INSERT INTO kelas (nama,dosen_id) VALUES (?,?)').run('Keamanan Informasi', id.dosen1); // id 1
db.prepare('INSERT INTO kelas (nama,dosen_id) VALUES (?,?)').run('Basis Data', id.dosen2);         // id 2

const addNilai = db.prepare('INSERT INTO nilai (kelas_id,mahasiswa_id,nilai) VALUES (?,?,?)');
addNilai.run(1, id.mhs1, 80);
addNilai.run(1, id.mhs2, 70);
addNilai.run(2, id.mhs1, 90);
addNilai.run(2, id.mhs3, 85);

db.prepare('INSERT INTO service_clients VALUES (?,?)')
  .run(cfg.SERVICE_CLIENT_ID, bcrypt.hashSync(cfg.SERVICE_CLIENT_SECRET, 10));

console.log('Seed selesai.');