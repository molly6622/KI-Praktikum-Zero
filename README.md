# Sistem Nilai - Zero Trust Security

Tugas Praktikum Individu, Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.

Sistem Nilai dengan API Gateway sebagai Policy Enforcement Point (PEP) yang terpisah dari service, mengikuti NIST SP 800-207. Prinsip yang diterapkan: never trust always verify, least privilege, dan assume breach.

## Arsitektur

| Komponen | Port | Peran (NIST SP 800-207) | Folder |
|---|---|---|---|
| API Gateway | 3000 | PEP, memuat Policy Engine / Policy Administrator | `gateway/` |
| Service Nilai | 3001 | Resource | `service-nilai/` |
| Service Transkrip | 3002 | Resource | `service-transkrip/` |
| Database SQLite | - | Resource (dipakai bersama) | `data/app.db` |
| Audit Log | - | Data source (tabel `audit_log`) | `data/app.db` |

Bagian penting:

- `gateway/index.js`: endpoint `/auth/*`, fungsi `guard` (verifikasi token, cek device, tanya policy, catat audit), dan proxy ke service.
- `gateway/policy.js`: Policy Engine (`decide`), mengembalikan allow/deny beserta alasan. Default deny.
- `shared/verify.js`: pemeriksaan di service (`requireGateway` untuk gateway secret, `requireToken` untuk verifikasi ulang token).
- `shared/config.js`: secret, port, dan jam akses.
- `seed.js`: membuat tabel dan data awal.

## Prasyarat

- Node.js 18 atau lebih baru (dicek dengan `node -v`)

## Cara menjalankan

1. Masuk ke folder proyek lalu install dependency:

   ```
   npm install express http-proxy-middleware jsonwebtoken better-sqlite3 bcryptjs
   ```

2. Buat database dan data awal:

   ```
   node seed.js
   ```

   Muncul tulisan `Seed selesai.` Perintah ini mengatur ulang semua data ke kondisi awal.

3. Jalankan ketiga server, masing-masing di terminal yang berbeda (semua dari folder proyek):

   ```
   node service-transkrip/index.js
   node service-nilai/index.js
   node gateway/index.js
   ```

   Tulisan yang harus muncul: `Service Transkrip jalan di port 3002`, `Service Nilai jalan di port 3001`, `Gateway (PEP) jalan di port 3000`.

Semua request dari client dikirim ke gateway (port 3000).

## Akun dan device ID data awal

Password semua akun: `password123`

| Username | Role | Device ID | NIM | Keterangan |
|---|---|---|---|---|
| admin1 | admin | DEV-ADMIN1 | - | Melihat transkrip semua mahasiswa |
| dosen1 | dosen | DEV-DOSEN1 | - | Mengampu kelas 1 (Keamanan Informasi) |
| dosen2 | dosen | DEV-DOSEN2 | - | Mengampu kelas 2 (Basis Data) |
| mhs1 | mahasiswa | DEV-MHS1 | 2210001 | Nilai di kelas 1 dan 2 |
| mhs2 | mahasiswa | DEV-MHS2 | 2210002 | Nilai di kelas 1 |
| mhs3 | mahasiswa | DEV-MHS3 | 2210003 | Nilai di kelas 2 |

Akun service (untuk `POST /auth/service`): client ID `service-nilai`, secret `rahasia-service-nilai`.

Id user di audit log: 1 admin1, 2 dosen1, 3 dosen2, 4 mhs1, 5 mhs2, 6 mhs3.

## Kebijakan akses

| Endpoint | Diizinkan | Kondisi |
|---|---|---|
| `POST /auth/login` | Semua user | Kredensial valid dan device terdaftar |
| `POST /auth/refresh`, `/auth/logout` | Semua user | Refresh token valid dan belum dicabut |
| `POST /auth/service` | Service Nilai | Client ID dan secret valid |
| `GET /nilai` | Mahasiswa, dosen | Mahasiswa: nilai miliknya. Dosen: kelas yang diampu (`?kelas_id=`) |
| `PUT /nilai/:id` | Dosen | Kelas yang diampu, nilai belum final, dalam jam akses |
| `POST /kelas/:id/finalisasi` | Dosen | Kelas yang diampu, dalam jam akses. Lalu sinkron ke transkrip lewat gateway |
| `GET /transkrip/:nim` | Mahasiswa, admin | Mahasiswa: NIM sendiri. Admin: semua NIM |
| `POST /transkrip/sinkron` | Service Nilai | Hanya token service |

## Mekanisme keamanan

- **Access token**: JWT berlaku 10 menit, berisi `sub` dan `role`, dikirim lewat `Authorization: Bearer <token>`.
- **Refresh token**: berlaku 1 hari, disimpan (hash SHA-256) di tabel `refresh_tokens`, bisa dicabut. Logout mencabut refresh token.
- **Token service**: berlaku 5 menit, role `service`, didapat dari `POST /auth/service`.
- **Gateway secret**: gateway menambahkan header `X-Gateway-Secret`; service menolak request tanpa header ini.
- **Verifikasi ulang di service**: service memverifikasi tanda tangan dan masa berlaku token walaupun request membawa gateway secret yang benar.
- **Device terdaftar**: setiap request user wajib membawa header `X-Device-ID` yang terdaftar untuk user tersebut (diperiksa saat login dan di setiap request).
- **Jam akses**: ubah nilai dan finalisasi hanya pukul 07.00 sampai 21.00 (jam lokal komputer).
- **Audit log**: setiap keputusan dicatat di tabel `audit_log` (waktu, subjek, endpoint, device, hasil, alasan). Waktu dalam UTC.

## Mengubah jam akses

Jam akses dibaca dari environment variable `JAM_BUKA` dan `JAM_TUTUP` (default 7 dan 21). Gateway harus di-restart setelah diubah.

PowerShell:

```
$env:JAM_BUKA=1; $env:JAM_TUTUP=2; node gateway/index.js
```

Git Bash / Linux / Mac:

```
JAM_BUKA=1 JAM_TUTUP=2 node gateway/index.js
```

## Contoh pengujian (PowerShell)

Login dosen1 lalu lihat nilai kelasnya:

```
$r = Invoke-RestMethod -Method Post -Uri http://localhost:3000/auth/login `
  -ContentType "application/json" `
  -Headers @{ "X-Device-ID" = "DEV-DOSEN1" } `
  -Body '{"username":"dosen1","password":"password123"}'

Invoke-RestMethod -Uri "http://localhost:3000/nilai?kelas_id=1" `
  -Headers @{ "Authorization" = "Bearer $($r.accessToken)"; "X-Device-ID" = "DEV-DOSEN1" }
```

Hasil yang diharapkan pada beberapa skenario:

| Skenario | Hasil |
|---|---|
| Request tanpa token | 401 |
| Token benar, `X-Device-ID` salah | 403 |
| dosen1 membuka `/nilai?kelas_id=2` (kelas dosen2) | 403 |
| mhs1 membuka `/transkrip/2210002` | 403 |
| admin1 membuka `/transkrip/2210002` | 200 |
| Ubah nilai setelah kelas final | 403 |
| Ubah nilai di luar jam akses | 403 |
| Token user ke `POST /transkrip/sinkron` | 403 |
| Akses langsung ke `localhost:3001` tanpa gateway secret | 403 |
| Akses langsung ke `localhost:3001` dengan secret tanpa token | 401 |
| Refresh dengan token yang sudah di-logout | 401 |

## Melihat audit log

```
node -e "const db=require('./shared/db');console.table(db.prepare('SELECT waktu,subjek,endpoint,device,hasil,alasan FROM audit_log ORDER BY id DESC LIMIT 20').all())"
```

## Catatan

- Request ber-body (PUT/POST) dari PowerShell membawa header `Expect: 100-continue` yang bisa membuat proxy menggantung. Gateway sudah menghapus header ini di bagian awal `gateway/index.js`.
- Secret pada `shared/config.js` berupa nilai contoh untuk keperluan praktikum. Pada sistem nyata, secret diatur lewat environment variable.
