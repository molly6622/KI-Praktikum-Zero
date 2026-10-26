module.exports = {
  JWT_SECRET: process.env.JWT_SECRET || 'ganti-rahasia-jwt',
  GATEWAY_SECRET: process.env.GATEWAY_SECRET || 'ganti-rahasia-gateway',

  // akun service nilai (untuk POST /auth/service)
  SERVICE_CLIENT_ID: 'service-nilai',
  SERVICE_CLIENT_SECRET: process.env.SERVICE_CLIENT_SECRET || 'rahasia-service-nilai',

  // jam akses, bisa diubah lewat environment agar mudah didemokan
  JAM_BUKA: Number(process.env.JAM_BUKA ?? 7),
  JAM_TUTUP: Number(process.env.JAM_TUTUP ?? 21),

  GATEWAY_URL: 'http://localhost:3000',
  NILAI_URL: 'http://localhost:3001',
  TRANSKRIP_URL: 'http://localhost:3002',
};