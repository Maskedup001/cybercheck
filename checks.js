const net = require('net');
const tls = require('tls');
const https = require('https');

// Проверка одного порта
function checkPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = 'closed';

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      status = 'open';
      socket.destroy();
    });

    socket.on('timeout', () => socket.destroy());
    socket.on('error', () => {});
    socket.on('close', () => resolve({ port, status }));

    socket.connect(port, host);
  });
}

// Проверка SSL-сертификата
function checkSSL(host) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const valid = socket.authorized;
        const daysLeft = Math.floor(
          (new Date(cert.valid_to) - Date.now()) / 86400000
        );

        socket.end();
        resolve({
          hasSSL: true,
          valid,
          daysLeft,
          validTo: cert.valid_to,
          issuer: cert.issuer?.O || 'неизвестен'
        });
      }
    );

    socket.on('error', () => resolve({ hasSSL: false }));
    socket.setTimeout(3000, () => socket.destroy());
  });
}

// Проверка заголовков безопасности
function checkHeaders(host) {
  return new Promise((resolve) => {
    const req = https.get(
      `https://${host}`,
      {
        timeout: 5000,
        rejectUnauthorized: false   // ← важно: не падать на невалидном сертификате
      },
      (res) => {
        const h = res.headers;
        resolve({
          server: h['server'] || 'не указан',
          csp: !!h['content-security-policy'],
          xframe: !!h['x-frame-options'],
          hsts: !!h['strict-transport-security'],
          xcontent: !!h['x-content-type-options']
        });
        res.destroy();
      }
    );

    req.on('error', () => resolve({ error: true }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ error: true });
    });
  });
}

module.exports = { checkPort, checkSSL, checkHeaders };