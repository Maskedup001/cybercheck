const net = require('net');
const tls = require('tls');
const https = require('https');
const http = require('http');

// Проверка одного порта. Таймаут 3 сек — медленные сайты считаем закрытыми
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

// Проверка SSL. rejectUnauthorized: false — не падаем на просроченных сертификатах
function checkSSL(host, port) {
  return new Promise((resolve) => {
    if (!port) {
      return resolve({ hasSSL: false });
    }

    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();

        if (!cert || !cert.valid_to) {
          socket.end();
          return resolve({ hasSSL: false });
        }

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
    socket.setTimeout(3000, () => {
      socket.destroy();
      resolve({ hasSSL: false });
    });
  });
}

// Проверка заголовков. Сначала HTTPS, при ошибке — HTTP (для сайтов без SSL)
function checkHeaders(host, port) {
  return new Promise((resolve) => {
    if (!port) {
      return resolve({ error: true });
    }

    const tryHttp = () => {
      const req = http.get(
        `http://${host}:${port}`,
        { timeout: 5000 },
        (res) => {
          resolve(parseHeaders(res.headers, 'HTTP'));
          res.destroy();
        }
      );

      req.on('error', () => resolve({ error: true }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ error: true });
      });
    };

    const tryHttps = () => {
      const req = https.get(
        `https://${host}:${port}`,
        { timeout: 5000, rejectUnauthorized: false },
        (res) => {
          resolve(parseHeaders(res.headers, 'HTTPS'));
          res.destroy();
        }
      );

      req.on('error', tryHttp);
      req.on('timeout', () => {
        req.destroy();
        tryHttp();
      });
    };

    tryHttps();
  });
}

// Приводим заголовки к общему формату для фронтенда
function parseHeaders(h, protocol) {
  return {
    protocol: protocol,
    server: h['server'] || 'не указан',
    csp: !!h['content-security-policy'],
    xframe: !!h['x-frame-options'],
    hsts: !!h['strict-transport-security'],
    xcontent: !!h['x-content-type-options']
  };
}

module.exports = { checkPort, checkSSL, checkHeaders };