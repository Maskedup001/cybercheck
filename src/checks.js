const net = require("net");
const tls = require("tls");
const https = require("https");
const http = require("http");

// Проверяет, открыт ли указанный порт.
// connectIp — уже проверенный IP-адрес (не hostname!), это важно для SSRF-защиты.
// Если соединение установилось — порт открыт. Таймаут или ошибка — порт закрыт.
function checkPort(connectIp, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = "closed";

    socket.setTimeout(timeout);

    socket.on("connect", () => {
      status = "open";
      socket.destroy();
    });

    socket.on("timeout", () => socket.destroy());
    socket.on("error", () => {});
    socket.on("close", () => resolve({ port, status }));

    socket.connect(port, connectIp);
  });
}

// Проверяет SSL-сертификат на указанном порту.
// connectIp — IP для подключения, hostname — для SNI (только если это домен, не IP).
// rejectUnauthorized: false нужен, чтобы ПРОЧИТАТЬ информацию о невалидных
// сертификатах (просроченных, самоподписанных) — иначе соединение оборвётся.
function checkSSL(connectIp, port, hostname) {
  return new Promise((resolve) => {
    if (!port) return resolve({ hasSSL: false });

    // SNI (Server Name Indication) по RFC 6066 запрещён для IP-литералов.
    // Передаём только если hostname — доменное имя.
    const servername = net.isIP(hostname) ? undefined : hostname;

    const socket = tls.connect(
      { host: connectIp, port, servername, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();

        // Сертификат не пришёл — значит на этом порту не TLS
        if (!cert || !cert.valid_to) {
          socket.end();
          return resolve({ hasSSL: false });
        }

        const verifyError = socket.authorizationError || null;
        const valid = verifyError === null;
        const daysLeft = Math.floor(
          (new Date(cert.valid_to) - Date.now()) / 86400000,
        );

        socket.end();
        resolve({
          hasSSL: true,
          valid,
          verifyError, // <-- добавляем причину ошибки в ответ
          daysLeft,
          validTo: cert.valid_to,
          validToISO: (() => {
            if (!cert.valid_to) return null;
            const d = new Date(cert.valid_to);
            return Number.isNaN(d.getTime()) ? null : d.toISOString();
          })(),
          issuer: cert.issuer?.O || cert.issuer?.CN || "неизвестен",
        });
      },
    );

    socket.on("error", () => resolve({ hasSSL: false }));
    socket.setTimeout(3000, () => {
      socket.destroy();
      resolve({ hasSSL: false });
    });
  });
}

// Проверяет HTTP-заголовки безопасности.
// Сначала пробует HTTPS, при ошибке — HTTP (для сайтов без SSL).
// connectIp — IP для подключения, hostname — для SNI и Host-заголовка.
function checkHeaders(connectIp, port, hostname) {
  return new Promise((resolve) => {
    if (!port) return resolve({ error: true });

    const servername = net.isIP(hostname) ? undefined : hostname;

    // Запасной вариант — HTTP (если HTTPS не ответил)
    const tryHttp = () => {
      const req = http.get(
        { host: connectIp, port, headers: { Host: hostname }, timeout: 5000 },
        (res) => {
          resolve(parseHeaders(res.headers, "HTTP"));
          res.destroy();
        },
      );

      req.on("error", () => resolve({ error: true }));
      req.on("timeout", () => {
        req.destroy();
        resolve({ error: true });
      });
    };

    // Основной вариант — HTTPS
    const tryHttps = () => {
      const req = https.get(
        {
          host: connectIp,
          port,
          servername,
          rejectUnauthorized: false,
          headers: { Host: hostname },
          timeout: 5000,
        },
        (res) => {
          resolve(parseHeaders(res.headers, "HTTPS"));
          res.destroy();
        },
      );

      req.on("error", tryHttp);
      req.on("timeout", () => {
        req.destroy();
        tryHttp();
      });
    };

    tryHttps();
  });
}

// Приводит заголовки к единому формату для фронтенда.
// protocol — 'HTTP' или 'HTTPS', чтобы клиент видел реальную схему.
function parseHeaders(h, protocol) {
  return {
    protocol,
    server: h["server"] || "не указан",
    csp: !!h["content-security-policy"],
    xframe: !!h["x-frame-options"],
    hsts: !!h["strict-transport-security"],
    xcontent: !!h["x-content-type-options"],
  };
}

module.exports = { checkPort, checkSSL, checkHeaders };
