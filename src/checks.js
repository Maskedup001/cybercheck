const net = require("net");
const tls = require("tls");
const https = require("https");
const http = require("http");

// Проверяет, открыт ли указанный порт.
// connectIp — уже проверенный IP-адрес (не hostname!), это важно для SSRF-защиты.
// Если соединение установилось — порт открыт. Таймаут или ошибка — порт закрыт.
function checkPort(connectIp, port, timeout = 3000, retries = 1) {
  return new Promise((resolve) => {
    const attempt = (attemptsLeft) => {
      const socket = new net.Socket();
      let status = "closed";
      socket.setTimeout(timeout);
      socket.on("connect", () => {
        status = "open";
        socket.destroy();
      });
      socket.on("timeout", () => socket.destroy());
      socket.on("error", () => {});
      socket.on("close", () => {
        if (status === "closed" && attemptsLeft > 0) {
          // Если закрыт и есть попытки — пробуем еще раз через 500мс
          setTimeout(() => attempt(attemptsLeft - 1), 500);
        } else {
          resolve({ port, status });
        }
      });
      socket.connect(port, connectIp);
    };
    attempt(retries);
  });
}

// Проверяет SSL-сертификат на указанном порту.
// connectIp — IP для подключения, hostname — для SNI (только если это домен, не IP).
// rejectUnauthorized: false нужен, чтобы ПРОЧИТАТЬ информацию о невалидных
// сертификатах (просроченных, самоподписанных) — иначе соединение оборвётся.

// Проверяет, принимает ли сервер устаревшие версии TLS (1.0 / 1.1)
function checkOldTls(connectIp, port, hostname) {
  return new Promise((resolve) => {
    const servername = net.isIP(hostname) ? undefined : hostname;
    const socket = tls.connect(
      {
        host: connectIp,
        port,
        servername,
        rejectUnauthorized: false,
        minVersion: "TLSv1",
        maxVersion: "TLSv1.1", // Принудительно ограничиваем версию
      },
      () => {
        resolve(true); // Если подключился — значит, поддерживает старые TLS
        socket.destroy();
      },
    );
    socket.on("error", () => resolve(false));
    socket.setTimeout(3000, () => {
      socket.destroy();
      resolve(false);
    });
  });
}

async function checkSSL(connectIp, port, hostname) {
  if (!port) return { hasSSL: false };

  // Параллельно проверяем поддержку устаревших TLS
  const supportsOldTls = await checkOldTls(connectIp, port, hostname);

  return new Promise((resolve) => {
    const servername = net.isIP(hostname) ? undefined : hostname;

    const socket = tls.connect(
      {
        host: connectIp,
        port,
        servername,
        rejectUnauthorized: false,
        minVersion: "TLSv1",
      },
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
          verifyError, // <-- Причина ошибки в ответ
          daysLeft,
          validTo: cert.valid_to,
          validToISO: (() => {
            if (!cert.valid_to) return null;
            const d = new Date(cert.valid_to);
            return Number.isNaN(d.getTime()) ? null : d.toISOString();
          })(),
          issuer: cert.issuer?.O || cert.issuer?.CN || "неизвестен",
          tlsVersion: socket.getProtocol(),
          supportsOldTls, // <--- Результат в ответ
        });
      },
    );

    socket.on("error", () => resolve({ hasSSL: false }));
    socket.setTimeout(5000, () => {
      socket.destroy();
      resolve({ hasSSL: false });
    });
  });
}

// Проверяет HTTP-заголовки безопасности.
// Сначала пробует HTTPS, при ошибке — HTTP (для сайтов без SSL).
// connectIp — IP для подключения, hostname — для SNI и Host-заголовка.
function checkHeaders(connectIp, port, hostname, retries = 1) {
  return new Promise((resolve) => {
    if (!port) return resolve({ error: true });

    const servername = net.isIP(hostname) ? undefined : hostname;
    let settled = false;
    const resolveOnce = (data) => {
      if (settled) return;
      settled = true;
      resolve(data);
    };

    const attempt = (attemptsLeft) => {
      const tryHttp = (callback) => {
        const req = http.get(
          {
            host: connectIp,
            port,
            headers: { Host: hostname, "User-Agent": "CyberCheck/1.1" },
            timeout: 5000,
          },
          (res) => {
            resolveOnce(parseHeaders(res.headers, "HTTP"));
            res.destroy();
          },
        );
        req.on("error", callback);
        req.on("timeout", () => {
          req.destroy();
          callback();
        });
      };

      const tryHttps = () => {
        const req = https.get(
          {
            host: connectIp,
            port,
            servername,
            rejectUnauthorized: false,
            headers: { Host: hostname, "User-Agent": "CyberCheck/1.1" },
            timeout: 5000,
          },
          (res) => {
            resolveOnce(parseHeaders(res.headers, "HTTPS"));
            res.destroy();
          },
        );

        const onFail = () => {
          tryHttp(() => {
            if (attemptsLeft > 0) {
              // Ждем 1 секунду и пробуем снова
              setTimeout(() => attempt(attemptsLeft - 1), 1000);
            } else {
              resolveOnce({ error: true });
            }
          });
        };

        req.on("error", onFail);
        req.on("timeout", () => {
          req.destroy();
          onFail();
        });
      };

      tryHttps();
    };

    attempt(retries);
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
