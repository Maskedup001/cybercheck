const net = require("net");
const tls = require("tls");
const https = require("https");
const http = require("http");

// Проверяет, открыт ли указанный порт.
// connectIp — уже проверенный IP-адрес (не hostname!), это важно для SSRF-защиты.
// Если соединение установилось — порт открыт. Таймаут или ошибка — порт закрыт.
function checkPort(connectIp, port, timeout = 3000, retries = 1, signal) {
  return new Promise((resolve) => {
    const attempt = (attemptsLeft) => {
      if (signal?.aborted) return resolve({ port, status: "closed" });
      const socket = new net.Socket();
      let status = "closed";

      if (signal) {
        signal.addEventListener(
          "abort",
          () => {
            socket.destroy();
            resolve({ port, status: "closed" });
          },
          { once: true },
        );
      }
      socket.setTimeout(timeout);
      socket.on("connect", () => {
        status = "open";
        socket.destroy();
      });
      socket.on("timeout", () => socket.destroy());
      socket.on("error", (err) => {
        // При явном отказе ретрай бессмыслен
        if (err.code === "ECONNREFUSED") status = "refused";
      });
      socket.on("close", () => {
        if (signal?.aborted) return;
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
function checkOldTls(connectIp, port, hostname, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve(false);
    const servername = net.isIP(hostname) ? undefined : hostname;
    const socket = tls.connect(
      {
        host: connectIp,
        port,
        servername,
        rejectUnauthorized: false,
        minVersion: "TLSv1",
        maxVersion: "TLSv1.1",
        ciphers: "DEFAULT@SECLEVEL=0",
        signal,
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

async function checkSSL(connectIp, port, hostname, signal) {
  if (!port) return { hasSSL: false };

  return new Promise((resolve) => {
    let settled = false;
    let mainSucceeded = false;
    const finish = (data) => {
      if (settled) return;
      settled = true;
      resolve(data);
    };
    const onError = () => {
      if (!mainSucceeded) finish({ hasSSL: false });
    };

    const servername = net.isIP(hostname) ? undefined : hostname;
    const socket = tls.connect(
      {
        host: connectIp,
        port,
        servername,
        rejectUnauthorized: false,
        ciphers: "DEFAULT@SECLEVEL=0",
        signal,
        minVersion: "TLSv1",
      },
      async () => {
        mainSucceeded = true;
        socket.setTimeout(0); // Отключаем таймаут, мы уже получили сертификат
        const cert = socket.getPeerCertificate();
        if (!cert || !cert.valid_to) {
          socket.end();
          return finish({ hasSSL: false });
        }

        const verifyError = socket.authorizationError || null;
        const valid = verifyError === null;
        const daysLeft = Math.floor(
          (new Date(cert.valid_to) - Date.now()) / 86400000,
        );
        const tlsVersion = socket.getProtocol();

        socket.end();

        let supportsOldTls = false;
        try {
          supportsOldTls = await checkOldTls(connectIp, port, hostname, signal);
        } catch (e) {}

        finish({
          hasSSL: true,
          valid,
          verifyError,
          daysLeft,
          validTo: cert.valid_to,
          validToISO: (() => {
            if (!cert.valid_to) return null;
            const d = new Date(cert.valid_to);
            return Number.isNaN(d.getTime()) ? null : d.toISOString();
          })(),
          issuer: cert.issuer?.O || cert.issuer?.CN || "неизвестен",
          tlsVersion,
          supportsOldTls,
        });
      },
    );

    socket.on("error", onError);
    socket.setTimeout(5000, () => {
      socket.destroy();
      finish({ hasSSL: false });
    });
  });
}

// Проверяет HTTP-заголовки безопасности.
// Сначала пробует HTTPS, при ошибке — HTTP (для сайтов без SSL).
// connectIp — IP для подключения, hostname — для SNI и Host-заголовка.
function checkHeaders(connectIp, port, hostname, retries = 1, signal) {
  return new Promise((resolve) => {
    if (!port) return resolve({ error: true });
    if (signal?.aborted) return resolve({ error: true });

    const servername = net.isIP(hostname) ? undefined : hostname;
    let settled = false;
    const resolveOnce = (data) => {
      if (settled) return;
      settled = true;
      resolve(data);
    };

    const attempt = (attemptsLeft) => {
      let failing = false;
      const tryHttp = (callback) => {
        const req = http.get(
          {
            host: connectIp,
            port,
            headers: { Host: hostname, "User-Agent": "CyberCheck/1.2" },
            timeout: 5000,
            signal,
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
            headers: { Host: hostname, "User-Agent": "CyberCheck/1.2" },
            timeout: 5000,
            signal,
          },
          (res) => {
            resolveOnce(parseHeaders(res.headers, "HTTPS"));
            res.destroy();
          },
        );

        const onFail = () => {
          if (settled || failing) return;
          if (signal?.aborted) return resolveOnce({ error: true });
          failing = true;
          tryHttp(() => {
            if (settled) return;
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
