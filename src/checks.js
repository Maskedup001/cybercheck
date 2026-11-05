const pkg = require("../package.json");
const UA = `CyberCheck/${pkg.version}`;
const net = require("net");
const tls = require("tls");
const https = require("https");
const http = require("http");
const {
  parseSetCookie,
  summarizeCookies,
  analyzeSecurityHeaders,
  sanitizeHeaderText,
} = require("./header-analysis");
const {
  isLiteralIp,
  stageDeadline,
  timeoutFor,
  hasBudget,
} = require("./scan-helpers");

// Паузы между попытками. Они входят в бюджет этапа, а не добавляются к нему.
const RETRY_DELAY_MS = 500;
const HEADERS_RETRY_DELAY_MS = 1000;

// Проверка старых TLS — отдельное соединение. Если на неё осталось меньше
// секунды, результат всё равно недостоверен, а бюджет этапа будет съеден.
const OLD_TLS_TIMEOUT_MS = 3000;
const OLD_TLS_MIN_MS = 1000;

// Попытка короче 50 мс не успевает даже на TCP-хендшейк: считаем, что
// времени не осталось, и не открываем сокет.
const MIN_ATTEMPT_MS = 50;

// Проверяет, открыт ли указанный порт.
// connectIp — уже проверенный IP-адрес (не hostname!), это важно для SSRF-защиты.
// timeoutMs — бюджет всего этапа (все попытки вместе), deadline — дедлайн
// скана. Если соединение установилось — порт открыт. Таймаут или ошибка —
// порт закрыт.
function checkPort(
  connectIp,
  port,
  timeoutMs = 3000,
  retries = 1,
  signal,
  deadline = null,
) {
  if (!isLiteralIp(connectIp)) {
    return Promise.resolve({ port, status: "closed" });
  }

  const stage = stageDeadline(timeoutMs, deadline);

  return new Promise((resolve) => {
    // Таймер ретрая храним, чтобы снять его при завершении: иначе после
    // отмены или дедлайна он мог бы запустить лишнюю попытку и подержать
    // процесс.
    let retryTimer = null;
    const settle = (result) => {
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      resolve(result);
    };

    const attempt = (attemptsLeft) => {
      if (signal?.aborted) return settle({ port, status: "closed" });

      // Остаток бюджета этапа считаем перед каждой попыткой: ретрай не
      // должен получать свежие 3 секунды после того, как первая попытка
      // уже израсходовала бюджет.
      const attemptTimeout = timeoutFor(timeoutMs, stage);
      if (attemptTimeout < MIN_ATTEMPT_MS) {
        return settle({ port, status: "closed" });
      }

      const socket = new net.Socket();
      let status = "closed";

      const onAbort = () => {
        socket.destroy();
        settle({ port, status: "closed" });
      };
      if (signal) signal.addEventListener("abort", onAbort, { once: true });

      socket.setTimeout(attemptTimeout);
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
        if (signal) signal.removeEventListener("abort", onAbort);
        if (signal?.aborted) return;

        // Ретрай имеет смысл только для быстрого сбоя (отказ, сброс) и
        // только если на него вместе с паузой остался бюджет.
        const retryFits = hasBudget(
          stage,
          RETRY_DELAY_MS + MIN_ATTEMPT_MS,
        );
        if (status === "closed" && attemptsLeft > 0 && retryFits) {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            attempt(attemptsLeft - 1);
          }, RETRY_DELAY_MS);
        } else {
          settle({ port, status });
        }
      });
      socket.connect(port, connectIp);
    };
    attempt(retries);
  });
}

// Проверяет, принимает ли сервер устаревшие версии TLS (1.0 / 1.1).
// timeoutMs — остаток бюджета этапа TLS, а не фиксированные 3 секунды.
function checkOldTls(connectIp, port, hostname, signal, timeoutMs) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve(false);

    // timeoutMs уже ограничен остатком бюджета этапа TLS.
    const budget = Number.isFinite(timeoutMs) ? timeoutMs : OLD_TLS_TIMEOUT_MS;
    if (budget < MIN_ATTEMPT_MS) return resolve(false);

    const servername = net.isIP(hostname) ? undefined : hostname;
    const socket = tls.connect(
      {
        host: connectIp,
        port,
        servername,
        rejectUnauthorized: false,
        minVersion: "TLSv1",
        maxVersion: "TLSv1.1",
        ciphers: "ALL:@SECLEVEL=0", // Максимальная совместимость для детекта старых шифров
        signal,
      },
      () => {
        resolve(true); // Если подключился — значит, поддерживает старые TLS
        socket.destroy();
      },
    );
    socket.on("error", () => resolve(false));
    socket.setTimeout(budget, () => {
      socket.destroy();
      resolve(false);
    });
  });
}

// Проверяет SSL-сертификат на указанном порту.
// connectIp — IP для подключения, hostname — для SNI (только если это домен, не IP).
// rejectUnauthorized: false нужен, чтобы ПРОЧИТАТЬ информацию о невалидных
// сертификатах (просроченных, самоподписанных) — иначе соединение оборвётся.
async function checkSSL(
  connectIp,
  port,
  hostname,
  signal,
  retries = 1,
  timeoutMs = 5000,
  deadline = null,
) {
  if (!port) return { hasSSL: false };
  if (!isLiteralIp(connectIp)) {
    return { hasSSL: false, error: "INVALID_CONNECT_IP" };
  }

  const stage = stageDeadline(timeoutMs, deadline);

  return new Promise((resolve) => {
    let retryTimer = null;
    const settle = (data) => {
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      resolve(data);
    };

    const attempt = (attemptsLeft) => {
      const attemptTimeout = timeoutFor(timeoutMs, stage);
      if (attemptTimeout < MIN_ATTEMPT_MS) {
        return settle({ hasSSL: false, error: "HANDSHAKE_FAILED" });
      }

      let settled = false;
      let mainSucceeded = false;
      let attemptFailed = false;
      const finish = (data) => {
        if (settled) return;
        settled = true;
        settle(data);
      };
      const onError = () => {
        if (mainSucceeded || attemptFailed) return;
        attemptFailed = true;

        if (signal?.aborted) {
          return finish({ hasSSL: false, error: "HANDSHAKE_FAILED" });
        }

        const retryFits = hasBudget(
          stage,
          RETRY_DELAY_MS + MIN_ATTEMPT_MS,
        );
        if (attemptsLeft > 0 && retryFits) {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            attempt(attemptsLeft - 1);
          }, RETRY_DELAY_MS);
        } else {
          finish({ hasSSL: false, error: "HANDSHAKE_FAILED" });
        }
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
          socket.setTimeout(0);
          try {
            const cert = socket.getPeerCertificate();
            if (!cert || !cert.valid_to) {
              socket.end();
              // TLS поднялся, но сертификат не разобран: это ошибка проверки,
              // а не «SSL нет». Иначе отчёт печатал бы no-ssl и потолок 30.
              return finish({
                hasSSL: false,
                error: "CERT_PARSE_FAILED",
              });
            }

            const verifyError = socket.authorizationError || null;
            const valid = verifyError === null;
            const daysLeft = Math.floor(
              (new Date(cert.valid_to) - Date.now()) / 86400000,
            );
            const tlsVersion = socket.getProtocol();
            socket.end();

            // Старые протоколы проверяются только на остаток бюджета этапа:
            // иначе успешный хендшейк добавлял к этапу фиксированные 3 с.
            let supportsOldTls = false;
            if (hasBudget(stage, OLD_TLS_MIN_MS)) {
              try {
                supportsOldTls = await checkOldTls(
                  connectIp,
                  port,
                  hostname,
                  signal,
                  timeoutFor(OLD_TLS_TIMEOUT_MS, stage),
                );
              } catch (e) {}
            }

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
          } catch (e) {
            socket.end();
            finish({ hasSSL: false, error: "CERT_PARSE_FAILED" });
          }
        },
      );

      socket.on("error", onError);
      socket.setTimeout(attemptTimeout, () => {
        socket.destroy();
        onError();
      });
    };
    attempt(retries);
  });
}

// Проверяет HTTP-заголовки безопасности.
// hasTls — результат checkSSL по этому же порту: если TLS не поднялся,
// HTTPS-попытка заведомо провалится и только съест таймаут.
// connectIp — IP для подключения, hostname — для SNI и Host-заголовка.
// timeoutMs — бюджет всего этапа, deadline — дедлайн скана.
function checkHeaders(
  connectIp,
  port,
  hostname,
  retries = 1,
  signal,
  hasTls = true,
  timeoutMs = 5000,
  deadline = null,
) {
  if (!isLiteralIp(connectIp)) {
    return Promise.resolve({ error: true });
  }

  const stage = stageDeadline(timeoutMs, deadline);

  return new Promise((resolve) => {
    if (!port) return resolve({ error: true });
    if (signal?.aborted) return resolve({ error: true });

    const servername = net.isIP(hostname) ? undefined : hostname;
    // Добавляем порт в Host для нестандартных портов (например, 8080)
    const hostHeader =
      port === 80 || port === 443 ? hostname : `${hostname}:${port}`;

    let settled = false;
    let retryTimer = null;
    const resolveOnce = (data) => {
      if (settled) return;
      settled = true;
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      resolve(data);
    };

    const attempt = (attemptsLeft) => {
      if (timeoutFor(timeoutMs, stage) < MIN_ATTEMPT_MS) {
        return resolveOnce({ error: true });
      }

      let failing = false;
      let retried = false;

      const retryOrFail = () => {
        if (settled || retried) return;
        retried = true;
        if (signal?.aborted) return resolveOnce({ error: true });

        const retryFits = hasBudget(
          stage,
          HEADERS_RETRY_DELAY_MS + MIN_ATTEMPT_MS,
        );
        if (attemptsLeft > 0 && retryFits) {
          // Пауза перед повтором входит в тот же бюджет этапа.
          retryTimer = setTimeout(() => {
            retryTimer = null;
            attempt(attemptsLeft - 1);
          }, HEADERS_RETRY_DELAY_MS);
        } else {
          resolveOnce({ error: true });
        }
      };

      const tryHttp = () => {
        // Таймаут считается перед каждым запросом: fallback с HTTPS на HTTP
        // не должен получать полный бюджет этапа второй раз.
        const requestTimeout = timeoutFor(timeoutMs, stage);
        if (requestTimeout < MIN_ATTEMPT_MS) return retryOrFail();

        const req = http.get(
          {
            host: connectIp,
            port,
            // Используем hostHeader и актуальную версию UA
            headers: { Host: hostHeader, "User-Agent": UA },
            timeout: requestTimeout,
            signal,
          },
          (res) => {
            resolveOnce(parseHeaders(res.headers, "HTTP"));
            res.destroy();
          },
        );
        let failed = false;
        const done = () => {
          if (failed || settled) return;
          failed = true;
          retryOrFail();
        };
        req.on("error", done);
        req.on("timeout", () => {
          req.destroy();
          done();
        });
      };

      const tryHttps = () => {
        const requestTimeout = timeoutFor(timeoutMs, stage);
        if (requestTimeout < MIN_ATTEMPT_MS) return retryOrFail();

        const req = https.get(
          {
            host: connectIp,
            port,
            servername,
            rejectUnauthorized: false,
            // Используем hostHeader и актуальную версию UA
            headers: { Host: hostHeader, "User-Agent": UA },
            timeout: requestTimeout,
            signal,
          },
          (res) => {
            resolveOnce(parseHeaders(res.headers, "HTTPS"));
            res.destroy();
          },
        );

        const onFail = () => {
          if (settled || failing) return;
          failing = true;
          tryHttp();
        };

        req.on("error", onFail);
        req.on("timeout", () => {
          req.destroy();
          onFail();
        });
      };

      // Пробуем HTTPS на 443, даже если checkSSL не успел подтвердить TLS
      if (hasTls || port === 443) {
        tryHttps();
      } else {
        tryHttp();
      }
    };

    attempt(retries);
  });
}

// Приводит заголовки к единому формату для фронтенда.
// protocol — 'HTTP' или 'HTTPS', чтобы клиент видел реальную схему.
// server нормализован в строку или null: «не указан» — это решение UI,
// а не данные API (иначе у headers и fingerprint разные контракты).
function parseHeaders(h, protocol) {
  const cookies = parseSetCookie(h["set-cookie"]);
  const security = analyzeSecurityHeaders(h);

  return {
    protocol,
    server: sanitizeHeaderText(h["server"]),
    ...security,
    cookies,
    cookieSummary: summarizeCookies(cookies),
  };
}

module.exports = { checkPort, checkSSL, checkHeaders, parseHeaders };
