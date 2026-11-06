const net = require("node:net");
const https = require("node:https");
const http = require("node:http");
const pkg = require("../../package.json");
const {
  parseSetCookie,
  summarizeCookies,
  analyzeSecurityHeaders,
  sanitizeHeaderText,
} = require("./header-analysis");
const {
  isLiteralIp,
  hostHeaderFor,
  stageDeadline,
  timeoutFor,
  hasBudget,
} = require("../utils/scan-helpers");

const UA = `CyberCheck/${pkg.version}`;

// Пауза перед повтором заголовков входит в бюджет этапа.
const RETRY_DELAY_MS = 1000;

// Попытка короче 50 мс не успевает даже на TCP-хендшейк.
const MIN_ATTEMPT_MS = 50;

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
    // Для IPv6 Host обязан быть в скобках; для нестандартного порта — с :port.
    const hostHeader = hostHeaderFor(hostname, port);

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
          RETRY_DELAY_MS + MIN_ATTEMPT_MS,
        );
        if (attemptsLeft > 0 && retryFits) {
          // Пауза перед повтором входит в тот же бюджет этапа.
          retryTimer = setTimeout(() => {
            retryTimer = null;
            attempt(attemptsLeft - 1);
          }, RETRY_DELAY_MS);
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
            // Одноразовый сокет: глобальный keep-alive agent иначе держал бы
            // соединения со всеми просканированными хостами до таймаута.
            agent: false,
            // Используем hostHeader и актуальную версию UA
            headers: { Host: hostHeader, "User-Agent": UA },
            timeout: requestTimeout,
            signal,
          },
          (res) => {
            try {
              resolveOnce(parseHeaders(res.headers, "HTTP"));
            } catch {
              // Недоверенные заголовки не должны ронять процесс через
              // uncaughtException: любой сбой разбора — это ошибка проверки.
              resolveOnce({ error: true });
            }
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
            agent: false,
            // Используем hostHeader и актуальную версию UA
            headers: { Host: hostHeader, "User-Agent": UA },
            timeout: requestTimeout,
            signal,
          },
          (res) => {
            try {
              resolveOnce(parseHeaders(res.headers, "HTTPS"));
            } catch {
              resolveOnce({ error: true });
            }
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

module.exports = { checkHeaders, parseHeaders };
