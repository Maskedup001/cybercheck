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

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
const BOT_UA = `CyberCheck/${pkg.version}`;

const RETRY_DELAY_MS = 1000;
const MIN_ATTEMPT_MS = 50;
const MAX_REDIRECTS = 3;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// Тело читается только ради CSP в <meta http-equiv>: заголовки уже описывают
// ответ, поэтому 64 КБ достаточно, а больший лимит тянул бы трафик впустую.
const MAX_HEADERS_BODY = 65536;

function normalizeHostname(hostname) {
  return String(hostname)
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
}

// Возвращает path + query только для того же origin.
// Внешние хосты не преследуются.
function sameOriginPath(location, hostname, port, protocol) {
  if (typeof location !== "string" || !location.trim()) {
    return null;
  }

  const scheme = protocol === "HTTPS" ? "https:" : "http:";

  let target;

  try {
    const base = new URL(
      `${scheme}//${hostHeaderFor(hostname, port)}/`
    );

    target = new URL(location, base);
  } catch {
    return null;
  }

  if (
    target.protocol !== scheme ||
    target.username ||
    target.password
  ) {
    return null;
  }

  const targetPort = target.port
    ? Number(target.port)
    : target.protocol === "https:"
      ? 443
      : 80;

  if (
    normalizeHostname(target.hostname) !== normalizeHostname(hostname) ||
    targetPort !== Number(port)
  ) {
    return null;
  }

  return `${target.pathname || "/"}${target.search}`;
}

// Проверяет HTTP-заголовки безопасности.
// connectIp — заранее проверенный литеральный IP.
// hostname используется для Host и SNI.
// Бюджет всех запросов и redirect-хопов общий.
function checkHeaders(
  connectIp,
  port,
  hostname,
  retries = 1,
  signal,
  hasTls = true,
  timeoutMs = 5000,
  deadline = null,
  ua = BROWSER_UA,
) {
  if (!isLiteralIp(connectIp)) {
    return Promise.resolve({ error: true });
  }

  const stage = stageDeadline(timeoutMs, deadline);

  return new Promise((resolve) => {
    if (!port || signal?.aborted) {
      return resolve({ error: true });
    }

    const servername = net.isIP(hostname)
      ? undefined
      : hostname;

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

    const attempt = (
      attemptsLeft,
      path = "/",
      redirectsLeft = MAX_REDIRECTS,
      forcedProtocol = null,
    ) => {
      if (settled) return;

      if (
        signal?.aborted ||
        timeoutFor(timeoutMs, stage) < MIN_ATTEMPT_MS
      ) {
        return resolveOnce({ error: true });
      }

      let retried = false;
      let failing = false;

      // Заголовки и тело уже полученного ответа. Нужны, чтобы таймаут на
      // теле не стирал результат: статус и заголовки — основная часть
      // отчёта, тело — только дополнительный источник CSP.
      let gotHeaders = false;
      let responseDone = false;
      let responseStatus = null;
      let responseHeaders = {};
      let responseRawHeaders = [];
      let responseProtocol = null;
      let responseChunks = [];
      let responseTotal = 0;

      const readResponseBody = () =>
        Buffer.concat(responseChunks, responseTotal).toString("utf8");

      const finishResponse = () => {
        if (responseDone) return;
        responseDone = true;

        try {
          resolveOnce(
            parseHeaders(
              responseHeaders,
              responseProtocol,
              responseStatus,
              responseRawHeaders,
              readResponseBody()
            )
          );
        } catch {
          resolveOnce({ error: true });
        }
      };

      const retryOrFail = () => {
        if (settled || retried) return;

        retried = true;

        if (signal?.aborted) {
          return resolveOnce({ error: true });
        }

        const retryFits = hasBudget(
          stage,
          RETRY_DELAY_MS + MIN_ATTEMPT_MS
        );

        if (attemptsLeft > 0 && retryFits) {
          retryTimer = setTimeout(() => {
            retryTimer = null;

            attempt(
              attemptsLeft - 1,
              path,
              redirectsLeft,
              forcedProtocol
            );
          }, RETRY_DELAY_MS);
        } else {
          resolveOnce({ error: true });
        }
      };

      const handleResponse = (res, protocol) => {
        const status =
          typeof res.statusCode === "number"
            ? res.statusCode
            : null;

        const location = res.headers?.location;

        const nextPath =
          REDIRECT_STATUSES.has(status) && redirectsLeft > 0
            ? sameOriginPath(
                location,
                hostname,
                port,
                protocol
              )
            : null;

        if (nextPath) {
          // Промежуточный редирект не участвует в оценке.
          // Тело ответа отбрасывается.
          res.on("error", () => {});
          res.resume();

          attempt(
            attemptsLeft,
            nextPath,
            redirectsLeft - 1,
            protocol
          );

          return;
        }

        gotHeaders = true;
        responseStatus = status;
        responseHeaders = res.headers || {};
        responseRawHeaders = Array.isArray(res.rawHeaders) ? res.rawHeaders : [];
        responseProtocol = protocol;

        // CSP может прийти только в <meta>, поэтому тело дочитывается до
        // конца (но не больше лимита). Любая ошибка чтения не отменяет уже
        // полученные заголовки — результат отдаётся finishResponse().
        res.on("data", (chunk) => {
          if (responseDone) return;

          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          const remaining = MAX_HEADERS_BODY - responseTotal;
          if (remaining <= 0) return;

          if (buf.length >= remaining) {
            responseChunks.push(buf.subarray(0, remaining));
            responseTotal += remaining;
            // Лимит достигнут: дальше читать незачем, но заголовки и
            // прочитанное тело уже есть.
            finishResponse();
            res.destroy();
            return;
          }

          responseChunks.push(buf);
          responseTotal += buf.length;
        });
        res.on("end", finishResponse);
        res.on("error", finishResponse);
        res.on("aborted", finishResponse);
      };

      const requestWithProtocol = (protocol) => {
        const requestTimeout = timeoutFor(
          timeoutMs,
          stage
        );

        if (requestTimeout < MIN_ATTEMPT_MS) {
          return retryOrFail();
        }

        const options = {
          host: connectIp,
          port,
          path,
          agent: false,
          headers: {
            Host: hostHeader,
            "User-Agent": ua,
          },
          timeout: requestTimeout,
          signal,
        };

        const isHttps = protocol === "HTTPS";

        if (isHttps) {
          options.servername = servername;
          options.rejectUnauthorized = false;
        }

        const client = isHttps ? https : http;

        const req = client.get(options, (res) => {
          handleResponse(res, protocol);
        });

        const onFail = () => {
          if (settled || failing) return;

          failing = true;

          // Заголовки уже получены: тело могло оборваться или не дочитаться
          // за остаток бюджета, но отчёт по заголовкам всё равно нужен.
          if (gotHeaders) {
            finishResponse();
            return;
          }

          // HTTPS -> HTTP fallback допустим только
          // для первоначального запроса.
          if (
            isHttps &&
            !forcedProtocol &&
            !signal?.aborted
          ) {
            requestWithProtocol("HTTP");
          } else {
            retryOrFail();
          }
        };

        req.on("error", onFail);

        req.on("timeout", () => {
          req.destroy();
          onFail();
        });
      };

      const protocol =
        forcedProtocol ||
        (hasTls || port === 443 ? "HTTPS" : "HTTP");

      requestWithProtocol(protocol);
    };

    attempt(retries);
  });
}

// Приводит заголовки к единому формату.
// status и location относятся к конечному ответу,
// если same-origin редирект удалось выполнить.
// rawHeaders — res.rawHeaders (несколько CSP/XFO — несколько политик),
// body — прочитанное тело GET / для CSP в <meta>.
function parseHeaders(h, protocol, status = null, rawHeaders = [], body = "") {
  const cookies = parseSetCookie(h["set-cookie"]);
  const security = analyzeSecurityHeaders(h, rawHeaders, body);

  return {
    protocol,
    status,
    location: sanitizeHeaderText(h.location),
    server: sanitizeHeaderText(h["server"]),
    ...security,
    cookies,
    cookieSummary: summarizeCookies(cookies),
  };
}

module.exports = {
  checkHeaders,
  parseHeaders,
  BROWSER_UA,
  BOT_UA,
  sameOriginPath,
};