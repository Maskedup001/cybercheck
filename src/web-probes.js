const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const pkg = require("../package.json");
const {
  parseSetCookie,
  detectWaf,
  detectCms,
} = require("./header-analysis");
const { SENSITIVE_FILE_PATHS } = require("./file-paths");

const UA = `CyberCheck/${pkg.version}`;
const DEFAULT_TIMEOUT_MS = 2000;
const DEFAULT_MAX_BODY = 65536;

const SECURITY_TXT_PATH = "/.well-known/security.txt";
const SECURITY_TXT_MAX_BODY = 8192;

// Значение заголовка строкой (первое из списка) или null.
function headerText(headers, name) {
  if (!headers || typeof headers !== "object") return null;
  const raw = headers[name];
  if (raw === undefined || raw === null) return null;
  const text = Array.isArray(raw) ? raw[0] : raw;
  const trimmed = String(text).trim();
  return trimmed === "" ? null : trimmed;
}

// Host без порта только для стандартных портов, иначе браузер/сервер
// должны видеть hostname:port.
function hostHeaderFor(hostname, port) {
  return port === 80 || port === 443 ? hostname : `${hostname}:${port}`;
}

// Список протоколов для попыток. Для 443 сначала HTTPS (часто TLS не
// подтверждён checkSSL), при сетевой/TLS-ошибке — HTTP. Для остальных
// портов решает уже проверенный hasTls.
function protocolsFor(port, hasTls) {
  if (hasTls) return ["HTTPS"];
  if (port === 80) return ["HTTP"];
  if (port === 443) return ["HTTPS", "HTTP"];
  if (port === 8080) return ["HTTP"];
  return ["HTTP"];
}

// Ошибка сети — это данные, а не исключение: все проверки должны
// возвращать частичный отчёт, даже если соединение не состоялось.
function networkError(protocol, err) {
  let code = null;
  if (typeof err === "string") {
    code = err;
  } else if (err && typeof err === "object") {
    code = err.code || err.message;
  }

  return {
    status: null,
    headers: {},
    body: "",
    protocol,
    error: code ? String(code) : "REQUEST_FAILED",
  };
}

// header-analysis всегда возвращает объект, даже когда ничего не нашёл:
// { name: null, evidence: [] }. Наружу для "не найдено" отдаём null, чтобы
// отчёт не содержал пустых объектов.
function normalizeDetection(result) {
  if (!result || !result.name) return null;
  return result;
}

// Set-Cookie в Node приходит массивом; parseSetCookie работает с одной
// строкой, поэтому разворачиваем аккуратно и не роняем фингерпринт на
// неожиданном значении.
function cookiesFromHeaders(headers) {
  const raw = headers && headers["set-cookie"];
  if (!raw) return [];

  const values = Array.isArray(raw) ? raw : [raw];
  const cookies = [];

  for (const value of values) {
    if (typeof value !== "string") continue;
    try {
      const parsed = parseSetCookie(value);
      if (Array.isArray(parsed)) cookies.push(...parsed);
    } catch {
      // Битый Set-Cookie не должен ломать фингерпринт.
    }
  }

  return cookies;
}

// Единая низкоуровневая точка HTTP-запросов для веб-проб.
//
// ИНВАРИАНТ SSRF: TCP-соединение всегда идёт на уже проверенный connectIp.
// hostname используется только для заголовка Host и TLS SNI; DNS здесь не
// вызывается. Никаких fetch(hostname) или http.get(hostname).
//
// Возвращает Promise, который резолвится ровно один раз и никогда не
// отклоняется: сетевые ошибки приходят как { status: null, error }.
function request(options = {}) {
  const {
    method = "GET",
    path = "/",
    connectIp,
    port,
    hostname,
    hasTls = false,
    signal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    readBody = false,
    maxBody = DEFAULT_MAX_BODY,
    headers: extraHeaders = {},
  } = options;

  const protocols = protocolsFor(port, Boolean(hasTls));
  const hostHeader = hostHeaderFor(hostname, port);
  const timeout =
    Number.isFinite(timeoutMs) && timeoutMs >= 0
      ? timeoutMs
      : DEFAULT_TIMEOUT_MS;
  const maxBytes =
    Number.isFinite(maxBody) && maxBody >= 0
      ? Math.floor(maxBody)
      : DEFAULT_MAX_BODY;

  return new Promise((resolve) => {
    let settled = false;
    let currentReq = null;
    let currentProtocol = protocols[0];
    let timer = null;
    let abortHandler = null;

    // SSRF-инвариант: соединение возможно только с литеральным IP. Имя хоста
    // или undefined увели бы http.request в собственный DNS-резолв (а
    // undefined — на localhost), то есть обошли бы проверку адреса.
    if (typeof connectIp !== "string" || net.isIP(connectIp) === 0) {
      resolve(networkError(protocols[0], { code: "INVALID_CONNECT_IP" }));
      return;
    }

    // Заголовки и тело, уже полученные до таймаута: если страница ответила
    // медленно, статус и cf-ray всё равно нужны отчёту (PS-11).
    let partialStatus = null;
    let partialHeaders = {};
    let bodyChunks = [];
    let bodyTotal = 0;

    function clearTimer() {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    }

    function cleanup() {
      clearTimer();
      if (signal && abortHandler) {
        signal.removeEventListener("abort", abortHandler);
        abortHandler = null;
      }
    }

    function finish(result) {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    }

    function fail(protocol, err) {
      finish(networkError(protocol, err));
    }

    if (signal && signal.aborted) {
      fail(currentProtocol, { code: "ABORT_ERR" });
      return;
    }

    if (signal) {
      abortHandler = () => {
        const req = currentReq;
        currentReq = null;
        // Сначала фиксируем результат, затем разрушаем сокет: error от
        // destroy() уже не должен запускать fallback или второй resolve.
        fail(currentProtocol, { code: "ABORT_ERR" });
        if (req) req.destroy();
      };
      signal.addEventListener("abort", abortHandler, { once: true });
    }

    function attempt(index) {
      if (settled) return;
      if (signal && signal.aborted) {
        fail(currentProtocol, { code: "ABORT_ERR" });
        return;
      }

      const protocol = protocols[index];
      currentProtocol = protocol;
      const isHttps = protocol === "HTTPS";
      const lib = isHttps ? https : http;

      const requestHeaders = {
        ...extraHeaders,
        Host: hostHeader,
        "User-Agent": UA,
        // Без gzip: тело фингерпринта разбираем как обычный HTML/текст.
        "Accept-Encoding": "identity",
      };

      const requestOptions = {
        // Всегда connectIp, не hostname.
        host: connectIp,
        port,
        method,
        path,
        headers: requestHeaders,
        // Одноразовые сокеты: не держим keep-alive соединения после пробы.
        agent: false,
      };

      if (isHttps) {
        requestOptions.rejectUnauthorized = false;
        requestOptions.servername = net.isIP(hostname) ? undefined : hostname;
      }

      let req;
      try {
        req = lib.request(requestOptions);
      } catch (err) {
        fail(protocol, err);
        return;
      }

      currentReq = req;
      let gotResponse = false;
      let attemptEnded = false;

      function stopTimer() {
        if (timer !== null) {
          clearTimeout(timer);
          timer = null;
        }
      }

      timer = setTimeout(() => {
        timer = null;
        if (settled || attemptEnded) return;
        attemptEnded = true;
        const failedReq = currentReq;
        currentReq = null;

        // Таймаут до получения заголовков — такая же сетевая ошибка, как
        // отказ соединения: для 443 пробуем HTTP fallback.
        if (!gotResponse && index + 1 < protocols.length) {
          if (failedReq) failedReq.destroy();
          attempt(index + 1);
          return;
        }

        // Ответ уже пришёл, но тело не дочиталось за отведённое время:
        // отдаём статус/заголовки и то, что успели прочитать, с пометкой
        // ошибки. Иначе медленная страница теряла бы WAF и статус.
        if (gotResponse) {
          finish({
            status: partialStatus,
            headers: partialHeaders,
            body: readPartialBody(),
            protocol,
            error: "ETIMEDOUT",
          });
          if (failedReq) failedReq.destroy();
          return;
        }

        fail(protocol, { code: "ETIMEDOUT" });
        if (failedReq) failedReq.destroy();
      }, timeout);

      function readPartialBody() {
        return bodyTotal > 0
          ? Buffer.concat(bodyChunks, bodyTotal).toString("utf8")
          : "";
      }

      function handleRequestError(err) {
        if (settled || attemptEnded) return;
        attemptEnded = true;
        stopTimer();
        currentReq = null;

        // HTTP-статус — это уже ответ, fallback на другой протокол не нужен.
        if (!gotResponse && index + 1 < protocols.length) {
          attempt(index + 1);
          return;
        }
        fail(protocol, err);
      }

      req.on("error", handleRequestError);

      req.on("response", (res) => {
        if (settled || attemptEnded) {
          res.on("error", () => {});
          res.resume();
          return;
        }
        gotResponse = true;

        partialStatus =
          typeof res.statusCode === "number" ? res.statusCode : null;
        partialHeaders = res.headers || {};

        const status = partialStatus;
        const responseHeaders = partialHeaders;

        if (!readBody) {
          attemptEnded = true;
          stopTimer();
          res.on("error", () => {});
          res.resume();
          finish({ status, headers: responseHeaders, protocol, error: null });
          return;
        }

        bodyChunks = [];
        bodyTotal = 0;
        let bodyDone = false;

        function finishBody() {
          if (bodyDone) return;
          bodyDone = true;
          attemptEnded = true;
          stopTimer();
          finish({
            status,
            headers: responseHeaders,
            body: readPartialBody(),
            protocol,
            error: null,
          });
        }

        function failBody(err) {
          if (bodyDone || settled) return;
          bodyDone = true;
          attemptEnded = true;
          stopTimer();
          // Оборванное тело не отменяет уже полученные заголовки.
          finish({
            status,
            headers: responseHeaders,
            body: readPartialBody(),
            protocol,
            error: err && err.code ? String(err.code) : "ECONNRESET",
          });
        }

        res.on("data", (chunk) => {
          if (bodyDone || settled) return;
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          const remaining = maxBytes - bodyTotal;

          if (buf.length >= remaining) {
            if (remaining > 0) {
              bodyChunks.push(buf.subarray(0, remaining));
              bodyTotal += remaining;
            }
            finishBody();
            res.destroy();
            return;
          }

          bodyChunks.push(buf);
          bodyTotal += buf.length;
        });
        res.on("end", finishBody);
        res.on("error", failBody);
        res.on("aborted", () => failBody({ code: "ECONNRESET" }));
      });

      req.end();
    }

    attempt(0);
  });
}

// Проверка типовых файлов утечки. Только HEAD, 200 — единственный признак
// экспозиции. 403 — это WAF/запрет, не уязвимость; 404 и прочие статусы —
// просто данные. Ошибки не выбрасываются, а попадают в results[].error.
async function checkSensitiveFiles(
  connectIp,
  port,
  hostname,
  hasTls,
  signal,
  timeoutMs = DEFAULT_TIMEOUT_MS,
) {
  const responses = await Promise.all(
    SENSITIVE_FILE_PATHS.map(async (probePath) => {
      try {
        return await request({
          method: "HEAD",
          path: probePath,
          connectIp,
          port,
          hostname,
          hasTls,
          signal,
          timeoutMs,
        });
      } catch (err) {
        return networkError(null, err);
      }
    }),
  );

  const results = responses.map((response, index) => {
    const status = response.status;
    return {
      path: SENSITIVE_FILE_PATHS[index],
      status,
      exposed: status === 200,
      blocked: status === 403,
      error: response.error ?? null,
    };
  });

  return {
    port,
    protocol: responses[0] ? responses[0].protocol : null,
    results,
    exposed: results.filter((result) => result.exposed).map((result) => result.path),
    blocked: results.filter((result) => result.blocked).map((result) => result.path),
  };
}

// security.txt: статус 200 сам по себе ничего не доказывает — SPA и
// catch-all отдают 200 HTML на любой путь. Требуем text/plain и строку
// Contact: (RFC 9116), читая не больше 8 КБ.
async function checkSecurityTxt(
  connectIp,
  port,
  hostname,
  hasTls,
  signal,
  timeoutMs = DEFAULT_TIMEOUT_MS,
) {
  const response = await request({
    method: "GET",
    path: SECURITY_TXT_PATH,
    connectIp,
    port,
    hostname,
    hasTls,
    signal,
    timeoutMs,
    headers: { Accept: "text/plain" },
    readBody: true,
    maxBody: SECURITY_TXT_MAX_BODY,
  });

  const contentType = headerText(response.headers, "content-type");
  const body = typeof response.body === "string" ? response.body : "";
  // Без Content-Type не отбрасываем: часть серверов его не отдаёт.
  const plainText = contentType === null || /^text\/plain\b/i.test(contentType);
  const hasContact = /(?:^|\n)\s*Contact\s*:/i.test(body);
  const present = response.status === 200 && plainText && hasContact;

  return {
    path: SECURITY_TXT_PATH,
    status: response.status,
    present,
    blocked: response.status === 403,
    error: response.error,
  };
}

// Фингерпринт WAF/CMS. Тело читается не больше 64 КБ, чтобы не тянуть
// большие страницы. WAF определяется по заголовкам при любом статусе;
// CMS — только по успешному ответу: иначе заглушка ошибки/WAF даёт ложное
// «CMS не обнаружена» либо случайное совпадение в тексте ошибки.
async function checkFingerprint(
  connectIp,
  port,
  hostname,
  hasTls,
  signal,
  timeoutMs = DEFAULT_TIMEOUT_MS,
) {
  const response = await request({
    method: "GET",
    path: "/",
    connectIp,
    port,
    hostname,
    hasTls,
    signal,
    timeoutMs,
    headers: { Accept: "text/html" },
    readBody: true,
    maxBody: DEFAULT_MAX_BODY,
  });

  const headers = response.headers || {};
  const body = typeof response.body === "string" ? response.body : "";
  const cookies = cookiesFromHeaders(headers);

  let waf = null;
  try {
    waf = normalizeDetection(detectWaf(headers, cookies));
  } catch {
    waf = null;
  }

  let cms = null;
  if (response.status === 200 && body.length > 0) {
    try {
      cms = normalizeDetection(detectCms(body, headers, cookies));
    } catch {
      cms = null;
    }
  }

  return {
    waf,
    cms,
    server: headerText(headers, "server"),
    status: response.status,
    error: response.error,
    bodyBytes: Buffer.byteLength(body, "utf8"),
  };
}

module.exports = {
  request,
  checkSensitiveFiles,
  checkSecurityTxt,
  checkFingerprint,
};
