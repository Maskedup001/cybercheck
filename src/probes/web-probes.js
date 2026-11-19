const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const {
  parseSetCookie,
  detectWaf,
  detectCms,
  sanitizeHeaderText,
} = require("./header-analysis");
const { SENSITIVE_FILE_PATHS } = require("../core/file-paths");
const { hostHeaderFor } = require("../utils/scan-helpers");
// У проб тот же браузерный User-Agent, что и у проверки заголовков: иначе
// файлы, security.txt и фингерпринт запрашивались бы отдельным, предсказуемым
// «CyberCheck/…», и цель могла бы отдавать им другой ответ.
const { BROWSER_UA, sameOriginPath } = require("./http-headers");

const UA = BROWSER_UA;
const DEFAULT_TIMEOUT_MS = 2000;
const DEFAULT_MAX_BODY = 65536;
// Редирект преследуется только в пределах того же origin и не больше трёх раз:
// чужой хост потребовал бы нового резолва и проверки адреса (SSRF), а проба
// соединяется с уже проверенным литеральным IP.
const MAX_PATH_REDIRECTS = 3;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

const SECURITY_TXT_PATH = "/.well-known/security.txt";
// security.txt — однострочные RFC 9116-записи; 32 КБ хватает с запасом.
// Меньший лимит обрезал файл до строки Contact и давал ложное «некорректный».
const SECURITY_TXT_MAX_BODY = 32768;

// Значение заголовка строкой (первое из списка) или null.
function headerText(headers, name) {
  if (!headers || typeof headers !== "object") return null;
  const raw = headers[name];
  if (raw === undefined || raw === null) return null;
  const text = Array.isArray(raw) ? raw[0] : raw;
  const trimmed = String(text).trim();
  return trimmed === "" ? null : trimmed;
}

// Host без порта только для стандартных портов; IPv6 — в квадратных скобках.
// Сама логика живёт в scan-helpers, чтобы HTTP-заголовки и веб-пробы не
// разошлись в формате Host.

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
    // Путь и остаток переходов живут на всю пробу: редирект выполняется тем же
    // соединением (тот же connectIp/порт), меняется только путь из Location.
    let requestPath = path;
    let redirectsLeft = MAX_PATH_REDIRECTS;
    // Один бюджет на все переходы: иначе три хопа умножали бы таймаут на
    // четыре и медленная цель держала бы сокет вчетверо дольше.
    const requestDeadline = Date.now() + timeout;

    // SSRF-инвариант: соединение возможно только с литеральным IP. Имя хоста
    // или undefined увели бы http.request в собственный DNS-резолв (а
    // undefined — на localhost), то есть обошли бы проверку адреса.
    if (typeof connectIp !== "string" || net.isIP(connectIp) === 0) {
      resolve(networkError(protocols[0], { code: "INVALID_CONNECT_IP" }));
      return;
    }

    // Заголовки и тело, уже полученные до таймаута: если страница ответила
    // медленно, статус и cf-ray всё равно нужны отчёту.
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
        path: requestPath,
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

      const attemptTimeout = Math.max(0, requestDeadline - Date.now());
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
            bodyBuffer: Buffer.concat(bodyChunks, bodyTotal),
            protocol,
            error: "ETIMEDOUT",
            truncated: false,
          });
          if (failedReq) failedReq.destroy();
          return;
        }

        fail(protocol, { code: "ETIMEDOUT" });
        if (failedReq) failedReq.destroy();
      }, attemptTimeout);

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

        // same-origin редирект: повторяем запрос тем же connectIp и портом,
        // подставляя только путь из Location. Переход на другой origin не
        // выполняем — он требует нового резолва и проверки адреса, иначе
        // проба стала бы SSRF-вектором.
        const nextPath =
          REDIRECT_STATUSES.has(status) && redirectsLeft > 0
            ? sameOriginPath(responseHeaders.location, hostname, port, protocol)
            : null;

        if (nextPath) {
          redirectsLeft -= 1;
          attemptEnded = true;
          stopTimer();
          currentReq = null;
          res.on("error", () => {});
          res.resume();
          req.destroy();
          requestPath = nextPath;
          attempt(protocols.indexOf(protocol));
          return;
        }

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

        function finishBody(truncated = false) {
          if (bodyDone) return;
          bodyDone = true;
          attemptEnded = true;
          stopTimer();
          finish({
            status,
            headers: responseHeaders,
            body: readPartialBody(),
            // Байты тела нужны пробам файлов утечки: только сигнатура
            // содержимого доказывает, что 200 — это файл, а не заглушка.
            bodyBuffer: Buffer.concat(bodyChunks, bodyTotal),
            protocol,
            error: null,
            // true — упёрлись в maxBytes, дальше тело не читалось:
            // отсутствие строки в таком теле ничего не доказывает.
            truncated: Boolean(truncated),
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
            bodyBuffer: Buffer.concat(bodyChunks, bodyTotal),
            protocol,
            error: err && err.code ? String(err.code) : "ECONNRESET",
            truncated: false,
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
            finishBody(true);
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

// Сигнатуры содержимого для путей утечки. Список путей — общий
// (SENSITIVE_FILE_PATHS), а сигнатура привязана к пути через Map: порядок
// путей можно менять, не переставляя проверки.
//
// 200 от SPA/catch-all — это HTML-заглушка на любой путь, а не файл утечки.
// Поэтому экспозиция подтверждается только содержимым, а не статусом.
const DS_STORE_MAGIC = Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31]);
const FILE_SIGNATURES = new Map([
  // .env — строки KEY=VALUE; HTML/JSON так не начинаются.
  [
    "/.env",
    (buf) => /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(buf.toString("utf8", 0, 4096)),
  ],
  ["/.git/config", (buf) => /^\[core\]/m.test(buf.toString("utf8", 0, 4096))],
  // ZIP: 50 4B 03 04 (обычный), 50 4B 05 06 (пустой архив),
  // 50 4B 07 08 (spanned).
  [
    "/backup.zip",
    (buf) =>
      buf.length >= 4 &&
      buf[0] === 0x50 &&
      buf[1] === 0x4b &&
      (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07),
  ],
  // .DS_Store начинается с магических байтов формата, а не с текста.
  [
    "/.DS_Store",
    (buf) => buf.length >= 8 && buf.subarray(0, 8).equals(DS_STORE_MAGIC),
  ],
]);

// Пробе читается только начало файла: для сигнатуры хватает 4 КБ, а
// выкачивать большие архивы проба не должна.
const MAX_PROBE_BODY = 4096;

// Проверка типовых файлов утечки. GET (а не HEAD) нужен, потому что 200
// сам по себе ничего не доказывает: решение принимается по сигнатуре тела.
// 403 — это WAF/запрет, не уязвимость; 200 без сигнатуры — «не проверено».
// Ошибки не выбрасываются, а попадают в results[].error.
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
          method: "GET",
          path: probePath,
          connectIp,
          port,
          hostname,
          hasTls,
          signal,
          timeoutMs,
          readBody: true,
          maxBody: MAX_PROBE_BODY,
        });
      } catch (err) {
        return networkError(null, err);
      }
    }),
  );

  const results = responses.map((response, index) => {
    const path = SENSITIVE_FILE_PATHS[index];
    const status = response.status;
    const body = Buffer.isBuffer(response.bodyBuffer)
      ? response.bodyBuffer
      : Buffer.alloc(0);

    const signature = FILE_SIGNATURES.get(path);
    const signatureOk =
      status === 200 &&
      !response.error &&
      body.length > 0 &&
      typeof signature === "function" &&
      signature(body);

    return {
      path,
      status,
      exposed: signatureOk,
      blocked: status === 403,
      // 200 без сигнатуры — это «не проверено», а не «открыто» и не
      // «закрыто»: баллы за путь не начисляются, находка не создаётся.
      error:
        response.error ??
        (status === 200 && !signatureOk ? "NO_SIGNATURE" : null),
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
// Contact: (RFC 9116), читая не больше 32 КБ.
//
// Обрезанное тело — отдельное состояние «не проверено»: отсутствие Contact
// в первых 32 КБ не доказывает, что файла нет.
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
  const truncated = response.truncated === true;
  // Без Content-Type не отбрасываем: часть серверов его не отдаёт.
  const plainText = contentType === null || /^text\/plain\b/i.test(contentType);
  const hasContact = /(?:^|\n)\s*Contact\s*:/i.test(body);
  const present = response.status === 200 && plainText && hasContact;

  // Contact не найден, но тело обрезано лимитом — сказать «файла нет» или
  // «файл некорректен» нельзя. Отдаём явную причину, чтобы scoring отличил
  // это от настоящего отсутствия.
  if (!present && response.status === 200 && truncated && !response.error) {
    return {
      path: SECURITY_TXT_PATH,
      status: response.status,
      present: false,
      blocked: false,
      error: "TRUNCATED",
      truncated: true,
    };
  }

  return {
    path: SECURITY_TXT_PATH,
    status: response.status,
    present,
    blocked: response.status === 403,
    error: response.error,
    truncated,
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
    server: sanitizeHeaderText(headerText(headers, "server")),
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
