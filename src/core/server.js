const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { checkPort } = require("../probes/ports");
const { checkSSL } = require("../probes/tls");
const { checkHeaders, BROWSER_UA, BOT_UA } = require("../probes/http-headers");
const { resolvePublicIps } = require("./net-guard");
const { readNodeEnv } = require("./config");
const { checkDnsSecurity } = require("../probes/dns-security");
const { ScanLimiter } = require("../utils/rate-limit");
const {
  parseTarget,
  normalizeHostname,
  rateKey,
  budgetLeft,
  clampTimeout,
  effectiveHasTls,
  tlsUnknownPort,
  isHtmlRequestPath,
  selectWebPorts,
  WEB_PORT_ORDER,
  buildReport,
} = require("../utils/scan-helpers");
const {
  checkSensitiveFiles,
  checkSecurityTxt,
  checkFingerprint,
} = require("../probes/web-probes");

// Общий бюджет одного скана. Клиент ждёт 65 с, поэтому 5 с остаются на
// сеть и передачу ответа.
const SCAN_BUDGET_MS = 60_000;
const DNS_BUDGET_MS = 5000;
const PORT_TIMEOUT_MS = 3000;
const TLS_TIMEOUT_MS = 5000;
const HEADERS_TIMEOUT_MS = 8000;
const DNS_SECURITY_TIMEOUT_MS = 3000;
const PROBE_TIMEOUT_MS = 2000;

// Таймауты и потолки HTTP-сервера. Держим их константами рядом: тест берёт
// ожидаемые значения отсюда и сравнивает с реальными свойствами server.
const SERVER_HEADERS_TIMEOUT_MS = 10_000;
const SERVER_REQUEST_TIMEOUT_MS = 15_000;
const SERVER_KEEP_ALIVE_TIMEOUT_MS = 5_000;
const SERVER_MAX_CONNECTIONS = 4096;
const SERVER_MAX_REQUESTS_PER_SOCKET = 100;
const MAX_SOCKETS_PER_IP = 64;

// Секрет для подписи токенов согласия. В продакшене должен быть задан явно
// и не совпадать с публичным dev-значением из .env.example: иначе токены
// согласия может подписать кто угодно.
const CONSENT_SECRET_PLACEHOLDER = "dev-secret-do-not-use-in-prod";
const NODE_ENV = readNodeEnv(process.env.NODE_ENV);
const IS_PRODUCTION = NODE_ENV === "production";

const CONSENT_SECRET =
  process.env.CONSENT_SECRET ||
  (IS_PRODUCTION ? null : CONSENT_SECRET_PLACEHOLDER);

if (
  IS_PRODUCTION &&
  (!CONSENT_SECRET ||
    CONSENT_SECRET === CONSENT_SECRET_PLACEHOLDER ||
    CONSENT_SECRET.length < 32)
) {
  console.error(
    "ОШИБКА: в production CONSENT_SECRET обязателен, не должен совпадать с " +
      "публичным dev-значением и должен быть не короче 32 символов.",
  );
  process.exit(1);
}

if (
  !process.env.CONSENT_SECRET &&
  NODE_ENV &&
  NODE_ENV !== "development"
) {
  console.warn(
    "ВНИМАНИЕ: CONSENT_SECRET не задан, токены согласия подписываются публичным dev-секретом.",
  );
}

const SCAN_PORTS = [80, 443, 22, 3306, 8080];

// Резолв с жёстким таймаутом и отменой. Гонка нужна потому, что DNS-модуль
// принимает таймаут, но не гарантирует, что ответит ровно через него.
async function resolveWithTimeout(hostname, ms = DNS_BUDGET_MS, signal) {
  let timer;
  let onAbort;
  try {
    const attempts = [
      resolvePublicIps(hostname, { timeoutMs: ms }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("DNS_TIMEOUT")), ms);
      }),
    ];

    if (signal) {
      attempts.push(
        new Promise((_, reject) => {
          if (signal.aborted) return reject(new Error("SCAN_ABORTED"));
          onAbort = () => reject(new Error("SCAN_ABORTED"));
          signal.addEventListener("abort", onAbort, { once: true });
        }),
      );
    }

    return await Promise.race(attempts);
  } finally {
    clearTimeout(timer);
    if (signal && onAbort) signal.removeEventListener("abort", onAbort);
  }
}

// Хелпер для ограничения времени выполнения скана.
// Поддерживает внешний сигнал отмены (если клиент оборвал соединение).
function withTimeout(factory, ms, externalSignal) {
  const controller = new AbortController();
  const signal = externalSignal
    ? AbortSignal.any([externalSignal, controller.signal])
    : controller.signal;

  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error("SCAN_TIMEOUT"));
    }, ms);
  });

  return Promise.race([
    Promise.resolve().then(() => factory(signal)),
    timeout,
  ]).finally(() => {
    clearTimeout(timer);
  });
}

function issueConsentToken() {
  const issuedAt = Date.now().toString();
  const mac = crypto
    .createHmac("sha256", CONSENT_SECRET)
    .update(issuedAt)
    .digest("base64url");
  return `${issuedAt}.${mac}`;
}

function verifyConsentToken(token) {
  if (typeof token !== "string" || token.length > 200) return false;
  const [issuedAtStr, mac] = token.split(".");
  if (!issuedAtStr || !mac) return false;

  const expectedMac = crypto
    .createHmac("sha256", CONSENT_SECRET)
    .update(issuedAtStr)
    .digest("base64url");
  const a = Buffer.from(mac);
  const b = Buffer.from(expectedMac);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  const issuedAt = Number(issuedAtStr);
  return Number.isFinite(issuedAt) && Date.now() - issuedAt <= 900_000; // 15 минут
}

// Определяет реальный IP клиента с учетом доверия к прокси.
// trustProxy — число реальных прокси перед приложением (0..10). Правый край
// X-Forwarded-For дописан ближайшим прокси, поэтому адрес клиента стоит на
// позиции length - trustProxy, а не всегда в конце: при двух прокси
// (Cloudflare + Render) прежний код ключевал лимит по адресу прокси и делал
// кулдаун общим для всех клиентов.
function clientIdentity(req, trustProxy) {
  const socketIp = req.socket && req.socket.remoteAddress;
  const socketKey = rateKey(socketIp);

  if (!trustProxy || trustProxy <= 0) {
    return { edgeKey: socketKey, clientKey: socketKey, rawIp: socketIp };
  }

  const forwarded = String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

  const index = forwarded.length - trustProxy;
  const candidate = index >= 0 ? forwarded[index] : socketIp;

  const clientKey = net.isIP(candidate) ? rateKey(candidate) : socketKey;

  return {
    // За прокси сокет — это сам прокси: лимит на edge иначе ограничивал бы
    // всех клиентов двумя одновременными сканами.
    edgeKey: clientKey,
    clientKey,
    rawIp: candidate,
  };
}

// Возвращает строковую сигнатуру полей безопасности для сравнения ответов
// при разных User-Agent (обнаружение клоакинга).
function securitySignature(headers) {
  if (!headers || headers.error) return null;
  return JSON.stringify([
    headers.status,
    headers.server,
    headers.hstsState,
    headers.cspState,
    headers.xframeState,
    headers.xcontentState,
    headers.referrerPolicyState,
    headers.permissionsPolicyState,
    headers.coopState,
    headers.corsWildcard,
    headers.cookieSummary,
  ]);
}

// Подтверждает, что порт 80 перенаправляет на HTTPS: только 3xx с https://
// в Location. Редирект на чужой хост защитой этого сайта не является:
// Location: https://evil.example/ раньше засчитывался как редирект на HTTPS.
function redirectsToHttps(headers, hostname) {
  if (!headers || headers.error) return false;

  if (
    typeof headers.status !== "number" ||
    headers.status < 300 ||
    headers.status >= 400
  ) {
    return false;
  }

  const location = headers.location || "";
  if (!/^https:/i.test(location)) return false;

  try {
    const target = new URL(location);
    return normalizeHostname(target.hostname) === normalizeHostname(hostname);
  } catch {
    return false;
  }
}

// Собирает Express-приложение и лимитер, но ничего не слушает: так HTTP-слой
// можно поднять на случайном порту в тестах и переиспользовать.
function createApp(config, options = {}) {
  const { publicOrigin, publicDir, pages, isProduction, demoMode, trustProxy } =
    config;

  // Тестовый шов: по умолчанию набор портов и порядок веб-портов штатные.
  // Тест лимитера подставляет сюда порт своего зависшего target-сервера,
  // чтобы не занимать фиксированный 8080 (EADDRINUSE при параллельном
  // запуске) и при этом прогнать настоящий скан, а не заглушку.
  const { scanPorts = SCAN_PORTS, webPortOrder = WEB_PORT_ORDER } = options;

  const pageCache = new Map();

  function renderPage(name) {
    const raw = fs.readFileSync(path.join(publicDir, name), "utf-8");
    return raw.replaceAll("__BASE_URL__", () => publicOrigin);
  }

  // Токен согласия живёт 15 минут, поэтому его нельзя кэшировать вместе с
  // HTML: в production страница рендерится один раз на старте, и через
  // четверть часа все сканы получали бы 400 до перезапуска процесса.
  // Кэшируем только шаблон с подставленным BASE_URL, а токен — на каждый ответ.
  function withConsentToken(html) {
    return html.replaceAll("__CONSENT_TOKEN__", () => issueConsentToken());
  }

  function pageHtml(name) {
    if (!isProduction) return withConsentToken(renderPage(name));

    if (!pageCache.has(name)) pageCache.set(name, renderPage(name));
    return withConsentToken(pageCache.get(name));
  }

  // В продакшене HTML читается на старте: это сразу падает, если файл пропал.
  // В разработке читаем с диска на каждый запрос, иначе после правки разметки
  // сервер продолжает отдавать старую версию.
  if (isProduction) {
    for (const name of pages) pageCache.set(name, renderPage(name));
  }

  const app = express();

  // Trust proxy: только целое 0..10. 0 — не доверять прокси, 1 — Render.
  // Верхняя граница не даёт выставить «доверять всей цепочке» числом вроде 1000.
  if (trustProxy > 0) {
    app.set("trust proxy", trustProxy);
  }

  app.disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'"],
          "style-src": ["'self'"],
          "object-src": ["'none'"],
          "frame-ancestors": ["'none'"],
          "base-uri": ["'self'"],
          // На dev-стенде по LAN-адресу директива апгрейдит ассеты на HTTPS
          // и ломает отладку: в продакшене она остаётся.
          "upgrade-insecure-requests": isProduction ? [] : null,
        },
      },
      xFrameOptions: { action: "deny" },
      referrerPolicy: { policy: "no-referrer" },
    }),
  );

  app.use(cors({ origin: [publicOrigin], methods: ["POST"], maxAge: 600 }));

  // Динамика не кэшируется, статика — наоборот: браузер перепроверяет её
  // по ETag и получает 304 вместо повторной загрузки двух десятков файлов
  // (16 CSS через @import + модули фронтенда).
  function noStore(req, res, next) {
    res.set("Cache-Control", "no-store");
    next();
  }

  function revalidate(req, res, next) {
    res.set("Cache-Control", "public, max-age=0, must-revalidate");
    next();
  }

  app.use("/api", noStore);

  // Тело POST /api/scan обязано быть JSON: express.json молча пропускает
  // request с другим Content-Type, и клиент получал бы 400 «Некорректный
  // адрес» вместо честного 415 про формат. req.originalUrl не переписывается
  // монтированием, поэтому проверяем именно /api/scan: неизвестный
  // /api/scan/foo должен получить 404, а не 415.
  function requireJsonBody(req, res, next) {
    if (req.method !== "POST") return next();

    const pathname = req.originalUrl.split("?")[0];
    if (pathname !== "/api/scan" && pathname !== "/api/scan/") return next();
    if (req.is("application/json")) return next();
    return res.status(415).json({ error: "Поддерживается только JSON" });
  }

  app.use("/api/scan", requireJsonBody);

  app.use(express.json({ limit: "8kb" }));

  // Отдаём страницы с подставленным BASE_URL
  app.get("/", noStore, (req, res) => {
    res.type("html").send(pageHtml("index.html"));
  });
  app.get("/legal.html", revalidate, (req, res) => {
    res.type("html").send(pageHtml("legal.html"));
  });
  app.get("/privacy.html", revalidate, (req, res) => {
    res.type("html").send(pageHtml("privacy.html"));
  });
  app.get("/index.html", (req, res) => res.redirect("/"));
  app.get("/favicon.ico", (req, res) => res.redirect(301, "/favicon.svg"));

  // Обложка OG — PNG. Явный Content-Type нужен, чтобы тип совпадал с
  // og:image:type и не зависел от настроек статики; при nosniff расхождение
  // заставило бы браузеры и краулеры отказаться от картинки.
  app.get("/assets/screenshots/og-cover.png", revalidate, (req, res) => {
    res.set("Content-Type", "image/png");
    res.sendFile(path.join(publicDir, "assets/screenshots/og-cover.png"));
  });

  // Статика не должна отдавать HTML-шаблоны: /%69ndex.html и /./index.html не
  // совпадают с точными роутами выше, но express.static нормализует путь и
  // отдал бы сырой файл с незаполненным __BASE_URL__ (сломанные canonical/
  // og:url). HTML отдаётся только через pageHtml.
  app.use((req, res, next) => {
    if (!isHtmlRequestPath(req.path)) return next();
    res.status(404);
    if (req.path.startsWith("/api/")) return res.json({ error: "Не найдено" });
    return res.type("text").send("Не найдено");
  });

  app.use(express.static(publicDir, { index: false }));

  // Лимиты сканирования. Логика живёт в utils/rate-limit.js: её надо
  // проверять без Express, сети и реального времени (часы подставляются
  // в тестах). Кулдаун, потолок одновременных сканов и лимит на ключ —
  // один объект, чтобы «пропустить» и «отпустить» нельзя было
  // рассинхронизировать.
  const limiter = new ScanLimiter({
    // Потолок одновременных сканов: без него поток запросов с разных IP
    // держит открытыми сотни исходящих сокетов к целям. Лимит на IP
    // от этого не защищает — обходится сменой адреса.
    maxConcurrent: 25,
    // 60-секундный скан, запускаемый каждые 10 секунд, иначе копил бы до
    // шести параллельных соединений с одного адреса.
    maxPerKey: 1,
    maxPerEdge: 2, // Защита от подмены XFF: не больше 2 сканов с одного сокета
    cooldownMs: 10_000,
    maxKeys: 10_000,
  });
  limiter.startSweeper(30_000);

  app.post("/api/scan", async (req, res) => {
    const { clientKey, edgeKey, rawIp } = clientIdentity(req, trustProxy);

    // Сначала валидация, чтобы мусорные запросы не жгли лимит.
    // req.body может быть undefined (не-JSON Content-Type): destructuring
    // упал бы 500 вместо понятного 400.
    const { url, consent, consentToken } = req.body || {};

    if (typeof url !== "string" || url.length === 0 || url.length > 2048) {
      return res.status(400).json({ error: "Некорректный адрес" });
    }
    if (consent !== true) {
      return res
        .status(400)
        .json({ error: "Подтверди, что у тебя есть право на проверку" });
    }

    if (!verifyConsentToken(consentToken)) {
      return res.status(400).json({
        error: "Подтверждение устарело или недействительно. Обнови страницу.",
      });
    }

    // Схема определяется по началу строки: поиск "://" где угодно ломал
    // валидный ввод вида "example.com/?next=https://x".
    const parsed = parseTarget(url);
    if (!parsed) {
      const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(url.trim());
      if (scheme && !/^https?$/i.test(scheme[1])) {
        return res
          .status(400)
          .json({ error: "Поддерживаются только http и https" });
      }
      return res.status(400).json({ error: "Некорректный адрес" });
    }

    const hostname = normalizeHostname(parsed.hostname);

    // Явный порт в URL раньше молча игнорировался: скан шёл по 80/443, а
    // пользователь думал, что проверен https://host:8443. Добавляем его к
    // списку проб и ставим первым веб-портом.
    const requestedPort = parsed.port ? Number(parsed.port) : null;
    // Схема из URL: для явного http://host:8443 TLS-проба не нужна, иначе
    // отчёт писал бы «ошибка проверки SSL» у обычного HTTP-сервиса.
    const requestScheme = parsed.protocol;
    // 22/3306 — не веб-порты: добавлять их в webPortOrder бессмысленно.
    const requestWebPortOrderExcluded = new Set([22, 3306]);
    const requestScanPorts =
      Number.isInteger(requestedPort) &&
      requestedPort > 0 &&
      requestedPort <= 65535 &&
      !scanPorts.includes(requestedPort)
        ? [requestedPort, ...scanPorts]
        : scanPorts;
    const requestWebPortOrder =
      Number.isInteger(requestedPort) &&
      !requestWebPortOrderExcluded.has(requestedPort)
        ? [
            requestedPort,
            ...webPortOrder.filter((port) => port !== requestedPort),
          ]
        : webPortOrder;

    if (hostname.length === 0 || hostname.length > 253) {
      return res.status(400).json({ error: "Некорректный адрес" });
    }

    const isIp = net.isIP(hostname);
    const domainRegex = /^([a-z0-9-]+\.)+[a-z0-9-]{2,}$/i;

    if (hostname !== "localhost" && !isIp && !domainRegex.test(hostname)) {
      return res.status(400).json({ error: "Некорректный адрес" });
    }

    // Лимит частоты срабатывает ТОЛЬКО для валидных запросов: проверка
    // адреса выше отсекает мусор до счётчиков. attempt() проверяет потолок
    // одновременных сканов раньше кулдауна, чтобы 503 не блокировал клиента
    // на 10 секунд. Ключ считается по IP, а не по цели: иначе лимит обходился
    // бы сменой домена.
    const key = clientKey;
    const denial = limiter.attempt(key, edgeKey);
    if (denial) {
      res.set("Retry-After", String(denial.retryAfter));
      return res.status(denial.status).json({ error: denial.error });
    }

    // Обрабатываем обрыв соединения клиентом:
    // если клиент ушёл, прерываем скан, чтобы не держать сокеты.
    const scanAbortController = new AbortController();
    const onClose = () => {
      if (!res.writableEnded) scanAbortController.abort();
    };

    try {
      // Подписка и лог — внутри try: если что-то из этого упадёт, finally всё
      // равно отпустит семафор и поставит кулдаун, и лимит не «потечёт».
      res.on("close", onClose);

      // Логируем ПОСЛЕ валидации (защита от log injection).
      // req.ip — недоверенное значение: при TRUST_PROXY>0 оно приходит
      // из X-Forwarded-For, поэтому в лог попадает только валидный адрес.
      const loggedIp = net.isIP(rawIp) ? rawIp : "unknown";
      console.log(
        `[${new Date().toISOString()}] Сканирование: ${hostname} | IP: ${loggedIp}`,
      );

      // Один дедлайн на весь скан. budget() отдаёт остаток этапу, а сами
      // проверки получают ещё и deadline: внутри этапа его делят все попытки,
      // ретраи и проверка старых TLS, иначе одна медленная цель снова
      // складывала бы несколько полных таймаутов и обрывалась 504.
      const deadline = Date.now() + SCAN_BUDGET_MS;
      const budget = (ms) => clampTimeout(ms, deadline);
      const ensureBudget = () => {
        if (budgetLeft(deadline) <= 0) throw new Error("SCAN_TIMEOUT");
      };

      const scanResult = await withTimeout(
        async (signal) => {
          let connectIp;
          let resolvedIps = [];

          if (
            demoMode &&
            (hostname === "localhost" ||
              hostname === "127.0.0.1" ||
              hostname === "::1")
          ) {
            // connectIp должен быть литеральным IP: request() fail-closed
            // отказывается работать с именем хоста (SSRF-инвариант).
            connectIp = hostname === "::1" ? "::1" : "127.0.0.1";
            resolvedIps = [connectIp];
          } else {
            try {
              resolvedIps = await resolveWithTimeout(
                hostname,
                budget(DNS_BUDGET_MS),
                signal,
              );
            } catch (e) {
              if (e.message === "SCAN_ABORTED" || signal.aborted) {
                throw new Error("SCAN_TIMEOUT");
              }
              if (e.message === "DNS_TIMEOUT") {
                const err = new Error("DNS_TIMEOUT");
                err.code = "DNS_TIMEOUT";
                throw err;
              }
              const err = new Error("DNS_RESOLVE_FAILED");
              err.code = "DNS_RESOLVE_FAILED";
              throw err;
            }

            if (resolvedIps.length === 0) {
              const err = new Error("PRIVATE_ADDRESS");
              err.code = "PRIVATE_ADDRESS";
              throw err;
            }
            connectIp = resolvedIps[0];
          }

          let connectIpToUse = connectIp;
          let openPorts = [];
          // Статусы всех пяти портов выбранного IP: открытые уходят в отчёт,
          // а filtered/closed нужны, чтобы не выдать «SSL не настроен» за
          // недоступный 443.
          let chosenPortResults = null;
          // DNS/email-проверки не зависят от веб-портов и идут параллельно
          // с перебором адресов/портов. Для IP и localhost модуль вернёт
          // applicable:false, не обращаясь к резолверу.
          const dnsPromise = checkDnsSecurity(hostname, {
            signal,
            timeoutMs: budget(DNS_SECURITY_TIMEOUT_MS),
          }).catch((error) => {
            // checkDnsSecurity ловит штатные сбои сама. Сюда попадает только
            // неожиданное исключение: не роняем весь скан и не оставляем
            // необработанный rejection, но и не выдаём проверку за успешную.
            console.error("[scan] DNS-проверки не удались:", error);
            return {
              applicable: true,
              spf: { present: false, error: "INTERNAL" },
              dmarc: { present: false, error: "INTERNAL" },
              caa: { present: false, error: "INTERNAL" },
            };
          });

          // Перебираем IP, пока не найдем тот, у которого есть открытые
          // порты (максимум 3). Открытые порты разных A/AAAA-адресов
          // объединяем: иначе 22 на первом IP терялась бы, если на втором
          // открыт только 443, и находка/штраф зависели бы от порядка DNS.
          const openByPort = new Map();
          for (const ip of resolvedIps.slice(0, 3)) {
            ensureBudget();
            const ports = await Promise.all(
              requestScanPorts.map((p) =>
                checkPort(ip, p, budget(PORT_TIMEOUT_MS), 1, signal, deadline),
              ),
            );
            if (signal.aborted) throw new Error("SCAN_TIMEOUT");

            const currentOpen = ports.filter((p) => p.status === "open");
            // Полные состояния последнего проверенного IP: scoring должен
            // видеть filtered, иначе «22 не ответил» превращался в «22 закрыт»
            // и приносил баллы за непроверенное.
            chosenPortResults = ports;
            if (currentOpen.length > 0) {
              for (const result of currentOpen) {
                if (!openByPort.has(result.port)) {
                  openByPort.set(result.port, result);
                }
              }
              openPorts = requestScanPorts.filter((port) => openByPort.has(port)).map(
                (port) => openByPort.get(port),
              );

              if (currentOpen.some((p) => requestWebPortOrder.includes(p.port))) {
                connectIpToUse = ip;
                break;
              }
            }
          }

          if (openPorts.length === 0) {
            const dns = await dnsPromise;
            return buildReport(
              hostname,
              [],
              // NO_WEB_PORT: TLS не проверялся. Отдавать {hasSSL:false} без
              // ошибки нельзя — scoring делал бы вывод «SSL не настроен» и
              // потолок 30 у хоста, который просто не отвечает.
              { hasSSL: false, error: "NO_WEB_PORT" },
              { error: true },
              {
                dns,
                files: { error: "NO_WEB_PORT", results: [] },
                securityTxt: { error: "NO_WEB_PORT", present: false, status: null },
                fingerprint: null,
                portChecks: chosenPortResults,
              },
            );
          }

          const availableWebPorts = selectWebPorts(
            openPorts,
            requestWebPortOrder,
          );

          if (availableWebPorts.length === 0) {
            const dns = await dnsPromise;
            return buildReport(
              hostname,
              openPorts,
              { hasSSL: false, error: "NO_WEB_PORT" },
              { error: true },
              {
                dns,
                files: { error: "NO_WEB_PORT", results: [] },
                securityTxt: { error: "NO_WEB_PORT", present: false, status: null },
                fingerprint: null,
                portChecks: chosenPortResults,
              },
            );
          }

          // Пробуем веб-порты, пока не получим успешные заголовки
          let bestSsl = { hasSSL: false };
          let bestHeaders = { error: true };
          let bestPort = availableWebPorts[0];
          let bestPortTls = false;
          let cloaking = false;
          // Порт с рабочим TLS, на котором не удалось снять заголовки. Если
          // потом 80 отдаст 301, нельзя выдавать его за основной результат:
          // отчёт получал «TLS валиден» и «заголовки не проверены» одновре-
          // менно. Лучше честно отметить заголовки непроверенными на TLS-порту.
          let tlsPortWithoutHeaders = null;

          for (const wp of availableWebPorts) {
            ensureBudget();
            // На 80 порту TLS не бывает, не тратим время и не пугаем клиента.
            // Явный http://host:port тоже означает HTTP: TLS-проба там
            // заведомо провалится и даст ложную «ошибку SSL».
            const skipTls =
              wp === 80 ||
              (wp === requestedPort && requestScheme === "http:");

            let ssl = skipTls
              ? { hasSSL: false }
              : await checkSSL(
                  connectIpToUse,
                  wp,
                  hostname,
                  signal,
                  1,
                  budget(TLS_TIMEOUT_MS),
                  deadline,
                ).catch((error) => {
                  return {
                    hasSSL: false,
                    error: "PROBE_FAILED",
                    errorCode: error.code || null,
                  };
                });
            // Провал TLS на нестандартном веб-порту — не ошибка проверки:
            // порт мог быть обычным HTTP. HTTP-протокол заголовков всё равно
            // определит реальную схему.
            if (
              wp !== 443 &&
              ssl.error &&
              !(wp === requestedPort && requestScheme === "https:")
            ) {
              ssl = { hasSSL: false };
            }
            if (wp === bestPort) bestPortTls = Boolean(ssl.hasSSL);
            if (signal.aborted) throw new Error("SCAN_TIMEOUT");

            // Основная проверка от лица браузера, чтобы WAF не подменял ответ
            const headers = await checkHeaders(
              connectIpToUse,
              wp,
              hostname,
              1,
              signal,
              Boolean(ssl.hasSSL),
              budget(HEADERS_TIMEOUT_MS),
              deadline,
              BROWSER_UA,
            );

            if (!headers.error) {
              bestHeaders = headers;
              bestPort = wp;
              bestPortTls = Boolean(ssl.hasSSL);
              if (!bestSsl.hasSSL && !bestSsl.error) bestSsl = ssl;

              // Контрольный запрос от лица сканера для выявления клоакинга
              const headersBot = await checkHeaders(
                connectIpToUse,
                wp,
                hostname,
                0,
                signal,
                Boolean(ssl.hasSSL),
                budget(HEADERS_TIMEOUT_MS),
                deadline,
                BOT_UA,
              );

              const browserSig = securitySignature(headers);
              const botSig = securitySignature(headersBot);
              if (
                browserSig !== null &&
                botSig !== null &&
                browserSig !== botSig
              ) {
                cloaking = true;
              }
              break;
            } else {
              if (ssl.hasSSL) tlsPortWithoutHeaders = { port: wp, ssl };
              if (wp === 443) bestSsl = ssl;
            }
          }

          // 443 (или другой TLS-порт) не отдал заголовки, а запасной 80 —
          // только редирект. Возвращаемся к TLS-порту: заголовки считаем
          // непроверенными, но TLS и последующие пробы идут по HTTPS.
          if (
            tlsPortWithoutHeaders &&
            !bestHeaders.error &&
            typeof bestHeaders.status === "number" &&
            bestHeaders.status >= 300
          ) {
            bestPort = tlsPortWithoutHeaders.port;
            bestPortTls = true;
            bestHeaders = { error: true, tlsPort: bestPort };
            if (!bestSsl.hasSSL) bestSsl = tlsPortWithoutHeaders.ssl;
          }

          // Источник истины для TLS — протокол фактически полученных
          // заголовков: на 443 checkHeaders пробует HTTPS даже при упавшем
          // checkSSL, и без этого отчёт расходился (headers HTTPS +
          // ssl.error/no-ssl), а пробы уходили по HTTP на порт с рабочим TLS.
          const hasTls = effectiveHasTls({
            headers: bestHeaders,
            port: bestPort,
            portTls: bestPortTls,
          });

          // Заголовки сняты по HTTPS, но checkSSL не успел: перепроверяем,
          // чтобы отчёт содержал сертификат, а не ложную ошибку TLS.
          if (hasTls && !bestSsl.hasSSL) {
            ensureBudget();
            const rechecked = await checkSSL(
              connectIpToUse,
              bestPort,
              hostname,
              signal,
              1,
              budget(TLS_TIMEOUT_MS),
              deadline,
            ).catch((error) => {
              return {
                hasSSL: false,
                error: "PROBE_FAILED",
                errorCode: error.code || null,
              };
            });
            if (rechecked && rechecked.hasSSL) {
              bestSsl = rechecked;
            } else {
              // HTTPS подтверждён ответом сервера, а сертификат прочитать не
              // удалось. Это не «SSL не настроен» и не повод резать оценку
              // потолком 60: помечаем факт, scoring покажет отдельную находку
              // и не применит жёсткий потолок ошибки TLS.
              bestSsl = { ...bestSsl, hasSSL: false, tlsConfirmed: true };
            }
          }

          // 443 не ответил (filtered/closed) — это «не измерено», а не «HTTPS
          // не настроен»: помечаем TLS непроверенным, чтобы scoring не выдал
          // критичный no-ssl и потолок 30 по сетевой блокировке.
          if (
            !bestSsl.hasSSL &&
            !bestSsl.error &&
            bestSsl.tlsConfirmed !== true &&
            tlsUnknownPort(chosenPortResults)
          ) {
            bestSsl = { ...bestSsl, tlsChecked: false };
          }

          // HSTS защищает только повторные заходы: первый http://-запрос
          // уходит открытым, если порт 80 не перенаправляет на HTTPS.
          // Проверяем это отдельным запросом и только при живом TLS и открытом
          // 80; в остальных случаях результат null — «не проверялось».
          let httpRedirectsToHttps = null;
          if (hasTls && openPorts.some((port) => port.port === 80)) {
            ensureBudget();
            const plain = await checkHeaders(
              connectIpToUse,
              80,
              hostname,
              0,
              signal,
              false,
              budget(HEADERS_TIMEOUT_MS),
              deadline,
            );
            if (plain && !plain.error) {
              httpRedirectsToHttps = redirectsToHttps(plain, hostname);
            }
          }

          // Все пробы идут на проверенный connectIp; hostname — только Host/SNI.
          ensureBudget();
          const probeTimeout = budget(PROBE_TIMEOUT_MS);
          const [dns, files, securityTxt, fingerprint] = await Promise.all([
            dnsPromise,
            checkSensitiveFiles(
              connectIpToUse,
              bestPort,
              hostname,
              hasTls,
              signal,
              probeTimeout,
            ),
            checkSecurityTxt(
              connectIpToUse,
              bestPort,
              hostname,
              hasTls,
              signal,
              probeTimeout,
            ),
            checkFingerprint(
              connectIpToUse,
              bestPort,
              hostname,
              hasTls,
              signal,
              probeTimeout,
            ),
          ]);
          if (signal.aborted) throw new Error("SCAN_TIMEOUT");

          // 200 OK на файл утечки — критическая находка. Что считать
          // критичным, решает buildReport (utils/scan-helpers), чтобы сервер
          // и тесты пользовались одним правилом, а не дублировали список путей.
          return buildReport(hostname, openPorts, bestSsl, bestHeaders, {
            dns,
            files,
            securityTxt,
            fingerprint,
            cloaking,
            httpRedirectsToHttps,
            httpPortOpen: openPorts.some((port) => port.port === 80),
            portChecks: chosenPortResults,
          });
        },
        SCAN_BUDGET_MS,
        scanAbortController.signal,
      );

      if (res.writableEnded || scanAbortController.signal.aborted) return;
      res.json(scanResult);
    } catch (e) {
      if (res.writableEnded || scanAbortController.signal.aborted) return;
      // DNS-таймаут, ошибка резолва и приватный адрес отвечают одинаково:
      // разный текст позволял проверять, существует ли внутреннее имя в сети
      // сканера (split-horizon/metadata.internal).
      if (
        e.code === "DNS_TIMEOUT" ||
        e.code === "DNS_RESOLVE_FAILED" ||
        e.code === "PRIVATE_ADDRESS"
      ) {
        return res.status(400).json({ error: "Не удалось проверить адрес" });
      }
      if (e.message === "SCAN_TIMEOUT") {
        console.error("[scan] Превышено время сканирования (60с)");
        return res
          .status(504)
          .json({ error: "Сканирование заняло слишком много времени" });
      }
      console.error("[scan] проверка не удалась:", e);
      res.status(500).json({ error: "Ошибка сканирования" });
    } finally {
      // Отпускаем лимит на любом исходе: семафор не должен «течь», если скан
      // упал или клиент оборвал соединение. finish() же ставит кулдаун —
      // осознанно и для неуспешных сканов (см. комментарий в rate-limit.js).
      limiter.finish(key, edgeKey);

      res.off("close", onClose);
    }
  });

  // Healthcheck для хостингов (Render, Railway и т.д.)
  app.get("/healthz", noStore, (req, res) =>
    res.json({ ok: true, uptime: process.uptime() }),
  );

  // 404 для API: любой неизвестный путь под /api отвечает JSON, а не HTML.
  app.use((req, res) => {
    res.status(404).json({ error: "Не найдено" });
  });

  // Единый обработчик ошибок. Регистрируется последним: Express идёт
  // по стеку от места ошибки вперёд, поэтому обработчик, стоящий выше
  // остальных маршрутов, чужие ошибки не увидит.
  app.use((err, req, res, next) => {
    const raw = err.status || err.statusCode || 500;
    const status = raw >= 400 && raw < 600 ? raw : 500;
    console.error(`[${status}] ${req.method} ${req.originalUrl}`);
    console.error(err.stack || err);
    if (res.headersSent) return next(err);

    const message =
      status === 413
        ? "Слишком большой запрос"
        : status === 415
          ? "Поддерживается только JSON"
          : status === 400
            ? "Некорректный запрос"
            : status === 429
              ? "Слишком много запросов"
              : status === 503
                ? "Сервис занят, попробуй через минуту"
                : "Внутренняя ошибка сервера";

    res.status(status).json({ error: message });
  });

  return { app, limiter };
}

// Ограничения HTTP-сервера: таймауты сокетов, потолок соединений и лимит
// сокетов с одного адреса. Вынесено в отдельную функцию, чтобы тесты поднимали
// сервер в своём процессе и проверяли реальные свойства объекта.
function applySocketLimits(server, config = {}) {
  // Без явных таймаутов медленный клиент (slowloris) держит соединение и тело
  // запроса сколько угодно, а на starter-плане это исчерпывает лимит
  // соединений.
  server.headersTimeout = SERVER_HEADERS_TIMEOUT_MS;
  server.requestTimeout = SERVER_REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = SERVER_KEEP_ALIVE_TIMEOUT_MS;

  // Потолок сокетов заметно выше того, что может открыть один хост: при малом
  // значении любой желающий idle-сокетами заставляет Node уничтожать новые
  // соединения (полный отказ в обслуживании).
  server.maxConnections = SERVER_MAX_CONNECTIONS;
  server.maxRequestsPerSocket = SERVER_MAX_REQUESTS_PER_SOCKET;

  // Если прокси не используется, ограничиваем число сокетов с одного IP,
  // чтобы защититься от idle-соединений и DoS-атак. За прокси у всех клиентов
  // один адрес edge, и такой лимит заблокировал бы всех сразу.
  if (!config.trustProxy) {
    const socketsByIp = new Map();

    server.on("connection", (socket) => {
      const ip = socket.remoteAddress || "unknown";
      const open = socketsByIp.get(ip) || 0;

      if (open >= MAX_SOCKETS_PER_IP) {
        socket.destroy();
        return;
      }

      socketsByIp.set(ip, open + 1);
      socket.once("close", () => {
        const left = (socketsByIp.get(ip) || 1) - 1;
        if (left <= 0) socketsByIp.delete(ip);
        else socketsByIp.set(ip, left);
      });
    });
  }

  return server;
}

// Создаёт Express-приложение и HTTP-сервер с лимитами, но не слушает порт и не
// вешает обработчики сигналов: ровно такой сервер нужен тестам, чтобы жить в их
// процессе и не завершать его по SIGTERM.
function createHttpServer(config, options = {}) {
  const { app, limiter } = createApp(config, options);
  const server = http.createServer(app);
  applySocketLimits(server, config);
  return { app, server, limiter };
}

// Поднимает HTTP-сервер и, по умолчанию, graceful shutdown.
function startServer(config, options = {}) {
  const { app, server, limiter } = createHttpServer(config, options);

  server.listen(config.port, () => {
    const actualPort = server.address().port;
    console.log(`Сканер запущен: http://localhost:${actualPort}`);
    console.log(`[CORS] разрешён origin: ${config.publicOrigin}`);
    if (config.demoMode) console.log("[DEMO_MODE] localhost разрешён");
  });

  // EADDRINUSE/EACCES не должны уходить в uncaughtException с сырым стеком:
  // это штатная ошибка запуска, и сообщение должно быть понятным.
  server.on("error", (error) => {
    console.error(`Не удалось запустить сервер: ${error.message}`);
    process.exit(1);
  });

  // Обработчики сигналов и страховки от необработанных ошибок вешаются на
  // процесс целиком: тестовому процессу они не нужны и мешают, поэтому их
  // можно отключить. По умолчанию (в продакшене) они включены.
  if (options.installSignalHandlers !== false) {
    // Graceful shutdown (корректное завершение при SIGTERM/SIGINT)
    for (const sig of ["SIGTERM", "SIGINT"]) {
      process.on(sig, () => {
        console.log(`${sig}: останавливаюсь...`);
        limiter.stopSweeper();
        server.close(() => process.exit(0));

        // Закрываем "спящие" соединения (Node 18+)
        if (server.closeIdleConnections) server.closeIdleConnections();

        setTimeout(() => {
          // Форсированно закрываем оставшиеся соединения
          if (server.closeAllConnections) server.closeAllConnections();
          process.exit(1);
        }, 40_000).unref();
      });
    }

    // Страховка от необработанных ошибок в промисах
    process.on("unhandledRejection", (reason) => {
      console.error("Unhandled Rejection:", reason);
    });

    process.on("uncaughtException", (err) => {
      console.error("Uncaught Exception:", err);
      process.exit(1);
    });
  }

  return { app, server, limiter };
}

module.exports = {
  createApp,
  createHttpServer,
  applySocketLimits,
  startServer,
  SCAN_PORTS,
  issueConsentToken,
  verifyConsentToken,
  redirectsToHttps,
  clientIdentity,
};
