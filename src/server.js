const path = require("path");
const fs = require("node:fs");
const net = require("node:net");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { checkPort, checkSSL, checkHeaders } = require("./checks");
const { resolvePublicIps } = require("./net-guard");
const { checkDnsSecurity } = require("./dns-security");
const { ScanLimiter } = require("./rate-limit");
const {
  parseTarget,
  rateKey,
  budgetLeft,
  clampTimeout,
  effectiveHasTls,
  isHtmlRequestPath,
  selectWebPorts,
  buildReport,
} = require("./scan-helpers");
const {
  checkSensitiveFiles,
  checkSecurityTxt,
  checkFingerprint,
} = require("./web-probes");

// Общий бюджет одного скана. Клиент ждёт 65 с, поэтому 5 с остаются на
// сеть и передачу ответа.
const SCAN_BUDGET_MS = 60_000;
const DNS_BUDGET_MS = 5000;
const PORT_TIMEOUT_MS = 3000;
const TLS_TIMEOUT_MS = 5000;
const HEADERS_TIMEOUT_MS = 5000;
const DNS_SECURITY_TIMEOUT_MS = 3000;
const PROBE_TIMEOUT_MS = 2000;

// 1. Строгая проверка PUBLIC_ORIGIN при старте
const envOrigin =
  process.env.PUBLIC_ORIGIN || process.env.RENDER_EXTERNAL_URL || "";
let parsedOrigin;
try {
  parsedOrigin = new URL(envOrigin);
} catch {
  console.error(
    "ОШИБКА: PUBLIC_ORIGIN (или RENDER_EXTERNAL_URL) должен быть валидным origin",
  );
  process.exit(1);
}

if (!["http:", "https:"].includes(parsedOrigin.protocol)) {
  console.error("ОШИБКА: PUBLIC_ORIGIN должен использовать http или https");
  process.exit(1);
}

const PUBLIC_ORIGIN = parsedOrigin.origin;

// HTML-страницы с подставленным BASE_URL: canonical, og:url и og:image
// должны быть абсолютными, а origin известен только здесь.
const PUBLIC_DIR = path.join(__dirname, "../public");
const PAGES = ["index.html", "legal.html", "privacy.html"];
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const pageCache = new Map();

function renderPage(name) {
  const raw = fs.readFileSync(path.join(PUBLIC_DIR, name), "utf-8");
  return raw.replaceAll("__BASE_URL__", () => PUBLIC_ORIGIN);
}

function pageHtml(name) {
  if (!IS_PRODUCTION) return renderPage(name);

  if (!pageCache.has(name)) pageCache.set(name, renderPage(name));
  return pageCache.get(name);
}

// В продакшене HTML кэшируется на старте: это дешевле и сразу падает,
// если файл пропал. В разработке читаем с диска на каждый запрос, иначе
// после правки разметки сервер продолжает отдавать старую версию.
if (IS_PRODUCTION) {
  for (const name of PAGES) pageHtml(name);
}

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

const DEMO_MODE = process.env.DEMO_MODE === "true";
if (DEMO_MODE && process.env.NODE_ENV !== "development") {
  console.error("ОШИБКА: DEMO_MODE разрешён только при NODE_ENV=development");
  process.exit(1);
}

const app = express();

// Trust proxy: только целое 0..10. 0 — не доверять прокси, 1 — Render.
// Верхняя граница не даёт выставить «доверять всей цепочке» числом вроде 1000.
// Number(" 1 ") или Number("0x1") давали неожиданный результат, поэтому
// принимаем только строку из цифр.
const trustProxyEnv = process.env.TRUST_PROXY;
let TRUST_PROXY = 0;
if (trustProxyEnv) {
  if (!/^\d+$/.test(trustProxyEnv.trim())) {
    console.error("ОШИБКА: TRUST_PROXY должен быть целым числом от 0 до 10");
    process.exit(1);
  }
  TRUST_PROXY = Number(trustProxyEnv.trim());
  if (
    !Number.isInteger(TRUST_PROXY) ||
    TRUST_PROXY < 0 ||
    TRUST_PROXY > 10
  ) {
    console.error("ОШИБКА: TRUST_PROXY должен быть целым числом от 0 до 10");
    process.exit(1);
  }
  if (TRUST_PROXY > 0) {
    app.set("trust proxy", TRUST_PROXY);
  }
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
        "upgrade-insecure-requests": IS_PRODUCTION ? [] : null,
      },
    },
    xFrameOptions: { action: "deny" },
    referrerPolicy: { policy: "no-referrer" },
  }),
);

app.use(cors({ origin: [PUBLIC_ORIGIN], methods: ["POST"], maxAge: 600 }));

// Динамика не кэшируется, статика — наоборот: браузер перепроверяет её
// по ETag и получает 304 вместо повторной загрузки двух десятков файлов
// (16 CSS через @import + 4 JS-модуля).
function noStore(req, res, next) {
  res.set("Cache-Control", "no-store");
  next();
}

function revalidate(req, res, next) {
  res.set("Cache-Control", "public, max-age=0, must-revalidate");
  next();
}

app.use("/api", noStore);

// Тело POST /api/scan обязано быть JSON. express.json молча пропускает
// запрос с другим Content-Type, и клиент получал бы 400 «Некорректный
// адрес» вместо честного 415 про формат — то есть шёл бы чинить URL.
// Проверка стоит до парсера и не даёт ему сработать на чужом типе.
function requireJsonBody(req, res, next) {
  if (req.method !== "POST") return next();
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

app.use(express.static(path.join(__dirname, "../public"), { index: false }));

// 2. Лимиты сканирования. Логика живёт в rate-limit.js: её надо проверять
// без Express, сети и реального времени (часы подставляются в тестах).
// Кулдаун, потолок одновременных сканов и лимит на ключ — один объект,
// чтобы «пропустить» и «отпустить» нельзя было рассинхронизировать.
const limiter = new ScanLimiter({
  // Потолок одновременных сканов: без него поток запросов с разных IP
  // держит открытыми сотни исходящих сокетов к целям. Лимит на IP
  // от этого не защищает — обходится сменой адреса.
  maxConcurrent: 25,
  // 60-секундный скан, запускаемый каждые 10 секунд, иначе копил бы до
  // шести параллельных соединений с одного адреса.
  maxPerKey: 1,
  cooldownMs: 10_000,
  maxKeys: 10_000,
});
limiter.startSweeper(30_000);

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

  return Promise.race([factory(signal), timeout]).finally(() => {
    clearTimeout(timer);
  });
}

app.post("/api/scan", async (req, res) => {
  const ip = req.ip;

  // 3. Сначала валидация, чтобы мусорные запросы не жгли лимит.
  // req.body может быть undefined (не-JSON Content-Type): destructuring
  // упал бы 500 вместо понятного 400.
  const { url, consent, consentTimestamp } = req.body || {};

  if (typeof url !== "string" || url.length === 0 || url.length > 2048) {
    return res.status(400).json({ error: "Некорректный адрес" });
  }
  if (consent !== true) {
    return res
      .status(400)
      .json({ error: "Подтверди, что у тебя есть право на проверку" });
  }
  const ts = Number(consentTimestamp);
  if (
    !Number.isFinite(ts) ||
    Date.now() - ts > 900_000 || // 15 минут на случай дрейфа часов
    ts - Date.now() > 60_000
  ) {
    return res
      .status(400)
      .json({ error: "Подтверждение устарело, обнови страницу" });
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

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");

  if (hostname.length === 0 || hostname.length > 253) {
    return res.status(400).json({ error: "Некорректный адрес" });
  }

  const isIp = net.isIP(hostname);
  const domainRegex = /^([a-z0-9-]+\.)+[a-z0-9-]{2,}$/i;

  if (hostname !== "localhost" && !isIp && !domainRegex.test(hostname)) {
    return res.status(400).json({ error: "Некорректный адрес" });
  }

  // 4. Лимит частоты срабатывает ТОЛЬКО для валидных запросов: проверка
  // адреса выше отсекает мусор до счётчиков. attempt() проверяет потолок
  // одновременных сканов раньше кулдауна, чтобы 503 не блокировал клиента
  // на 10 секунд. Ключ считается по IP, а не по цели: иначе лимит обходился
  // бы сменой домена.
  const key = rateKey(ip);
  const denial = limiter.attempt(key);
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

    // 5. Логируем ПОСЛЕ валидации (защита от log injection).
    // req.ip — недоверенное значение: при TRUST_PROXY>0 оно приходит
    // из X-Forwarded-For, поэтому в лог попадает только валидный адрес.
    const loggedIp = net.isIP(ip) ? ip : "unknown";
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

        if (DEMO_MODE && (hostname === "localhost" || hostname === "127.0.0.1")) {
          // connectIp должен быть литеральным IP: request() fail-closed
          // отказывается работать с именем хоста (SSRF-инвариант).
          connectIp = "127.0.0.1";
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
        // DNS/email-проверки не зависят от веб-портов и идут параллельно
        // с перебором адресов/портов. Для IP и localhost модуль вернёт
        // applicable:false, не обращаясь к резолверу.
        const dnsPromise = checkDnsSecurity(hostname, {
          signal,
          timeoutMs: budget(DNS_SECURITY_TIMEOUT_MS),
        });

        // Перебираем IP, пока не найдем тот, у которого есть открытые порты (максимум 3)
        for (const ip of resolvedIps.slice(0, 3)) {
          ensureBudget();
          const ports = await Promise.all(
            [80, 443, 22, 3306, 8080].map((p) =>
              checkPort(ip, p, budget(PORT_TIMEOUT_MS), 1, signal, deadline),
            ),
          );
          if (signal.aborted) throw new Error("SCAN_TIMEOUT");

          const currentOpen = ports.filter((p) => p.status === "open");
          if (currentOpen.length > 0) {
            connectIpToUse = ip;
            openPorts = currentOpen;
            if (currentOpen.some((p) => [443, 80, 8080].includes(p.port)))
              break;
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
            { dns, files: null, securityTxt: null, fingerprint: null },
          );
        }

        const availableWebPorts = selectWebPorts(openPorts);

        if (availableWebPorts.length === 0) {
          const dns = await dnsPromise;
          return buildReport(
            hostname,
            openPorts,
            { hasSSL: false, error: "NO_WEB_PORT" },
            { error: true },
            { dns, files: null, securityTxt: null, fingerprint: null },
          );
        }

        // Пробуем веб-порты, пока не получим успешные заголовки
        let bestSsl = { hasSSL: false };
        let bestHeaders = { error: true };
        let bestPort = availableWebPorts[0];
        let bestPortTls = false;

        for (const wp of availableWebPorts) {
          ensureBudget();
          // На 80 порту TLS не бывает, не тратим время и не пугаем клиента.
          // 8080 по умолчанию тоже HTTP: провал TLS там не означает ошибку.
          let ssl =
            wp === 80
              ? { hasSSL: false }
              : await checkSSL(
                  connectIpToUse,
                  wp,
                  hostname,
                  signal,
                  1,
                  budget(TLS_TIMEOUT_MS),
                  deadline,
                );
          if (wp === 8080 && ssl.error) ssl = { hasSSL: false };
          if (wp === bestPort) bestPortTls = Boolean(ssl.hasSSL);
          if (signal.aborted) throw new Error("SCAN_TIMEOUT");

          const headers = await checkHeaders(
            connectIpToUse,
            wp,
            hostname,
            1,
            signal,
            Boolean(ssl.hasSSL),
            budget(HEADERS_TIMEOUT_MS),
            deadline,
          );

          if (!headers.error) {
            bestHeaders = headers;
            bestPort = wp;
            bestPortTls = Boolean(ssl.hasSSL);
            if (!bestSsl.hasSSL && !bestSsl.error) bestSsl = ssl;
            break;
          } else if (wp === 443) {
            bestSsl = ssl;
          }
        }

        // Источник истины для TLS — протокол фактически полученных заголовков:
        // на 443 checkHeaders пробует HTTPS даже при упавшем checkSSL, и без
        // этого отчёт расходился (headers HTTPS + ssl.error/no-ssl), а пробы
        // уходили по HTTP на порт с рабочим TLS.
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
          );
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

        // 200 OK на файл утечки — критическая находка Step 1. Что считать
        // критичным, решает buildReport (scan-helpers), чтобы сервер и тесты
        // пользовались одним правилом, а не дублировали список путей.
        return buildReport(hostname, openPorts, bestSsl, bestHeaders, {
          dns,
          files,
          securityTxt,
          fingerprint,
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
    limiter.finish(key);

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

// 7. Единый обработчик ошибок. Регистрируется последним: Express идёт
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

// Строгий парсинг порта (защита от PORT=abc или PORT=3000.5)
const rawPort = process.env.PORT || "3000";
const PORT = Number(rawPort);
if (!Number.isInteger(PORT) || PORT < 0 || PORT > 65535) {
  console.error("ОШИБКА: PORT должен быть целым числом от 0 до 65535");
  process.exit(1);
}

const server = app.listen(PORT, () => {
  const actualPort = server.address().port;
  console.log(`Сканер запущен: http://localhost:${actualPort}`);
  console.log(`[CORS] разрешён origin: ${PUBLIC_ORIGIN}`);
  if (DEMO_MODE) console.log("[DEMO_MODE] localhost разрешён");
});

// Явные таймауты сокетов: без них медленный клиент (slowloris) держит
// соединение и тело запроса сколько угодно, а на starter-плане это
// исчерпывает лимит соединений.
server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxConnections = 500;
server.maxRequestsPerSocket = 100;

// Graceful shutdown (корректное завершение при SIGTERM/SIGINT)
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    console.log(`${sig}: останавливаюсь...`);
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
