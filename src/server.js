const { calculateScore } = require("./scoring");
const path = require("path");
const fs = require("node:fs");
const net = require("node:net");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { checkPort, checkSSL, checkHeaders } = require("./checks");
const { resolvePublicIps } = require("./net-guard");
const { checkDnsSecurity } = require("./dns-security");
const {
  checkSensitiveFiles,
  checkSecurityTxt,
  checkFingerprint,
} = require("./web-probes");

// 1. Строгая проверка PUBLIC_ORIGIN (NEW-02)
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
const CRITICAL_FILE_PATHS = new Set([
  "/.env",
  "/.git/config",
  "/backup.zip",
]);
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

async function resolveWithTimeout(hostname, ms = 5000, signal) {
  let timer;
  let onAbort;
  try {
    const attempts = [
      resolvePublicIps(hostname),
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
const trustProxyEnv = process.env.TRUST_PROXY;
let TRUST_PROXY = 0;
if (trustProxyEnv) {
  TRUST_PROXY = Number(trustProxyEnv);
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

app.use("/api", noStore);

app.use(express.static(path.join(__dirname, "../public")));

// 2. Rate Limit с LRU-вытеснением (NEW-04)
const lastScan = new Map();
const COOLDOWN_MS = 10_000;
const MAX_KEYS = 10_000;

// Потолок одновременных сканов: без него поток запросов с разных IP
// держит открытыми сотни исходящих сокетов к целям. Лимит на IP
// от этого не защищает — обходится сменой адреса.
const MAX_CONCURRENT_SCANS = 25;
let activeScans = 0;

function rateKey(ip) {
  if (!ip) return "unknown";
  const v4 = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4) return v4[1];
  if (net.isIPv4(ip)) return ip;
  if (net.isIPv6(ip)) {
    const [head] = ip.split("::");
    const parts = head.split(":").slice(0, 4);
    return parts.join(":") + "::/64";
  }
  return "unknown"; // NEW-01: невалидный IP не создаёт свой бакет
}

function remember(key, now) {
  if (lastScan.has(key)) {
    lastScan.delete(key); // NEW-04: переносим в конец (свежий)
  } else if (lastScan.size >= MAX_KEYS) {
    lastScan.delete(lastScan.keys().next().value);
  }
  lastScan.set(key, now);
}

function checkCooldown(key) {
  const now = Date.now();
  const last = lastScan.get(key) || 0;
  if (now - last < COOLDOWN_MS) {
    return Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
  }
  remember(key, now);
  return 0;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, time] of lastScan.entries()) {
    if (now - time > COOLDOWN_MS) lastScan.delete(key);
  }
}, 30_000).unref();

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

  // 3. Сначала валидация (NEW-03), чтобы мусорные запросы не жгли лимит
  const { url, consent, consentTimestamp } = req.body;

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

  let parsed;
  try {
    parsed = new URL(url.includes("://") ? url : `http://${url}`);
  } catch {
    return res.status(400).json({ error: "Некорректный адрес" });
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return res
      .status(400)
      .json({ error: "Поддерживаются только http и https" });
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

  // Проверяем потолок одновременных сканов до списания cooldown,
  // чтобы ответ 503 не блокировал клиента на 10 секунд.
  if (activeScans >= MAX_CONCURRENT_SCANS) {
    res.set("Retry-After", "60");
    return res
      .status(503)
      .json({ error: "Сервис занят, попробуй через минуту" });
  }

  // 4. Лимит частоты срабатывает ТОЛЬКО для валидных запросов
  const wait = checkCooldown(rateKey(ip));
  if (wait > 0) {
    res.set("Retry-After", String(wait));
    return res
      .status(429)
      .json({ error: `Подожди ${wait} сек. перед следующим сканом` });
  }

  activeScans += 1;

  // Обрабатываем обрыв соединения клиентом:
  // если клиент ушёл, прерываем скан, чтобы не держать сокеты.
  const scanAbortController = new AbortController();
  const onClose = () => {
    if (!res.writableEnded) scanAbortController.abort();
  };
  res.on("close", onClose);

  // 5. Логируем ПОСЛЕ валидации (защита от log injection).
  // req.ip — недоверенное значение: при TRUST_PROXY>0 оно приходит
  // из X-Forwarded-For, поэтому в лог попадает только валидный адрес.
  const loggedIp = net.isIP(ip) ? ip : "unknown";
  console.log(
    `[${new Date().toISOString()}] Сканирование: ${hostname} | IP: ${loggedIp}`,
  );

  try {
    // DNS-разрешение входит в общий 60-секундный бюджет: клиент ждёт 65 с,
    // поэтому 5 с остаются на сеть и передачу ответа. Один веб-порт может
    // занять до 34,5 с (TLS 13,5 + заголовки 21), плюс файлы/security.txt/
    // fingerprint; три «молчащих» порта по-прежнему обрываются 504.
    const scanResult = await withTimeout(
      async (signal) => {
        let connectIp;
        let resolvedIps = [];

        if (DEMO_MODE && (hostname === "localhost" || hostname === "127.0.0.1")) {
          connectIp = hostname;
          resolvedIps = [hostname];
        } else {
          try {
            resolvedIps = await resolveWithTimeout(hostname, 5000, signal);
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
        const dnsPromise = checkDnsSecurity(hostname, { signal });

        // Перебираем IP, пока не найдем тот, у которого есть открытые порты (максимум 3)
        for (const ip of resolvedIps.slice(0, 3)) {
          const ports = await Promise.all(
            [80, 443, 22, 3306, 8080].map((p) =>
              checkPort(ip, p, 3000, 1, signal),
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
            { hasSSL: false },
            { error: true },
            { dns, files: null, securityTxt: null, fingerprint: null },
          );
        }

        const availableWebPorts = [443, 80, 8080].filter((p) =>
          openPorts.some((op) => op.port === p),
        );

        if (availableWebPorts.length === 0) {
          const dns = await dnsPromise;
          return buildReport(
            hostname,
            openPorts,
            { hasSSL: false },
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
          // На 80 порту TLS не бывает, не тратим время и не пугаем клиента.
          // 8080 по умолчанию тоже HTTP: провал TLS там не означает ошибку.
          let ssl =
            wp === 80
              ? { hasSSL: false }
              : await checkSSL(connectIpToUse, wp, hostname, signal);
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

        // Все пробы идут на проверенный connectIp; hostname — только Host/SNI.
        // TLS берём именно у bestPort: bestSsl может остаться от 443, пока
        // заголовки успешно сняты с 80/8080.
        const hasTls = bestPort !== 80 && bestPortTls;
        const [dns, files, securityTxt, fingerprint] = await Promise.all([
          dnsPromise,
          checkSensitiveFiles(
            connectIpToUse,
            bestPort,
            hostname,
            hasTls,
            signal,
          ),
          checkSecurityTxt(connectIpToUse, bestPort, hostname, hasTls, signal),
          checkFingerprint(connectIpToUse, bestPort, hostname, hasTls, signal),
        ]);
        if (signal.aborted) throw new Error("SCAN_TIMEOUT");

        // 200 OK на файл утечки — критическая находка Step 1. /.DS_Store
        // остаётся в exposed, но не попадает в critical: это low-риск.
        const filesReport = files
          ? {
              ...files,
              critical: Array.isArray(files.exposed)
                ? files.exposed
                    .filter((path) => CRITICAL_FILE_PATHS.has(path))
                    .map((path) => ({ path, severity: "critical" }))
                : [],
            }
          : files;

        return buildReport(hostname, openPorts, bestSsl, bestHeaders, {
          dns,
          files: filesReport,
          securityTxt,
          fingerprint,
        });
      },
      60000,
      scanAbortController.signal,
    );

    if (res.writableEnded || scanAbortController.signal.aborted) return;
    res.json(scanResult);
  } catch (e) {
    if (res.writableEnded || scanAbortController.signal.aborted) return;
    if (e.code === "DNS_TIMEOUT") {
      return res.status(504).json({ error: "DNS не ответил за 5 секунд" });
    }
    if (e.code === "DNS_RESOLVE_FAILED") {
      return res.status(400).json({ error: "Не удалось разрешить адрес" });
    }
    if (e.code === "PRIVATE_ADDRESS") {
      return res
        .status(400)
        .json({ error: "Сканирование внутренних адресов запрещено" });
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
    // Декремент семафора гарантированно срабатывает на любом исходе
    activeScans -= 1;
    res.off("close", onClose);
  }
});

// 6. Хелпер для сборки ответа
// extra — данные Step 1 (dns/files/securityTxt/fingerprint). Они входят в
// calculateScore: иначе карточки показывали бы новые проверки, а оценка
// считалась бы только по ports/ssl/headers.
function buildReport(host, ports, ssl, headers, extra = {}) {
  const { dns, files, securityTxt, fingerprint } = extra;
  const { score, grade, findings } = calculateScore({
    host,
    ports,
    ssl,
    headers,
    dns,
    files,
    securityTxt,
    fingerprint,
  });
  return { host, ports, ssl, headers, ...extra, score, grade, findings };
}

// Healthcheck для хостингов (Render, Railway и т.д.)
app.get("/healthz", noStore, (req, res) =>
  res.json({ ok: true, uptime: process.uptime() }),
);

// 404 для API (F-19)
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
