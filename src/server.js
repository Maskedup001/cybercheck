const { calculateScore } = require("./scoring");
const path = require("path");
const net = require("node:net");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { checkPort, checkSSL, checkHeaders } = require("./checks");
const { resolvePublicIps } = require("./net-guard");

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

const DEMO_MODE = process.env.DEMO_MODE === "true";
if (DEMO_MODE && process.env.NODE_ENV !== "development") {
  console.error("ОШИБКА: DEMO_MODE разрешён только при NODE_ENV=development");
  process.exit(1);
}

const app = express();

// Trust proxy
const TRUST_PROXY = Number(process.env.TRUST_PROXY ?? 0);
if (Number.isInteger(TRUST_PROXY) && TRUST_PROXY > 0) {
  app.set("trust proxy", TRUST_PROXY);
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
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});
app.use(express.json({ limit: "8kb" }));
app.use(express.static(path.join(__dirname, "../public")));

// 2. Rate Limit с LRU-вытеснением (NEW-04)
const lastScan = new Map();
const COOLDOWN_MS = 10_000;
const MAX_KEYS = 10_000;

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

// Хелпер для ограничения времени выполнения скана
function withTimeout(promise, ms) {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error("SCAN_TIMEOUT")), ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() =>
    clearTimeout(timeoutId),
  );
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

  // 4. Лимит частоты срабатывает ТОЛЬКО для валидных запросов
  const wait = checkCooldown(rateKey(ip));
  if (wait > 0) {
    return res
      .status(429)
      .json({ error: `Подожди ${wait} сек. перед следующим сканом` });
  }

  // 5. Логируем ПОСЛЕ валидации (защита от log injection)
  console.log(
    `[${new Date().toISOString()}] Сканирование: ${hostname} | IP: ${ip}`,
  );

  let connectIp;
  if (DEMO_MODE && (hostname === "localhost" || hostname === "127.0.0.1")) {
    connectIp = hostname;
  } else {
    let resolvedIps;
    try {
      resolvedIps = await resolvePublicIps(hostname);
    } catch (e) {
      return res.status(400).json({ error: "Не удалось разрешить адрес" });
    }

    if (resolvedIps.length === 0) {
      return res
        .status(400)
        .json({ error: "Сканирование внутренних адресов запрещено" });
    }
    connectIp = resolvedIps[0];
  }

  try {
    // Ограничиваем весь процесс сканирования 20 секундами
    const scanResult = await withTimeout(
      (async () => {
        const ports = await Promise.all(
          [80, 443, 22, 3306, 8080].map((p) => checkPort(connectIp, p)),
        );
        const openPorts = ports.filter((p) => p.status === "open");
        const webPort = [443, 80, 8080].find((p) =>
          openPorts.some((op) => op.port === p),
        );

        if (!webPort) {
          const ssl = { hasSSL: false };
          const headers = { error: true };
          return buildReport(hostname, openPorts, ssl, headers);
        }

        const ssl = await checkSSL(connectIp, webPort, hostname);
        const headers = await checkHeaders(connectIp, webPort, hostname);
        return buildReport(hostname, openPorts, ssl, headers);
      })(),
      20000,
    ); // 20 секунд

    res.json(scanResult);
  } catch (e) {
    if (e.message === "SCAN_TIMEOUT") {
      console.error("[scan] Превышено время сканирования (20с)");
      return res
        .status(504)
        .json({ error: "Сканирование заняло слишком много времени" });
    }
    console.error("[scan] проверка не удалась:", e);
    res.status(500).json({ error: "Ошибка сканирования" });
  }
});

// 6. Улучшенный Error Handler (NEW-06)
app.use((err, req, res, next) => {
  const raw = err.status || err.statusCode || 500;
  const status = raw >= 400 && raw < 600 ? raw : 500;
  console.error(`[scan] ${status} ${req.method} ${req.originalUrl}`);
  console.error(err.stack || err);
  if (res.headersSent) return next(err);

  const message =
    status === 413
      ? "Слишком большой запрос"
      : status === 400
        ? "Некорректный запрос"
        : status === 429
          ? "Слишком много запросов"
          : "Внутренняя ошибка сервера";

  res.status(status).json({ error: message });
});

// Хелпер для сборки ответа
function buildReport(host, ports, ssl, headers) {
  const { score, grade, findings } = calculateScore({
    host,
    ports,
    ssl,
    headers,
  });
  return { host, ports, ssl, headers, score, grade, findings };
}

// Healthcheck для хостингов (Render, Railway и т.д.)
app.get("/healthz", (req, res) =>
  res.json({ ok: true, uptime: process.uptime() }),
);

// 404 для API (F-19)
app.use((req, res) => {
  res.status(404).json({ error: "Не найдено" });
});

const PORT = Number(process.env.PORT) || 3000;
if (PORT < 1 || PORT > 65535) {
  console.error("ОШИБКА: PORT должен быть числом от 1 до 65535");
  process.exit(1);
}
const server = app.listen(PORT, () => {
  console.log(`Сканер запущен: http://localhost:${PORT}`);
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
