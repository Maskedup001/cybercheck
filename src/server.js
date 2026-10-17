const path = require("path");
const net = require("node:net");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { checkPort, checkSSL, checkHeaders } = require("./checks");
const { resolvePublicIps } = require("./net-guard");

// DEMO_MODE включает сканирование localhost — только для локальной демонстрации
const DEMO_MODE = process.env.DEMO_MODE === "true";

// Fail-closed: демо-режим разрешён ТОЛЬКО при явно заданном NODE_ENV=development.
// Если NODE_ENV не задан — демо-режим запрещён.
if (DEMO_MODE && process.env.NODE_ENV !== "development") {
  console.error("ОШИБКА: DEMO_MODE разрешён только при NODE_ENV=development");
  process.exit(1);
}

const app = express();

// Отключаем заголовок X-Powered-By — не палим, что это Express
app.disable("x-powered-by");

// Helmet: защитные HTTP-заголовки (CSP, X-Frame-Options, Referrer-Policy и др.)
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
    referrerPolicy: { policy: "no-referrer" },
  }),
);

// CORS: только доверенный origin, без небезопасного fallback.
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN;
if (!PUBLIC_ORIGIN) {
  console.error(
    "ОШИБКА: не задан PUBLIC_ORIGIN (например, http://localhost:3000)",
  );
  process.exit(1);
}
app.use(cors({ origin: [PUBLIC_ORIGIN], methods: ["POST"], maxAge: 600 }));
app.use(express.json({ limit: "8kb" }));
app.use(express.static(path.join(__dirname, "../public")));

// Trust proxy: за прокси/балансировщиком задай TRUST_PROXY=1 (число хопов).
// Без этого req.ip — адрес прокси, и все клиенты делят одно окно cooldown.
const TRUST_PROXY = Number(process.env.TRUST_PROXY ?? 0);
if (Number.isInteger(TRUST_PROXY) && TRUST_PROXY > 0) {
  app.set("trust proxy", TRUST_PROXY);
}

// Cooldown: не больше 1 скана в 10 секунд с одного клиента.
// Ключ нормализует IPv6 до /64 — смена младших бит не даёт новое окно.
const lastScan = new Map();
const COOLDOWN_MS = 10_000;
const MAX_KEYS = 10_000;

// Приводит IPv6 к префиксу /64, IPv4-mapped разворачивает в IPv4.
function rateKey(ip) {
  if (!ip) return "unknown";

  // IPv4-mapped IPv6 (::ffff:x.x.x.x) → IPv4
  const v4 = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4) return v4[1];

  // Чистый IPv4 — как есть
  if (net.isIPv4(ip)) return ip;

  // IPv6 → /64
  if (net.isIPv6(ip)) {
    const [head] = ip.split("::");
    const parts = head.split(":").slice(0, 4);
    return parts.join(":") + "::/64";
  }

  return ip;
}

// Запоминает ключ, вытесняя самую старую запись при переполнении.
function remember(key, now) {
  if (lastScan.size >= MAX_KEYS) {
    lastScan.delete(lastScan.keys().next().value);
  }
  lastScan.set(key, now);
}

// Возвращает число секунд ожидания, если cooldown ещё активен, иначе 0.
function checkCooldown(key) {
  const now = Date.now();
  const last = lastScan.get(key) || 0;
  if (now - last < COOLDOWN_MS) {
    return Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
  }
  remember(key, now);
  return 0;
}

// Периодическая чистка: TTL = COOLDOWN_MS (а не 60 сек), интервал 30 сек.
setInterval(() => {
  const now = Date.now();
  for (const [key, time] of lastScan.entries()) {
    if (now - time > COOLDOWN_MS) lastScan.delete(key);
  }
}, 30_000).unref();

// Основной эндпоинт сканирования
app.post("/api/scan", async (req, res) => {
  const ip = req.ip;

  // Сначала — лимит частоты (ключ нормализует IPv6 до /64)
  const wait = checkCooldown(rateKey(ip));
  if (wait > 0) {
    return res.status(429).json({
      error: `Подожди ${wait} сек. перед следующим сканом`,
    });
  }

  const { url, consent, consentTimestamp } = req.body;

  // 1. Проверка типа url — защита от 500 со стеком
  if (typeof url !== "string" || url.length === 0 || url.length > 253) {
    return res.status(400).json({ error: "Некорректный адрес" });
  }

  // 2. Проверка согласия
  if (consent !== true) {
    return res.status(400).json({
      error: "Подтверди, что у тебя есть право на проверку",
    });
  }

  // 3. Проверка timestamp — защита от NaN и подделки из будущего
  const ts = Number(consentTimestamp);
  if (
    !Number.isFinite(ts) ||
    Date.now() - ts > 300_000 ||
    ts - Date.now() > 60_000
  ) {
    return res.status(400).json({
      error: "Подтверждение устарело, обнови страницу",
    });
  }

  // 4. Парсинг URL через стандартный new URL()
  let parsed;
  try {
    parsed = new URL(url.includes("://") ? url : `http://${url}`);
  } catch {
    return res.status(400).json({ error: "Некорректный адрес" });
  }

  const hostname = parsed.hostname.toLowerCase();

  // 5. Валидация формата: localhost, домен, или IPv4-адрес
  const hostRegex =
    /^(localhost|([a-z0-9-]+\.)+[a-z]{2,}|(\d{1,3}\.){3}\d{1,3})$/;
  if (!hostRegex.test(hostname)) {
    return res.status(400).json({ error: "Некорректный адрес" });
  }

  // 6. Логирование — после валидации (защита от log injection)
  console.log(
    `[${new Date().toISOString()}] Сканирование: ${hostname} | IP: ${ip}`,
  );

  // ===== SSRF-ЗАЩИТА =====
  // Резолвим DNS и проверяем, что все полученные IP публичные.
  // Сканируем по IP (не по hostname) — это защита от DNS rebinding,
  // когда между проверкой и подключением домен может сменить адрес.
  let connectIp;

  if (
    DEMO_MODE &&
    (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1")
  ) {
    // Демо-режим: localhost разрешён для показа на тестовом стенде
    connectIp = hostname;
  } else {
    let resolvedIps;
    try {
      resolvedIps = await resolvePublicIps(hostname);
    } catch (e) {
      return res.status(400).json({ error: "Не удалось разрешить адрес" });
    }

    if (resolvedIps.length === 0) {
      return res.status(400).json({
        error: "Сканирование внутренних адресов запрещено",
      });
    }

    connectIp = resolvedIps[0];
  }
  // ========================

  try {
    // Проверяем все порты параллельно
    const ports = await Promise.all(
      [80, 443, 22, 3306, 8080].map((p) => checkPort(connectIp, p)),
    );

    const openPorts = ports.filter((p) => p.status === "open");

    // Ищем веб-порт по приоритету: 443 → 80 → 8080
    const webPort = [443, 80, 8080].find((p) =>
      openPorts.some((op) => op.port === p),
    );

    // Если веб-порт не найден — SSL и заголовки проверить негде
    if (!webPort) {
      return res.json({
        host: hostname,
        ports: openPorts,
        ssl: { hasSSL: false },
        headers: { error: true },
      });
    }

    const ssl = await checkSSL(connectIp, webPort, hostname);
    const headers = await checkHeaders(connectIp, webPort, hostname);

    res.json({
      host: hostname,
      ports: openPorts,
      ssl,
      headers,
    });
  } catch (e) {
    res.status(500).json({ error: "Ошибка сканирования" });
  }
});

// Единый обработчик ошибок: наружу — только обобщённое сообщение, без стека.
app.use((err, req, res, next) => {
  const raw = err.status || err.statusCode || 500;
  const status = raw >= 400 && raw < 600 ? raw : 500;
  console.error(`[scan] ${status} ${err.name || "Error"}`);
  if (res.headersSent) return next(err);
  res.status(status).json({
    error: status === 413 ? "Слишком большой запрос" : "Некорректный запрос",
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сканер запущен: http://localhost:${PORT}`);
  if (DEMO_MODE) {
    console.log("[DEMO_MODE] localhost разрешён для сканирования");
  }
});
