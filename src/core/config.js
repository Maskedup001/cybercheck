const path = require("node:path");

// Единственное место, где читаются переменные окружения. Остальные модули
// получают готовый объект и не зависят от process.env — так конфигурацию
// можно проверить отдельно, а сервер не разрастается проверками на старте.

const PUBLIC_DIR = path.join(__dirname, "../../public");
const PAGES = ["index.html", "legal.html", "privacy.html"];

function fail(message) {
  console.error(`ОШИБКА: ${message}`);
  process.exit(1);
}

// Origin нужен и для CORS, и для абсолютных canonical/og:url. Render
// подставляет RENDER_EXTERNAL_URL сам, поэтому blueprint остаётся
// zero-config; PUBLIC_ORIGIN имеет приоритет.
function readOrigin(env) {
  const raw = env.PUBLIC_ORIGIN || env.RENDER_EXTERNAL_URL || "";

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    fail("PUBLIC_ORIGIN (или RENDER_EXTERNAL_URL) должен быть валидным origin");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    fail("PUBLIC_ORIGIN должен использовать http или https");
  }

  return parsed.origin;
}

// Порт — строго целое 0..65535. Пустое значение означает 3000, как и
// раньше: `PORT=` в окружении не должен ронять локальный запуск.
function readPort(raw) {
  const value = raw || "3000";
  const port = Number(value);

  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    fail("PORT должен быть целым числом от 0 до 65535");
  }

  return port;
}

// Доверять можно только целому числу прокси 0..10. true, мусор и огромные
// значения закрывают сервис: иначе один заголовок X-Forwarded-For обходил
// бы лимит частоты.
function readTrustProxy(raw) {
  if (!raw) return 0;

  const text = String(raw).trim();
  if (!/^\d+$/.test(text)) {
    fail("TRUST_PROXY должен быть целым числом от 0 до 10");
  }

  const value = Number(text);
  if (!Number.isInteger(value) || value < 0 || value > 10) {
    fail("TRUST_PROXY должен быть целым числом от 0 до 10");
  }

  return value;
}

function readConfig(env = process.env) {
  const publicOrigin = readOrigin(env);
  const demoMode = env.DEMO_MODE === "true";

  // Демо-режим ослабляет SSRF-защиту, поэтому без явного development он
  // не включается, а останавливает сервис.
  if (demoMode && env.NODE_ENV !== "development") {
    fail("DEMO_MODE разрешён только при NODE_ENV=development");
  }

  return {
    publicOrigin,
    publicDir: PUBLIC_DIR,
    pages: PAGES,
    isProduction: env.NODE_ENV === "production",
    demoMode,
    trustProxy: readTrustProxy(env.TRUST_PROXY),
    port: readPort(env.PORT),
  };
}

module.exports = { readConfig, PUBLIC_DIR, PAGES };
