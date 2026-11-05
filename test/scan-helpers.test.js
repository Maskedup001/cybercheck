const test = require("node:test");
const assert = require("node:assert");

const {
  parseTarget,
  rateKey,
  clampTimeout,
  effectiveHasTls,
  isHtmlRequestPath,
} = require("../src/scan-helpers");

// --- Схема определяется в начале адреса ----------------------------

test("parseTarget: схема ищется в начале, а не где угодно", () => {
  const parsed = parseTarget("example.com/?next=https://x");

  assert.ok(parsed);
  assert.strictEqual(parsed.hostname, "example.com");
  assert.strictEqual(parsed.protocol, "http:");
});

test("parseTarget: явные схемы и голый хост", () => {
  assert.strictEqual(parseTarget("https://example.com").protocol, "https:");
  assert.strictEqual(parseTarget("example.com:8443").port, "8443");
  assert.strictEqual(parseTarget("  example.com  ").hostname, "example.com");
});

test("parseTarget: неподдерживаемая схема и мусор", () => {
  for (const value of ["ftp://example.com", "javascript://x", "not a url", "", "   "]) {
    assert.strictEqual(parseTarget(value), null, value);
  }

  assert.strictEqual(parseTarget(null), null);
  assert.strictEqual(parseTarget(42), null);
});

// --- Канонический ключ rate-limit ---------------------------------

test("rateKey: IPv4 не меняется", () => {
  assert.strictEqual(rateKey("203.0.113.5"), "203.0.113.5");
});

test("rateKey: IPv4-mapped разворачивается в IPv4", () => {
  assert.strictEqual(rateKey("::ffff:127.0.0.1"), "127.0.0.1");
  assert.strictEqual(rateKey("::ffff:7f00:1"), "127.0.0.1");
});

test("rateKey: текстовые варианты одного /64 дают один ключ", () => {
  const short = rateKey("2001:db8::1");
  const long = rateKey("2001:0db8:0:0:0:0:0:1");
  const upper = rateKey("2001:DB8::abcd");

  assert.strictEqual(short, long);
  assert.strictEqual(short, upper);
  assert.match(short, /::\/64$/);
});

test("rateKey: разные /64 различаются, мусор — unknown", () => {
  assert.notStrictEqual(rateKey("2001:db8::1"), rateKey("2001:db9::1"));
  assert.strictEqual(rateKey("not-an-ip"), "unknown");
  assert.strictEqual(rateKey(""), "unknown");
  assert.strictEqual(rateKey(undefined), "unknown");
});

// --- Бюджет скана --------------------------------------------------

test("clampTimeout: остаток бюджета ограничивает этап", () => {
  const deadline = 10_000;

  assert.strictEqual(clampTimeout(5000, deadline, 1000), 5000);
  assert.strictEqual(clampTimeout(5000, deadline, 9000), 1000);
  assert.strictEqual(clampTimeout(5000, deadline, 11_000), 0);
});

// --- Источник истины для TLS --------------------------------------

test("effectiveHasTls: протокол заголовков важнее checkSSL", () => {
  // 443 ответил по HTTPS, хотя checkSSL упал.
  assert.strictEqual(
    effectiveHasTls({
      headers: { protocol: "HTTPS" },
      port: 443,
      portTls: false,
    }),
    true,
  );

  // 8080 ответил по HTTP — TLS там нет.
  assert.strictEqual(
    effectiveHasTls({
      headers: { protocol: "HTTP" },
      port: 8080,
      portTls: true,
    }),
    false,
  );

  // Заголовков нет: падаем назад к checkSSL (кроме 80).
  assert.strictEqual(
    effectiveHasTls({ headers: { error: true }, port: 443, portTls: true }),
    false,
  );
  assert.strictEqual(
    effectiveHasTls({ headers: {}, port: 443, portTls: true }),
    true,
  );
  assert.strictEqual(
    effectiveHasTls({ headers: {}, port: 80, portTls: true }),
    false,
  );
});

// --- TML не отдаётся статикой ------------------------------------

test("isHtmlRequestPath: ловит .html и его encoded-варианты", () => {
  for (const path of [
    "/index.html",
    "/%69ndex.html",
    "/./index.html",
    "/legal.html",
    "/app.htm",
    "/INDEX.HTML",
  ]) {
    assert.strictEqual(isHtmlRequestPath(path), true, path);
  }

  for (const path of ["/", "/app.js", "/assets/css/main.css", "/api/scan"]) {
    assert.strictEqual(isHtmlRequestPath(path), false, path);
  }
});
