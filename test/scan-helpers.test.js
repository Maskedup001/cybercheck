const test = require("node:test");
const assert = require("node:assert");

const {
  parseTarget,
  normalizeHostname,
  hostHeaderFor,
  rateKey,
  clampTimeout,
  budgetLeft,
  timeoutFor,
  hasBudget,
  stageDeadline,
  effectiveHasTls,
  selectWebPorts,
  withCriticalFiles,
  buildReport,
  isHtmlRequestPath,
  isLiteralIp,
} = require("../src/utils/scan-helpers");

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
  for (const value of [
    "ftp://example.com",
    "javascript://x",
    "not a url",
    "",
    "   ",
  ]) {
    assert.strictEqual(parseTarget(value), null, value);
  }

  assert.strictEqual(parseTarget(null), null);
  assert.strictEqual(parseTarget(42), null);
});

// --- IPv6: скобки только в Host, в отчёте — голый адрес -------------

test("normalizeHostname: снимает скобки IPv6 и точку в конце домена", () => {
  assert.strictEqual(normalizeHostname("[2001:db8::1]"), "2001:db8::1");
  assert.strictEqual(normalizeHostname("[::1]"), "::1");
  assert.strictEqual(normalizeHostname("  Example.COM.  "), "example.com");
  assert.strictEqual(normalizeHostname(""), "");
  assert.strictEqual(normalizeHostname(null), "");
});

test("hostHeaderFor: IPv6 в скобках, нестандартный порт — с суффиксом", () => {
  assert.strictEqual(hostHeaderFor("example.com", 80), "example.com");
  assert.strictEqual(hostHeaderFor("example.com", 443), "example.com");
  assert.strictEqual(hostHeaderFor("example.com", 8080), "example.com:8080");
  assert.strictEqual(hostHeaderFor("2001:db8::1", 443), "[2001:db8::1]");
  assert.strictEqual(hostHeaderFor("2001:db8::1", 8080), "[2001:db8::1]:8080");
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

test("budgetLeft: без дедлайна время не ограничено", () => {
  assert.strictEqual(budgetLeft(null, 1000), Infinity);
  assert.strictEqual(budgetLeft(undefined, 1000), Infinity);
  assert.strictEqual(budgetLeft(10_000, 9000), 1000);
  // Просроченный дедлайн — ровно ноль, а не отрицательное число.
  assert.strictEqual(budgetLeft(10_000, 11_000), 0);
});

test("timeoutFor: таймаут попытки не больше остатка", () => {
  assert.strictEqual(timeoutFor(5000, 20_000, 10_000), 5000);
  assert.strictEqual(timeoutFor(5000, 12_000, 10_000), 2000);
  assert.strictEqual(timeoutFor(5000, 10_000, 11_000), 0);
  // Мусорный таймаут не превращается в бесконечность.
  assert.strictEqual(timeoutFor(Number.NaN, 20_000, 10_000), 0);
  assert.strictEqual(timeoutFor(-1, 20_000, 10_000), 0);
  assert.strictEqual(timeoutFor(5000, null, 10_000), 5000);
});

test("hasBudget: остатка должно хватать на действие целиком", () => {
  assert.strictEqual(hasBudget(10_000, 1000, 8500), true);
  assert.strictEqual(hasBudget(10_000, 1000, 9500), false);
  assert.strictEqual(hasBudget(null, 1000, 9500), true);
});

test("stageDeadline: этап не выходит ни за свой таймаут, ни за дедлайн", () => {
  // Свободный дедлайн: этап получает свой таймаут.
  assert.strictEqual(stageDeadline(5000, 20_000, 10_000), 15_000);
  // Дедлайн скана ближе: побеждает он.
  assert.strictEqual(stageDeadline(5000, 12_000, 10_000), 12_000);
  // Дедлайна нет: только таймаут этапа.
  assert.strictEqual(stageDeadline(5000, null, 10_000), 15_000);
  // Нулевой таймаут не превращается в вечность.
  assert.strictEqual(stageDeadline(0, null, 10_000), 10_001);
});

// --- Выбор веб-портов ---------------------------------------------

test("selectWebPorts: только открытые веб-порты в порядке приоритета", () => {
  assert.deepStrictEqual(
    selectWebPorts([
      { port: 8080, status: "open" },
      { port: 443, status: "open" },
      { port: 80, status: "closed" },
      { port: 22, status: "open" },
    ]),
    [443, 8080],
  );

  assert.deepStrictEqual(selectWebPorts([]), []);
  assert.deepStrictEqual(selectWebPorts(null), []);
  assert.deepStrictEqual(
    selectWebPorts([
      { port: 80, status: "open" },
      { port: 443, status: "closed" },
    ]),
    [80],
  );
});

// --- Критические файлы и сборка отчёта ----------------------------

test("withCriticalFiles: critical только для реально критичных путей", () => {
  const files = {
    exposed: ["/.env", "/.DS_Store", "/.git/config"],
    results: [],
  };

  assert.deepStrictEqual(withCriticalFiles(files).critical, [
    { path: "/.env", severity: "high" },
    { path: "/.git/config", severity: "high" },
  ]);

  // .DS_Store остаётся в exposed, но критичным не считается.
  assert.ok(withCriticalFiles(files).exposed.includes("/.DS_Store"));

  assert.strictEqual(withCriticalFiles(null), null);
  assert.strictEqual(withCriticalFiles(undefined), undefined);
  assert.deepStrictEqual(withCriticalFiles({ exposed: [] }).critical, []);
});

test("buildReport: считает оценку, размечает файлы и отдаёт все секции", () => {
  const headers = {
    hsts: true,
    csp: true,
    xframe: true,
    xcontent: true,
    server: "",
    referrerPolicy: true,
    permissionsPolicy: true,
    coop: true,
    corsWildcard: false,
    cookies: [],
    cookieSummary: {
      total: 0,
      secure: 0,
      httpOnly: 0,
      sameSite: 0,
      missingSecure: 0,
      missingHttpOnly: 0,
      missingSameSite: 0,
    },
  };

  const report = buildReport(
    "example.com",
    [{ port: 443, status: "open" }],
    { hasSSL: true, valid: true, daysLeft: 200 },
    headers,
    {
      dns: {
        applicable: true,
        spf: { present: true },
        dmarc: { present: true, policy: "reject" },
        caa: { present: true, restrictive: true },
      },
      files: { exposed: ["/.env", "/.DS_Store"], results: [] },
      securityTxt: { present: true, status: 200 },
      fingerprint: null,
    },
  );

  assert.strictEqual(report.host, "example.com");
  assert.strictEqual(report.score, 40); // потолок из-за открытого /.env
  assert.strictEqual(report.grade, "D");
  assert.deepStrictEqual(report.files.critical, [
    { path: "/.env", severity: "high" },
  ]);
  assert.ok(report.findings.some((finding) => finding.id === "exposed-env"));
  assert.deepStrictEqual(report.ports, [{ port: 443, status: "open" }]);
});

test("buildReport: без данных новых проверок отчёт всё равно собирается", () => {
  const report = buildReport(
    "example.com",
    [],
    { hasSSL: false, error: "NO_WEB_PORT" },
    { error: true },
    {},
  );

  assert.strictEqual(report.dns, null);
  assert.strictEqual(report.files, null);
  assert.strictEqual(report.securityTxt, null);
  assert.strictEqual(report.fingerprint, null);
  assert.ok(
    report.findings.some((finding) => finding.id === "tls-not-checked"),
  );
  assert.strictEqual(typeof report.score, "number");
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

// --- HTML не отдаётся статикой ------------------------------------

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

test("isHtmlRequestPath: блокирует NTFS ADS и обратные слэши", () => {
  for (const path of [
    "/index.html::$DATA",
    "\\index.html",
    "/index.html:zone.identifier",
  ]) {
    assert.strictEqual(isHtmlRequestPath(path), true, path);
  }
});

// --- Литеральный IP ------------------------------------------------

test("isLiteralIp: принимает только IPv4/IPv6-литералы", () => {
  assert.strictEqual(isLiteralIp("127.0.0.1"), true);
  assert.strictEqual(isLiteralIp("::1"), true);
  assert.strictEqual(isLiteralIp("example.com"), false);
  assert.strictEqual(isLiteralIp("localhost"), false);
  assert.strictEqual(isLiteralIp(""), false);
  assert.strictEqual(isLiteralIp(undefined), false);
  assert.strictEqual(isLiteralIp(null), false);
});
