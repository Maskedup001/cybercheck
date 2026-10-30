const test = require("node:test");
const assert = require("node:assert");
const { calculateScore } = require("../src/scoring");

const okSSL = { hasSSL: true, valid: true, daysLeft: 200 };
const okHeaders = {
  hsts: true,
  csp: true,
  xframe: true,
  xcontent: true,
  server: "",
};

test("всё хорошо → A", () => {
  const r = calculateScore({ ports: [], ssl: okSSL, headers: okHeaders });
  assert.strictEqual(r.score, 100);
  assert.strictEqual(r.grade, "A");
  assert.deepStrictEqual(r.findings, []);
});

test("нет CSP → ровно 85 (B)", () => {
  const r = calculateScore({
    ports: [],
    ssl: okSSL,
    headers: { ...okHeaders, csp: false },
  });
  assert.strictEqual(r.score, 85);
  assert.strictEqual(r.grade, "B");
});

test("нет HSTS → ровно 85 (B)", () => {
  const r = calculateScore({
    ports: [],
    ssl: okSSL,
    headers: { ...okHeaders, hsts: false },
  });
  assert.strictEqual(r.score, 85);
  assert.strictEqual(r.grade, "B");
});

test("нет XCTO → ровно 90 (A)", () => {
  const r = calculateScore({
    ports: [],
    ssl: okSSL,
    headers: { ...okHeaders, xcontent: false },
  });
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "A");
});

test("просроченный SSL → ≤ 40 (D/F)", () => {
  const r = calculateScore({
    ports: [],
    ssl: { hasSSL: true, valid: false },
    headers: okHeaders,
  });
  assert.ok(r.score <= 40);
  assert.ok(["D", "F"].includes(r.grade));
});

test("нет SSL → ≤ 30 (D/F)", () => {
  const r = calculateScore({
    ports: [],
    ssl: { hasSSL: false },
    headers: okHeaders,
  });
  assert.ok(r.score <= 30);
});

test("headers.error → ≤ 60 + находка", () => {
  const r = calculateScore({ ports: [], ssl: okSSL, headers: { error: true } });
  assert.ok(r.score <= 60);
  assert.ok(r.findings.some((f) => f.id === "headers-unavailable"));
});

test("открыт 3306 → ≤ 70 + high", () => {
  const r = calculateScore({
    ports: [{ port: 3306 }],
    ssl: okSSL,
    headers: okHeaders,
  });
  assert.ok(r.score <= 70);
  assert.ok(
    r.findings.some((f) => f.id === "port-3306" && f.severity === "high"),
  );
});

test("server «не указан» не считается раскрытием", () => {
  const r = calculateScore({
    ports: [],
    ssl: okSSL,
    headers: { ...okHeaders, server: "не указан" },
  });
  assert.strictEqual(r.score, 100);
  assert.ok(!r.findings.some((f) => f.id === "server-exposed"));
});

test("HSTS без SSL не дает баллов", () => {
  const r = calculateScore({
    ports: [],
    ssl: { hasSSL: false },
    // Выключаем остальные заголовки, чтобы проверить только HSTS
    headers: {
      csp: false,
      xframe: false,
      xcontent: false,
      server: "nginx",
      hsts: true,
    },
  });
  assert.strictEqual(r.score, 20); // 20 (за порты) + 0 (за остальное)
});

test("поддержка устаревшего TLS снижает оценку", () => {
  const r = calculateScore({
    ports: [],
    ssl: { hasSSL: true, valid: true, daysLeft: 200, supportsOldTls: true },
    headers: okHeaders,
  });
  assert.strictEqual(r.score, 90); // 100 - 10
  assert.ok(r.findings.some((f) => f.id === "old-tls"));
});
