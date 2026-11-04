const test = require("node:test");
const assert = require("node:assert");
const { calculateScore, WEIGHTS } = require("../src/scoring");

const okSSL = { hasSSL: true, valid: true, daysLeft: 200 };

const emptyCookies = {
  total: 0,
  secure: 0,
  httpOnly: 0,
  sameSite: 0,
  missingSecure: 0,
  missingHttpOnly: 0,
  missingSameSite: 0,
};

const okHeaders = {
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
  cookieSummary: emptyCookies,
};

const okDns = {
  applicable: true,
  spf: { present: true, record: "v=spf1 -all", multiple: false, error: null },
  dmarc: {
    present: true,
    record: "v=DMARC1; p=reject",
    policy: "reject",
    strict: true,
    weak: false,
    error: null,
  },
  caa: { present: true, records: [], error: null },
};

const okFiles = { exposed: [], blocked: [], results: [] };
const okSecurityTxt = { present: true, status: 200 };

function report(overrides = {}) {
  return {
    ports: [],
    ssl: okSSL,
    headers: okHeaders,
    dns: okDns,
    files: okFiles,
    securityTxt: okSecurityTxt,
    fingerprint: null,
    ...overrides,
  };
}

test("сумма положительных весов ровно 100", () => {
  const sum = Object.values(WEIGHTS).reduce((total, value) => total + value, 0);
  assert.strictEqual(sum, 100);
});

test("всё хорошо → 100/A без находок", () => {
  const r = calculateScore(report());
  assert.strictEqual(r.score, 100);
  assert.strictEqual(r.grade, "A");
  assert.deepStrictEqual(r.findings, []);
});

test("нет CSP → 90/B, вес 10", () => {
  const r = calculateScore(
    report({ headers: { ...okHeaders, csp: false } }),
  );
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "B");
  const finding = r.findings.find((f) => f.id === "no-csp");
  assert.ok(finding);
  assert.strictEqual(finding.weight, 10);
  assert.strictEqual(finding.owasp, "A05:2021 Security Misconfiguration");
});

test("нет HSTS → 90/B, вес 8", () => {
  const r = calculateScore(
    report({ headers: { ...okHeaders, hsts: false } }),
  );
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "B");
  assert.strictEqual(
    r.findings.find((f) => f.id === "no-hsts").weight,
    8,
  );
});

test("нет XCTO → 90/B, вес 6", () => {
  const r = calculateScore(
    report({ headers: { ...okHeaders, xcontent: false } }),
  );
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "B");
  assert.strictEqual(
    r.findings.find((f) => f.id === "no-xcontent").weight,
    6,
  );
});

test("просроченный SSL → ≤ 40 (D/F), вес 12", () => {
  const r = calculateScore(
    report({ ssl: { hasSSL: true, valid: false } }),
  );
  assert.ok(r.score <= 40);
  assert.ok(["D", "F"].includes(r.grade));
  assert.strictEqual(r.findings.find((f) => f.id === "bad-ssl").weight, 12);
});

test("нет SSL → ≤ 30, no-ssl high", () => {
  const r = calculateScore(report({ ssl: { hasSSL: false } }));
  assert.ok(r.score <= 30);
  assert.ok(r.findings.some((f) => f.id === "no-ssl"));
});

test("headers.error → ≤ 60 + находка", () => {
  const r = calculateScore(report({ headers: { error: true } }));
  assert.ok(r.score <= 60);
  assert.ok(r.findings.some((f) => f.id === "headers-unavailable"));
});

test("открыт 3306 → ≤ 70 + high, вес 10", () => {
  const r = calculateScore(
    report({ ports: [{ port: 3306, status: "open" }] }),
  );
  assert.ok(r.score <= 70);
  const finding = r.findings.find((f) => f.id === "port-3306");
  assert.ok(finding);
  assert.strictEqual(finding.severity, "high");
  assert.strictEqual(finding.weight, 10);
});

test("server «не указан» и Server без версии не считаются раскрытием", () => {
  for (const server of [
    "не указан",
    "cloudflare",
    "github.com",
    "unknown",
    "nginx",
    "AmazonS3",
  ]) {
    const r = calculateScore(report({ headers: { ...okHeaders, server } }));
    assert.strictEqual(r.score, 100, `server=${server}`);
    assert.ok(
      !r.findings.some((f) => f.id === "server-exposed"),
      `server=${server}`,
    );
  }
});

test("Server с версией → находка low, вес 3, 97/A", () => {
  for (const server of [
    "nginx/1.18.0",
    "Apache/2.4.49 (Unix)",
    "nginx/2",
    "lighttpd/2",
    "Foo/3",
  ]) {
    const r = calculateScore(report({ headers: { ...okHeaders, server } }));
    const finding = r.findings.find((f) => f.id === "server-exposed");
    assert.ok(finding, `server=${server}`);
    assert.strictEqual(finding.severity, "low");
    assert.strictEqual(finding.weight, 3);
    assert.strictEqual(r.score, 97, `server=${server}`);
    assert.strictEqual(r.grade, "A", `server=${server}`);
  }
});

test("поддержка устаревшего TLS → 85/B, штраф 10", () => {
  const r = calculateScore(
    report({
      ssl: { ...okSSL, supportsOldTls: true },
    }),
  );
  assert.strictEqual(r.score, 85);
  assert.strictEqual(r.grade, "B");
  assert.strictEqual(r.findings.find((f) => f.id === "old-tls").weight, 10);
});

test("открыт 8080 → 90/B, medium cap", () => {
  const r = calculateScore(
    report({ ports: [{ port: 8080, status: "open" }] }),
  );
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "B");
  assert.strictEqual(
    r.findings.find((f) => f.id === "port-8080").weight,
    2,
  );
});

test("HTTP-only сайт → no-ssl и 30", () => {
  const r = calculateScore(
    report({
      ports: [{ port: 80, status: "open" }],
      ssl: { hasSSL: false },
    }),
  );
  assert.strictEqual(r.score, 30);
  assert.strictEqual(r.grade, "E");
  assert.ok(r.findings.some((f) => f.id === "no-ssl"));
  assert.ok(!r.findings.some((f) => f.id === "ssl-error"));
});

test("ошибка TLS → ssl-error и ≤ 60, без no-ssl", () => {
  const r = calculateScore(
    report({ ssl: { hasSSL: false, error: "HANDSHAKE_FAILED" } }),
  );
  assert.ok(r.score <= 60);
  assert.ok(r.findings.some((f) => f.id === "ssl-error"));
  assert.ok(!r.findings.some((f) => f.id === "no-ssl"));
});

test("сертификат через 7 дней → 90/B", () => {
  const r = calculateScore(
    report({ ssl: { hasSSL: true, valid: true, daysLeft: 7 } }),
  );
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "B");
  assert.ok(r.findings.some((f) => f.id === "ssl-expiring"));
});

test("открыт /.env → потолок 40 (D), high + A03", () => {
  const r = calculateScore(
    report({
      files: {
        critical: [{ path: "/.env", severity: "critical" }],
        blocked: [],
        results: [],
      },
    }),
  );
  assert.strictEqual(r.score, 40);
  assert.strictEqual(r.grade, "D");
  const finding = r.findings.find((f) => f.id === "exposed-env");
  assert.ok(finding);
  assert.strictEqual(finding.severity, "high");
  assert.strictEqual(finding.weight, WEIGHTS.env);
  assert.strictEqual(finding.owasp, "A03:2021 Injection");
});

test("открыт /.git/config → потолок 50 (D)", () => {
  const r = calculateScore(
    report({ files: { exposed: ["/.git/config"], blocked: [], results: [] } }),
  );
  assert.strictEqual(r.score, 50);
  assert.strictEqual(r.grade, "D");
  assert.ok(r.findings.some((f) => f.id === "exposed-git"));
});

test("открыт /backup.zip → потолок 50 (D)", () => {
  const r = calculateScore(
    report({ files: { exposed: ["/backup.zip"], blocked: [], results: [] } }),
  );
  assert.strictEqual(r.score, 50);
  assert.strictEqual(r.grade, "D");
  assert.ok(r.findings.some((f) => f.id === "exposed-backup"));
});

test("CORS wildcard → потолок 60 (C)", () => {
  const r = calculateScore(
    report({ headers: { ...okHeaders, corsWildcard: true } }),
  );
  assert.strictEqual(r.score, 60);
  assert.strictEqual(r.grade, "C");
  const finding = r.findings.find((f) => f.id === "cors-wildcard");
  assert.ok(finding);
  assert.strictEqual(finding.severity, "high");
  assert.strictEqual(finding.owasp, "A05:2021 Security Misconfiguration");
});

test("DMARC p=none → dmarc-weak и 90/B", () => {
  const r = calculateScore(
    report({
      dns: {
        ...okDns,
        dmarc: {
          present: true,
          record: "v=DMARC1; p=none",
          policy: "none",
          strict: false,
          weak: true,
          error: null,
        },
      },
    }),
  );
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "B");
  assert.strictEqual(
    r.findings.find((f) => f.id === "dmarc-weak").weight,
    WEIGHTS.dmarc,
  );
});

test("DNS timeout не роняет скан и не отнимает баллы", () => {
  const timeout = { present: false, error: "TIMEOUT" };
  const r = calculateScore(
    report({
      dns: {
        applicable: true,
        spf: { ...timeout },
        dmarc: { ...timeout, policy: null, strict: false, weak: false },
        caa: { present: false, records: [], error: "TIMEOUT" },
      },
    }),
  );
  assert.strictEqual(r.score, 100);
  assert.strictEqual(r.grade, "A");
  assert.ok(!r.findings.some((f) => f.id === "spf-missing"));
  assert.ok(!r.findings.some((f) => f.id === "dmarc-missing"));
  assert.ok(!r.findings.some((f) => f.id === "caa-missing"));
});

test("DNS ENODATA — это отсутствие записи, а не сбой", () => {
  const r = calculateScore(
    report({
      dns: {
        applicable: true,
        spf: { present: false, error: "ENODATA" },
        dmarc: {
          present: false,
          policy: null,
          strict: false,
          weak: false,
          error: "ENODATA",
        },
        caa: { present: false, records: [], error: "ENODATA" },
      },
    }),
  );
  assert.ok(r.findings.some((f) => f.id === "spf-missing"));
  assert.ok(r.findings.some((f) => f.id === "dmarc-missing"));
  assert.ok(r.findings.some((f) => f.id === "caa-missing"));
  assert.ok(r.score <= 90);
});

test("cookie без флагов → находки и 90/B", () => {
  const r = calculateScore(
    report({
      headers: {
        ...okHeaders,
        cookieSummary: {
          total: 1,
          secure: 0,
          httpOnly: 0,
          sameSite: 0,
          missingSecure: 1,
          missingHttpOnly: 1,
          missingSameSite: 1,
        },
      },
    }),
  );
  assert.strictEqual(r.score, 90);
  assert.strictEqual(r.grade, "B");
  assert.ok(r.findings.some((f) => f.id === "cookie-no-secure"));
  assert.ok(r.findings.some((f) => f.id === "cookie-no-httponly"));
  assert.ok(r.findings.some((f) => f.id === "cookie-no-samesite"));
});

test("нет security.txt → 98/A + low", () => {
  const r = calculateScore(
    report({ securityTxt: { present: false, status: 404 } }),
  );
  assert.strictEqual(r.score, 98);
  assert.strictEqual(r.grade, "A");
  const finding = r.findings.find((f) => f.id === "security-txt-missing");
  assert.ok(finding);
  assert.strictEqual(finding.severity, "low");
  assert.strictEqual(finding.weight, 2);
});

test("нет web-порта / files null → баллы не теряются", () => {
  const r = calculateScore(report({ files: null, securityTxt: null }));
  assert.strictEqual(r.score, 100);
  assert.strictEqual(r.grade, "A");
});

test("DNS не применим (IP) → баллы не теряются", () => {
  const r = calculateScore(report({ dns: { applicable: false } }));
  assert.strictEqual(r.score, 100);
  assert.strictEqual(r.grade, "A");
});

test("WAF/CMS — информационные находки с weight 0 и без снижения", () => {
  const r = calculateScore(
    report({
      fingerprint: {
        waf: { name: "cloudflare" },
        cms: { name: "wordpress" },
      },
    }),
  );
  assert.strictEqual(r.score, 100);
  assert.strictEqual(r.grade, "A");
  assert.ok(r.findings.some((f) => f.id === "waf-detected"));
  assert.ok(r.findings.some((f) => f.id === "cms-detected"));
  for (const id of ["waf-detected", "cms-detected"]) {
    const finding = r.findings.find((f) => f.id === id);
    assert.strictEqual(finding.weight, 0);
    assert.strictEqual(finding.severity, "low");
  }
});

test("у каждой находки есть OWASP-тег", () => {
  const bad = report({
    ports: [
      { port: 22, status: "open" },
      { port: 3306, status: "open" },
      { port: 8080, status: "open" },
    ],
    ssl: {
      hasSSL: true,
      valid: false,
      daysLeft: 5,
      supportsOldTls: true,
    },
    headers: {
      hsts: false,
      csp: false,
      xframe: false,
      xcontent: false,
      server: "nginx/1.2.3",
      referrerPolicy: false,
      permissionsPolicy: false,
      coop: false,
      corsWildcard: true,
      cookies: [],
      cookieSummary: {
        total: 1,
        secure: 0,
        httpOnly: 0,
        sameSite: 0,
        missingSecure: 1,
        missingHttpOnly: 1,
        missingSameSite: 1,
      },
    },
    dns: {
      applicable: true,
      spf: { present: false, error: "ENODATA" },
      dmarc: {
        present: true,
        policy: "none",
        strict: false,
        weak: true,
        error: null,
      },
      caa: { present: false, records: [], error: "ENODATA" },
    },
    files: {
      exposed: [
        "/.env",
        "/.git/config",
        "/backup.zip",
        "/.DS_Store",
      ],
      blocked: [],
      results: [],
    },
    securityTxt: { present: false, status: 404 },
    fingerprint: {
      waf: { name: "cloudflare" },
      cms: { name: "wordpress" },
    },
  });

  const r = calculateScore(bad);
  assert.ok(r.findings.length > 10);
  for (const finding of r.findings) {
    assert.match(
      finding.owasp,
      /^A\d{2}:2021 /,
      `находка ${finding.id} без OWASP`,
    );
  }
});
