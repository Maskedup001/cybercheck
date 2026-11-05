const test = require("node:test");
const assert = require("node:assert");
const { calculateScore, WEIGHTS } = require("../src/scoring");
const { analyzeSecurityHeaders } = require("../src/header-analysis");

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

test("ошибка TLS при подтверждённом HTTPS не ставит потолок 60", () => {
  const r = calculateScore(
    report({
      ssl: { hasSSL: false, error: "HANDSHAKE_FAILED", tlsConfirmed: true },
    }),
  );

  assert.ok(!r.findings.some((f) => f.id === "ssl-error"));
  assert.ok(!r.findings.some((f) => f.id === "no-ssl"));

  const finding = r.findings.find((f) => f.id === "ssl-unverified");
  assert.ok(finding);
  assert.strictEqual(finding.severity, "medium");
  assert.match(finding.title, /Сертификат не проверен/);

  // Баллы за TLS (12), HSTS (8) и срок сертификата (3) не начисляются:
  // валидность TLS неизвестна. Но жёсткого потолка 60 нет — сайт реально
  // ответил по HTTPS, поэтому 100 - 23 = 77, а не 60.
  assert.strictEqual(r.score, 77);
  assert.ok(r.score > 60);
});

test("CSP с wildcard в script-src не даёт 10 баллов", () => {
  // Проверка идёт через реальный разбор заголовка: scoring должен получать
  // csp=false и weak-находку, а не верить факту присутствия заголовка.
  const analyzed = analyzeSecurityHeaders({
    "content-security-policy": "default-src 'self'; script-src *",
  });

  const r = calculateScore(
    report({
      headers: { ...okHeaders, csp: analyzed.csp, cspState: analyzed.cspState },
    }),
  );

  assert.ok(r.findings.some((f) => f.id === "weak-csp"));
  assert.ok(!r.findings.some((f) => f.id === "no-csp"));
  assert.strictEqual(r.score, 90);
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

// --- Недоступный хост не получает ложный no-ssl -------------

test("NO_WEB_PORT → нет no-ssl и потолка 30, есть tls-not-checked", () => {
  const r = calculateScore(
    report({
      ports: [],
      ssl: { hasSSL: false, error: "NO_WEB_PORT" },
      headers: { error: true },
      files: null,
      securityTxt: null,
    }),
  );

  assert.ok(!r.findings.some((f) => f.id === "no-ssl"));
  assert.ok(r.findings.some((f) => f.id === "tls-not-checked"));
  assert.ok(!r.findings.some((f) => f.id === "ssl-error"));
  assert.ok(r.score > 30, `потолок 30 применён не должен быть: ${r.score}`);
  assert.ok(r.score <= 60);
});

test("только 22/3306 без веб-портов — тоже NO_WEB_PORT", () => {
  const r = calculateScore(
    report({
      ports: [{ port: 22, status: "open" }],
      ssl: { hasSSL: false, error: "NO_WEB_PORT" },
      headers: { error: true },
    }),
  );

  assert.ok(!r.findings.some((f) => f.id === "no-ssl"));
  assert.ok(r.findings.some((f) => f.id === "tls-not-checked"));
});

// --- Точность DNS-начислений -----------------

test("две SPF-записи → spf-multiple и 0 баллов", () => {
  const r = calculateScore(
    report({
      dns: {
        ...okDns,
        spf: {
          present: true,
          record: "v=spf1 -all",
          multiple: true,
          weak: false,
          error: null,
        },
      },
    }),
  );

  const finding = r.findings.find((f) => f.id === "spf-multiple");
  assert.ok(finding);
  assert.strictEqual(finding.weight, WEIGHTS.spf);
  assert.ok(!r.findings.some((f) => f.id === "spf-missing"));
  // 100 - 4 = 96, но medium-находка опускает потолок до 90.
  assert.strictEqual(r.score, 90);
});

test("SPF +all → spf-weak и 0 баллов", () => {
  const r = calculateScore(
    report({
      dns: {
        ...okDns,
        spf: {
          present: true,
          record: "v=spf1 +all",
          multiple: false,
          weak: true,
          error: null,
        },
      },
    }),
  );

  assert.ok(r.findings.some((f) => f.id === "spf-weak"));
  assert.strictEqual(r.score, 90);
});

test("две DMARC-записи → dmarc-multiple и 0 баллов", () => {
  const r = calculateScore(
    report({
      dns: {
        ...okDns,
        dmarc: {
          present: true,
          record: "v=DMARC1; p=reject",
          policy: "reject",
          strict: true,
          weak: false,
          multiple: true,
          error: null,
        },
      },
    }),
  );

  assert.ok(r.findings.some((f) => f.id === "dmarc-multiple"));
  assert.ok(!r.findings.some((f) => f.id === "dmarc-invalid"));
  // 100 - 3 = 97, потолок для medium-находки — 90.
  assert.strictEqual(r.score, 90);
});

test("CAA только с iodef → «не ограничивает», а не «нет CAA»", () => {
  const r = calculateScore(
    report({
      dns: {
        ...okDns,
        caa: {
          present: true,
          records: [{ critical: 0, iodef: "mailto:security@example.com" }],
          restrictive: false,
          error: null,
        },
      },
    }),
  );

  const finding = r.findings.find((f) => f.id === "caa-not-restrictive");
  assert.ok(finding);
  assert.match(finding.title, /не ограничивает/);
  assert.ok(!r.findings.some((f) => f.id === "caa-missing"));
  assert.strictEqual(r.score, 98);
});

test("CAA нет вовсе → caa-missing", () => {
  const r = calculateScore(
    report({
      dns: {
        ...okDns,
        caa: { present: false, records: [], restrictive: false, error: "ENODATA" },
      },
    }),
  );

  assert.ok(r.findings.some((f) => f.id === "caa-missing"));
  assert.ok(!r.findings.some((f) => f.id === "caa-not-restrictive"));
  assert.strictEqual(r.score, 98);
});

test("apex ENOTFOUND — нейтрально, _dmarc ENOTFOUND — отсутствие записи", () => {
  const r = calculateScore(
    report({
      dns: {
        applicable: true,
        spf: { present: false, multiple: false, weak: false, error: "ENOTFOUND" },
        dmarc: {
          present: false,
          policy: null,
          strict: false,
          weak: false,
          multiple: false,
          error: "ENOTFOUND",
        },
        caa: { present: false, records: [], restrictive: false, error: "ENOTFOUND" },
      },
    }),
  );

  assert.ok(!r.findings.some((f) => f.id === "spf-missing"));
  assert.ok(!r.findings.some((f) => f.id === "caa-missing"));
  assert.ok(r.findings.some((f) => f.id === "dmarc-missing"));
});

// --- Значения заголовков ------------------------------------------

test("небезопасные значения заголовков не дают баллов и дают weak-находки", () => {
  const r = calculateScore(
    report({
      headers: {
        ...okHeaders,
        hsts: false,
        hstsState: "weak",
        csp: false,
        cspState: "weak",
        xframe: false,
        xframeState: "weak",
        xcontent: false,
        xcontentState: "weak",
        referrerPolicy: false,
        referrerPolicyState: "weak",
        coop: false,
        coopState: "weak",
      },
    }),
  );

  const ids = r.findings.map((f) => f.id);
  for (const id of [
    "weak-hsts",
    "weak-csp",
    "weak-xframe",
    "weak-xcontent",
    "weak-referrer-policy",
    "weak-coop",
  ]) {
    assert.ok(ids.includes(id), `ожидали ${id}, получили ${ids.join(", ")}`);
  }

  assert.ok(!ids.includes("no-hsts"));
  // 8+10+6+6+2+2 = 34 балла не начислены.
  assert.ok(r.score <= 66, `score=${r.score}`);
});

// --- Упавшие HEAD-пробы не начисляют баллы -------------------------

test("все HEAD-пробы упали → баллы за файлы не начисляются, находок нет", () => {
  const failed = (path) => ({
    path,
    status: null,
    exposed: false,
    blocked: false,
    error: "ETIMEDOUT",
  });

  const r = calculateScore(
    report({
      files: {
        exposed: [],
        blocked: [],
        results: [
          failed("/.env"),
          failed("/.git/config"),
          failed("/.DS_Store"),
          failed("/backup.zip"),
        ],
      },
    }),
  );

  assert.ok(!r.findings.some((f) => f.id.startsWith("exposed-")));
  // 7+4+2+1 не начислены: неизвестно, открыты ли пути.
  assert.strictEqual(r.score, 86);
});

// --- Мусорный вход не бросает -------------------------------------

test("calculateScore(null) и мусорные ports не бросают", () => {
  assert.doesNotThrow(() => calculateScore(null));
  assert.doesNotThrow(() => calculateScore(undefined));
  assert.doesNotThrow(() => calculateScore("garbage"));

  const r = calculateScore(
    report({ ports: [null, 42, { port: 22, status: "open" }] }),
  );
  assert.strictEqual(typeof r.score, "number");
  assert.ok(r.findings.some((f) => f.id === "port-22"));
});

// --- Cookie -------------------------------------------------

test("Secure не начисляется при ssl.error", () => {
  const cookies = {
    total: 1,
    secure: 0,
    httpOnly: 1,
    sameSite: 1,
    insecureNone: 0,
    missingSecure: 1,
    missingHttpOnly: 0,
    missingSameSite: 0,
  };

  const r = calculateScore(
    report({
      ssl: { hasSSL: false, error: "HANDSHAKE_FAILED" },
      headers: { ...okHeaders, cookieSummary: cookies },
    }),
  );

  assert.ok(!r.findings.some((f) => f.id === "cookie-no-secure"));
});

test("SameSite=None без Secure → отдельная находка", () => {
  const r = calculateScore(
    report({
      headers: {
        ...okHeaders,
        cookieSummary: {
          total: 1,
          secure: 0,
          httpOnly: 1,
          sameSite: 1,
          insecureNone: 1,
          missingSecure: 1,
          missingHttpOnly: 0,
          missingSameSite: 0,
        },
      },
    }),
  );

  assert.ok(
    r.findings.some((f) => f.id === "cookie-samesite-none-insecure"),
  );
});

// --- Порядок находок по severity -----------------------------------

test("находки отсортированы по severity, затем по весу", () => {
  const r = calculateScore(
    report({
      headers: { ...okHeaders, csp: false, referrerPolicy: false },
    }),
  );

  const ranks = r.findings.map((f) =>
    f.severity === "high" ? 0 : f.severity === "medium" ? 1 : 2,
  );

  for (let i = 1; i < ranks.length; i += 1) {
    assert.ok(ranks[i - 1] <= ranks[i], `порядок severity нарушен: ${ranks}`);
  }
});

