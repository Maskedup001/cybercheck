const test = require("node:test");
const assert = require("node:assert");
const {
  parseSetCookie,
  summarizeCookies,
  analyzeSecurityHeaders,
  detectWaf,
  detectCms,
} = require("../src/probes/header-analysis");

test("parseSetCookie: undefined возвращает пустой массив", () => {
  assert.deepStrictEqual(parseSetCookie(undefined), []);
  assert.deepStrictEqual(parseSetCookie(null), []);
  assert.deepStrictEqual(parseSetCookie(42), []);
});

test("parseSetCookie: строка с Secure, HttpOnly и SameSite=Strict", () => {
  const cookies = parseSetCookie(
    "session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
  );

  assert.strictEqual(cookies.length, 1);
  assert.deepStrictEqual(cookies[0], {
    name: "session",
    secure: true,
    httpOnly: true,
    sameSite: true,
    sameSiteValue: "strict",
  });
  // Значение cookie наружу не отдаётся.
  assert.strictEqual("value" in cookies[0], false);
});

test("parseSetCookie: массив нескольких cookie с разными SameSite", () => {
  const cookies = parseSetCookie([
    "a=1; SameSite=Lax",
    "b=2; Secure; SameSite=None",
    "c=3",
  ]);

  assert.deepStrictEqual(cookies, [
    {
      name: "a",
      secure: false,
      httpOnly: false,
      sameSite: true,
      sameSiteValue: "lax",
    },
    {
      name: "b",
      secure: true,
      httpOnly: false,
      sameSite: true,
      sameSiteValue: "none",
    },
    {
      name: "c",
      secure: false,
      httpOnly: false,
      sameSite: false,
      sameSiteValue: null,
    },
  ]);
});

test("parseSetCookie: регистр флагов, SameSite без значения не считается", () => {
  const cookies = parseSetCookie("x=1; sEcUrE; hTtPoNlY; sAmEsItE");

  assert.deepStrictEqual(cookies, [
    {
      name: "x",
      secure: true,
      httpOnly: true,
      // SameSite без значения браузеры не применяют — это не защита.
      sameSite: false,
      sameSiteValue: null,
    },
  ]);
});

test("parseSetCookie: невалидное SameSite не засчитывается", () => {
  const cookies = parseSetCookie("a=1; SameSite=Foo");

  assert.deepStrictEqual(cookies, [
    { name: "a", secure: false, httpOnly: false, sameSite: false, sameSiteValue: null },
  ]);
});

test("parseSetCookie: мусорные записи не роняют разбор", () => {
  const cookies = parseSetCookie([
    "",
    "   ",
    "=orphan; Secure",
    // Запись без "=" — не cookie: токен не должен попасть в name.
    "nameonly",
    "good=1; Secure",
    42,
    null,
  ]);

  assert.deepStrictEqual(cookies, [
    {
      name: "good",
      secure: true,
      httpOnly: false,
      sameSite: false,
      sameSiteValue: null,
    },
  ]);
});

test("parseSetCookie: точка с запятой в кавычках не ломает разбор", () => {
  const cookies = parseSetCookie('q="a;b"; Secure; SameSite=Lax');

  assert.strictEqual(cookies.length, 1);
  assert.strictEqual(cookies[0].name, "q");
  assert.strictEqual(cookies[0].secure, true);
  assert.strictEqual(cookies[0].sameSiteValue, "lax");
  assert.strictEqual("value" in cookies[0], false);
});

test("summarizeCookies: считает флаги и пропуски", () => {
  const cookies = parseSetCookie([
    "a=1; Secure; HttpOnly; SameSite=Strict",
    "b=2; SameSite=Lax",
    "c=3",
  ]);

  assert.deepStrictEqual(summarizeCookies(cookies), {
    total: 3,
    secure: 1,
    httpOnly: 1,
    sameSite: 2,
    insecureNone: 0,
    missingSecure: 2,
    missingHttpOnly: 2,
    missingSameSite: 1,
  });
});

test("summarizeCookies: SameSite=None без Secure попадает в insecureNone", () => {
  const cookies = parseSetCookie([
    "a=1; SameSite=None",
    "b=2; SameSite=None; Secure",
  ]);

  const summary = summarizeCookies(cookies);
  assert.strictEqual(summary.insecureNone, 1);
  assert.strictEqual(summary.total, 2);
});

test("summarizeCookies: пустой список", () => {
  const empty = {
    total: 0,
    secure: 0,
    httpOnly: 0,
    sameSite: 0,
    insecureNone: 0,
    missingSecure: 0,
    missingHttpOnly: 0,
    missingSameSite: 0,
  };

  assert.deepStrictEqual(summarizeCookies([]), empty);
  assert.deepStrictEqual(summarizeCookies(undefined), empty);
});

test("analyzeSecurityHeaders: все заголовки присутствуют", () => {
  const result = analyzeSecurityHeaders({
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": " strict-origin-when-cross-origin ",
    "permissions-policy": "camera=()",
    "cross-origin-opener-policy": "same-origin",
    "access-control-allow-origin": " * ",
  });

  assert.strictEqual(result.hsts, true);
  assert.strictEqual(result.hstsState, "ok");
  assert.strictEqual(result.csp, true);
  assert.strictEqual(result.cspState, "ok");
  assert.strictEqual(result.xframe, true);
  assert.strictEqual(result.xframeState, "ok");
  assert.strictEqual(result.xcontent, true);
  assert.strictEqual(result.xcontentState, "ok");
  assert.strictEqual(result.referrerPolicy, true);
  assert.strictEqual(result.referrerPolicyState, "ok");
  assert.strictEqual(result.permissionsPolicy, true);
  assert.strictEqual(result.permissionsPolicyState, "ok");
  assert.strictEqual(result.coop, true);
  assert.strictEqual(result.coopState, "ok");
  assert.strictEqual(result.corsWildcard, true);
  assert.strictEqual(result.accessControlAllowOrigin, "*");
});

test("analyzeSecurityHeaders: пустые значения не считаются", () => {
  const result = analyzeSecurityHeaders({
    "strict-transport-security": "  ",
    "content-security-policy": "",
    "x-frame-options": "   ",
    "x-content-type-options": " ",
    "referrer-policy": "  ",
    "permissions-policy": "",
    "cross-origin-opener-policy": "   ",
    "access-control-allow-origin": "  ",
  });

  for (const state of [
    result.hstsState,
    result.cspState,
    result.xframeState,
    result.xcontentState,
    result.referrerPolicyState,
    result.permissionsPolicyState,
    result.coopState,
  ]) {
    assert.strictEqual(state, "missing");
  }

  assert.strictEqual(result.hsts, false);
  assert.strictEqual(result.corsWildcard, false);
  assert.strictEqual(result.accessControlAllowOrigin, null);
});

test("analyzeSecurityHeaders: небезопасные значения дают weak, а не баллы", () => {
  const cases = [
    ["strict-transport-security", "max-age=0", "hsts"],
    ["strict-transport-security", "includeSubDomains", "hsts"],
    ["cross-origin-opener-policy", "unsafe-none", "coop"],
    ["referrer-policy", "unsafe-url", "referrerPolicy"],
    ["x-content-type-options", "foo", "xcontent"],
    ["x-frame-options", "ALLOW-FROM https://example.com", "xframe"],
    ["content-security-policy", "default-src *", "csp"],
    ["content-security-policy", "script-src 'unsafe-inline'", "csp"],
    ["content-security-policy", "img-src 'self'", "csp"],
  ];

  for (const [header, value, field] of cases) {
    const result = analyzeSecurityHeaders({ [header]: value });
    assert.strictEqual(result[`${field}State`], "weak", `${header}: ${value}`);
    assert.strictEqual(result[field], false, `${header}: ${value}`);
  }

  // Безопасные варианты — ok.
  assert.strictEqual(
    analyzeSecurityHeaders({ "referrer-policy": "no-referrer" })
      .referrerPolicyState,
    "ok",
  );
  assert.strictEqual(
    analyzeSecurityHeaders({ "x-frame-options": "sameorigin" }).xframeState,
    "ok",
  );
  assert.strictEqual(
    analyzeSecurityHeaders({ "cross-origin-opener-policy": "same-origin-allow-popups" })
      .coopState,
    "ok",
  );
});

test("analyzeSecurityHeaders: CSP оценивается по эффективной директиве", () => {
  // script-src перекрывает default-src: политика «default-src 'self'»
  // бессмысленна, если ниже разрешены любые скрипты.
  const weakOverride = analyzeSecurityHeaders({
    "content-security-policy": "default-src 'self'; script-src *",
  });
  assert.strictEqual(weakOverride.cspState, "weak");
  assert.strictEqual(weakOverride.csp, false);

  // Обратный случай: строгий script-src при слабом default-src — защита есть.
  const strongOverride = analyzeSecurityHeaders({
    "content-security-policy": "default-src *; script-src 'self'",
  });
  assert.strictEqual(strongOverride.cspState, "ok");

  // inline-скрипты без nonce/hash — основной вектор XSS.
  assert.strictEqual(
    analyzeSecurityHeaders({
      "content-security-policy": "script-src 'self' 'unsafe-inline'",
    }).cspState,
    "weak",
  );

  // nonce рядом с unsafe-inline: браузер игнорирует unsafe-inline, политика рабочая.
  assert.strictEqual(
    analyzeSecurityHeaders({
      "content-security-policy": "script-src 'nonce-abc123' 'unsafe-inline'",
    }).cspState,
    "ok",
  );

  // script-src-elem перекрывает script-src для <script>.
  assert.strictEqual(
    analyzeSecurityHeaders({
      "content-security-policy": "script-src 'self'; script-src-elem *",
    }).cspState,
    "weak",
  );

  // Схема без хоста разрешает любой сайт по этой схеме.
  assert.strictEqual(
    analyzeSecurityHeaders({
      "content-security-policy": "script-src https:",
    }).cspState,
    "weak",
  );

  // Один permissive-источник в объединении перекрывает строгий 'self'.
  for (const value of [
    "script-src 'self' https:",
    "script-src 'self' data:",
    "script-src 'self' https://*",
  ]) {
    assert.strictEqual(
      analyzeSecurityHeaders({ "content-security-policy": value }).cspState,
      "weak",
      value,
    );
  }

  // nonce/hash и конкретный хост остаются строгими.
  assert.strictEqual(
    analyzeSecurityHeaders({
      "content-security-policy": "script-src 'self' 'nonce-abc123'",
    }).cspState,
    "ok",
  );

  // Явный запрет скриптов — ограничение.
  assert.strictEqual(
    analyzeSecurityHeaders({
      "content-security-policy": "script-src 'none'",
    }).cspState,
    "ok",
  );

  // 'none' рядом с другими источниками браузер игнорирует — политика слабая.
  assert.strictEqual(
    analyzeSecurityHeaders({
      "content-security-policy": "script-src 'none' https:",
    }).cspState,
    "weak",
  );
});

test("analyzeSecurityHeaders: Permissions-Policy без ограничений не защищает", () => {
  const cases = [
    ["camera=*", "weak"],
    ["camera", "weak"],
    ["camera=()", "ok"],
    ["camera=(self)", "ok"],
    ["camera=(*)", "weak"],
    ["camera=(\"*\")", "weak"],
    ["geolocation=*, microphone=()", "ok"],
  ];

  for (const [value, expected] of cases) {
    const result = analyzeSecurityHeaders({ "permissions-policy": value });
    assert.strictEqual(result.permissionsPolicyState, expected, value);
    assert.strictEqual(result.permissionsPolicy, expected === "ok", value);
  }
});

test("analyzeSecurityHeaders: ACAO очищается от управляющих и bidi-символов", () => {
  const cleaned = analyzeSecurityHeaders({
    "access-control-allow-origin": "https://x\u202e.com\u0000",
  });
  assert.strictEqual(cleaned.accessControlAllowOrigin, "https://x.com");
  assert.strictEqual(cleaned.corsWildcard, false);

  const long = analyzeSecurityHeaders({
    "access-control-allow-origin": `https://example.com/${"a".repeat(200)}`,
  });
  assert.strictEqual(long.accessControlAllowOrigin.length, 120);

  // Санитизация не должна ломать распознавание wildcard.
  const wildcard = analyzeSecurityHeaders({
    "access-control-allow-origin": "  *  ",
  });
  assert.strictEqual(wildcard.corsWildcard, true);
  assert.strictEqual(wildcard.accessControlAllowOrigin, "*");
});

test("analyzeSecurityHeaders: ACAO со звёздочкой и конкретный origin", () => {
  const wildcard = analyzeSecurityHeaders({
    "access-control-allow-origin": "*",
  });
  assert.strictEqual(wildcard.corsWildcard, true);
  assert.strictEqual(wildcard.accessControlAllowOrigin, "*");

  const specific = analyzeSecurityHeaders({
    "access-control-allow-origin": "https://example.com",
  });
  assert.strictEqual(specific.corsWildcard, false);
  assert.strictEqual(
    specific.accessControlAllowOrigin,
    "https://example.com",
  );
});

test("detectWaf: Cloudflare по cf-ray", () => {
  assert.deepStrictEqual(detectWaf({ "cf-ray": "8a1b2c3d4e5f-MXP" }, []), {
    name: "cloudflare",
    evidence: ["cf-ray"],
  });
});

test("detectWaf: Cloudflare по Server", () => {
  assert.deepStrictEqual(detectWaf({ server: "Cloudflare" }, []), {
    name: "cloudflare",
    evidence: ["server"],
  });
});

test("detectWaf: Cloudflare по cookie", () => {
  const cookies = parseSetCookie("cf_clearance=token; Secure; HttpOnly");

  assert.deepStrictEqual(detectWaf({}, cookies), {
    name: "cloudflare",
    evidence: ["cookie:cf_clearance"],
  });
});

test("detectWaf: Sucuri и Akamai", () => {
  assert.deepStrictEqual(detectWaf({ "x-sucuri-id": "abc123" }, []), {
    name: "sucuri",
    evidence: ["x-sucuri-id"],
  });
  assert.deepStrictEqual(detectWaf({ server: "AkamaiGHost" }, []), {
    name: "akamai",
    evidence: ["server"],
  });
});

test("detectWaf: без признаков", () => {
  const cookies = parseSetCookie("session=abc; Secure; HttpOnly");

  assert.deepStrictEqual(detectWaf({ server: "nginx" }, cookies), {
    name: null,
    evidence: [],
  });
});

test("detectCms: WordPress по meta generator", () => {
  const result = detectCms(
    '<html><head><meta name="generator" content="WordPress 6.4.3"></head></html>',
    {},
    [],
  );

  assert.strictEqual(result.name, "wordpress");
  assert.ok(result.evidence.includes("body:meta-generator"));
});

test("detectCms: WordPress по /wp-content/", () => {
  const result = detectCms(
    '<html><body><img src="/wp-content/uploads/logo.png"></body></html>',
    {},
    [],
  );

  assert.strictEqual(result.name, "wordpress");
  assert.ok(result.evidence.includes("body:wp-content"));
});

test("detectCms: WordPress по cookie", () => {
  const cookies = parseSetCookie(
    "wordpress_test_cookie=WP+Cookie+check; Path=/; HttpOnly",
  );
  const result = detectCms("<html></html>", {}, cookies);

  assert.strictEqual(result.name, "wordpress");
  assert.ok(result.evidence.includes("cookie:wordpress_"));
});

test("detectCms: Drupal", () => {
  const byBody = detectCms(
    '<html><head><meta name="generator" content="Drupal 10"></head></html>',
    {},
    [],
  );
  assert.strictEqual(byBody.name, "drupal");
  assert.ok(byBody.evidence.includes("body:meta-generator"));

  const byHeader = detectCms(
    "<html></html>",
    { "x-generator": "Drupal 10 (https://www.drupal.org)" },
    [],
  );
  assert.strictEqual(byHeader.name, "drupal");
  assert.ok(byHeader.evidence.includes("header:x-generator"));
});

test("detectCms: Joomla", () => {
  const result = detectCms(
    '<html><body><script src="/media/system/js/core.js"></script></body></html>',
    {},
    [],
  );

  assert.strictEqual(result.name, "joomla");
  assert.ok(result.evidence.includes("body:media-system-js"));
});

test("detectCms: Bitrix", () => {
  const result = detectCms(
    '<html><body><img src="/bitrix/templates/logo.png"></body></html>',
    {},
    [],
  );

  assert.strictEqual(result.name, "bitrix");
  assert.ok(result.evidence.includes("body:bitrix"));
});

test("detectCms: обычный HTML не даёт ложного срабатывания", () => {
  const cookies = parseSetCookie(
    "session=abc; Secure; HttpOnly; SameSite=Lax",
  );
  const result = detectCms(
    "<html><body><h1>Hello</h1><p>No CMS here.</p></body></html>",
    { server: "nginx" },
    cookies,
  );

  assert.deepStrictEqual(result, { name: null, evidence: [] });
});

test("detectCms: meta content=drupal без name=generator не считается", () => {
  const result = detectCms(
    '<html><head><meta name="description" content="Drupal hosting"></head></html>',
    {},
    [],
  );

  assert.strictEqual(result.name, null);
});
