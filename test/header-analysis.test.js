const test = require("node:test");
const assert = require("node:assert");
const {
  parseSetCookie,
  summarizeCookies,
  analyzeSecurityHeaders,
  detectWaf,
  detectCms,
} = require("../src/header-analysis");

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

test("parseSetCookie: регистр флагов и SameSite без значения", () => {
  const cookies = parseSetCookie("x=1; sEcUrE; hTtPoNlY; sAmEsItE");

  assert.deepStrictEqual(cookies, [
    {
      name: "x",
      secure: true,
      httpOnly: true,
      sameSite: true,
      sameSiteValue: null,
    },
  ]);
});

test("parseSetCookie: мусорные записи не роняют разбор", () => {
  const cookies = parseSetCookie([
    "",
    "   ",
    "=orphan; Secure",
    "nameonly",
    "good=1; Secure",
    42,
    null,
  ]);

  assert.deepStrictEqual(cookies, [
    {
      name: "nameonly",
      secure: false,
      httpOnly: false,
      sameSite: false,
      sameSiteValue: null,
    },
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
    missingSecure: 2,
    missingHttpOnly: 2,
    missingSameSite: 1,
  });
});

test("summarizeCookies: пустой список", () => {
  assert.deepStrictEqual(summarizeCookies([]), {
    total: 0,
    secure: 0,
    httpOnly: 0,
    sameSite: 0,
    missingSecure: 0,
    missingHttpOnly: 0,
    missingSameSite: 0,
  });
  assert.deepStrictEqual(summarizeCookies(undefined), {
    total: 0,
    secure: 0,
    httpOnly: 0,
    sameSite: 0,
    missingSecure: 0,
    missingHttpOnly: 0,
    missingSameSite: 0,
  });
});

test("analyzeSecurityHeaders: все заголовки присутствуют", () => {
  const result = analyzeSecurityHeaders({
    "referrer-policy": " strict-origin-when-cross-origin ",
    "permissions-policy": "camera=()",
    "cross-origin-opener-policy": "same-origin",
    "access-control-allow-origin": " * ",
  });

  assert.deepStrictEqual(result, {
    referrerPolicy: true,
    permissionsPolicy: true,
    coop: true,
    corsWildcard: true,
    accessControlAllowOrigin: "*",
  });
});

test("analyzeSecurityHeaders: пустые значения не считаются", () => {
  const result = analyzeSecurityHeaders({
    "referrer-policy": "  ",
    "permissions-policy": "",
    "cross-origin-opener-policy": "   ",
    "access-control-allow-origin": "  ",
  });

  assert.deepStrictEqual(result, {
    referrerPolicy: false,
    permissionsPolicy: false,
    coop: false,
    corsWildcard: false,
    accessControlAllowOrigin: null,
  });
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
