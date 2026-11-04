const http = require("node:http");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const pkg = require("../package.json");
const {
  request,
  checkSensitiveFiles,
  checkSecurityTxt,
  checkFingerprint,
} = require("../src/web-probes");

// Локальный сервер только на 127.0.0.1; порт всегда случайный.
// Уничтожаем открытые сокеты перед close(), иначе keep-alive/зависшие
// соединения могут задержать завершение теста.
async function startServer(handler) {
  const server = http.createServer(handler);
  const sockets = new Set();

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    const onError = (err) => reject(err);
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", onError);
      resolve();
    });
  });

  return {
    port: server.address().port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

test("checkSensitiveFiles: 200 — exposed, 403 — blocked, 404 — ни то ни другое", async (t) => {
  const statusByPath = new Map([
    ["/.env", 200],
    ["/.git/config", 403],
    ["/.DS_Store", 404],
    ["/backup.zip", 301],
  ]);

  const server = await startServer((req, res) => {
    res.statusCode = statusByPath.get(req.url) ?? 404;
    res.end();
  });
  t.after(() => server.close());

  const result = await checkSensitiveFiles(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(result.port, server.port);
  assert.equal(result.protocol, "HTTP");
  assert.deepEqual(result.results.map((item) => item.path), [
    "/.env",
    "/.git/config",
    "/.DS_Store",
    "/backup.zip",
  ]);
  assert.deepEqual(result.exposed, ["/.env"]);
  assert.deepEqual(result.blocked, ["/.git/config"]);

  assert.deepEqual(result.results.find((item) => item.path === "/.env"), {
    path: "/.env",
    status: 200,
    exposed: true,
    blocked: false,
    error: null,
  });
  assert.deepEqual(
    result.results.find((item) => item.path === "/.git/config"),
    {
      path: "/.git/config",
      status: 403,
      exposed: false,
      blocked: true,
      error: null,
    },
  );

  for (const path of ["/.DS_Store", "/backup.zip"]) {
    const item = result.results.find((entry) => entry.path === path);
    assert.equal(item.exposed, false);
    assert.equal(item.blocked, false);
    assert.equal(item.error, null);
  }
});

test("checkSensitiveFiles: использует HEAD для всех путей", async (t) => {
  const seen = [];
  const server = await startServer((req, res) => {
    seen.push({ method: req.method, url: req.url });
    res.statusCode = 404;
    res.end();
  });
  t.after(() => server.close());

  await checkSensitiveFiles("127.0.0.1", server.port, "localhost", false);

  assert.equal(seen.length, 4);
  assert.ok(
    seen.every((entry) => entry.method === "HEAD"),
    `Ожидали только HEAD, получили: ${seen.map((entry) => entry.method).join(", ")}`,
  );
  assert.deepEqual(
    seen.map((entry) => entry.url).sort(),
    ["/.env", "/.git/config", "/.DS_Store", "/backup.zip"].sort(),
  );
});

test("checkSecurityTxt: 200 — present, 404 — absent, 403 — blocked", async (t) => {
  let status = 200;
  const accepts = [];

  const server = await startServer((req, res) => {
    accepts.push(req.headers.accept);
    res.statusCode = status;
    res.end();
  });
  t.after(() => server.close());

  const present = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );
  assert.deepEqual(present, {
    path: "/.well-known/security.txt",
    status: 200,
    present: true,
    blocked: false,
    error: null,
  });

  status = 404;
  const absent = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );
  assert.deepEqual(absent, {
    path: "/.well-known/security.txt",
    status: 404,
    present: false,
    blocked: false,
    error: null,
  });

  status = 403;
  const blocked = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );
  assert.deepEqual(blocked, {
    path: "/.well-known/security.txt",
    status: 403,
    present: false,
    blocked: true,
    error: null,
  });

  assert.deepEqual(accepts, ["text/plain", "text/plain", "text/plain"]);
});

test("checkFingerprint: находит WordPress и Cloudflare и не даёт ложных срабатываний", async (t) => {
  const wordpressHtml = [
    "<!doctype html>",
    '<html><head><meta name="generator" content="WordPress 6.6.2">',
    "<title>Example</title></head>",
    "<body>Hello</body></html>",
  ].join("");

  let body = wordpressHtml;
  let cfRay = "8f2a1b3c4d5e6f70-FRA";

  const server = await startServer((req, res) => {
    if (cfRay) res.setHeader("cf-ray", cfRay);
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.end(body);
  });
  t.after(() => server.close());

  const hit = await checkFingerprint(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(hit.status, 200);
  assert.equal(hit.error, null);
  assert.equal(hit.server, null);
  assert.equal(hit.bodyBytes, Buffer.byteLength(wordpressHtml, "utf8"));
  assert.ok(hit.waf, "WAF должен определяться по cf-ray");
  assert.match(hit.waf.name, /cloudflare/i);
  assert.ok(hit.waf.evidence);
  assert.ok(hit.cms, "CMS должен определяться по meta generator");
  assert.match(hit.cms.name, /wordpress/i);
  assert.ok(hit.cms.evidence);

  cfRay = null;
  body = "<html><head><title>Plain</title></head><body>Hello</body></html>";

  const clean = await checkFingerprint(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(clean.status, 200);
  assert.equal(clean.error, null);
  assert.equal(clean.waf, null);
  assert.equal(clean.cms, null);
  assert.equal(clean.server, null);
  assert.equal(clean.bodyBytes, Buffer.byteLength(body, "utf8"));
});

test("checkFingerprint: при не-200 WAF остаётся, CMS без тела — null", async (t) => {
  const server = await startServer((req, res) => {
    res.statusCode = 403;
    res.setHeader("cf-ray", "8f2a1b3c4d5e6f70-FRA");
    res.end();
  });
  t.after(() => server.close());

  const result = await checkFingerprint(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(result.status, 403);
  assert.equal(result.error, null);
  assert.ok(result.waf);
  assert.match(result.waf.name, /cloudflare/i);
  assert.equal(result.cms, null);
  assert.equal(result.bodyBytes, 0);
});

test("request: Host содержит порт, подключение идёт на connectIp", async (t) => {
  let captured = null;

  const server = await startServer((req, res) => {
    captured = {
      method: req.method,
      url: req.url,
      host: req.headers.host,
      userAgent: req.headers["user-agent"],
      remoteAddress: req.socket.remoteAddress,
    };
    res.statusCode = 200;
    res.end("ok");
  });
  t.after(() => server.close());

  const result = await request({
    method: "GET",
    path: "/probe",
    connectIp: "127.0.0.1",
    port: server.port,
    // Имя заведомо не резолвится: успех возможен только через connectIp.
    hostname: "example.test",
    hasTls: false,
    timeoutMs: 2000,
  });

  assert.equal(result.status, 200);
  assert.equal(result.protocol, "HTTP");
  assert.equal(result.error, null);
  assert.ok(captured);
  assert.equal(captured.method, "GET");
  assert.equal(captured.url, "/probe");
  assert.equal(captured.host, `example.test:${server.port}`);
  assert.equal(captured.userAgent, `CyberCheck/${pkg.version}`);
  assert.match(captured.remoteAddress, /127\.0\.0\.1$/);
});

test("request: таймаут возвращает ошибку, не бросает", async (t) => {
  // Сервер принимает соединение, но никогда не отвечает.
  const server = await startServer(() => {});
  t.after(() => server.close());

  let result;
  await assert.doesNotReject(async () => {
    result = await request({
      method: "GET",
      path: "/",
      connectIp: "127.0.0.1",
      port: server.port,
      hostname: "localhost",
      hasTls: false,
      timeoutMs: 100,
    });
  });

  assert.equal(result.status, null);
  assert.deepEqual(result.headers, {});
  assert.equal(result.body, "");
  assert.equal(result.protocol, "HTTP");
  assert.equal(result.error, "ETIMEDOUT");
});

test("request: AbortSignal возвращает ошибку, не бросает", async (t) => {
  // Сервер принимает соединение, но никогда не отвечает.
  const server = await startServer(() => {});
  t.after(() => server.close());

  const controller = new AbortController();
  const pending = request({
    method: "GET",
    path: "/",
    connectIp: "127.0.0.1",
    port: server.port,
    hostname: "localhost",
    hasTls: false,
    signal: controller.signal,
    timeoutMs: 2000,
  });

  const abortTimer = setTimeout(() => controller.abort(), 20);

  let result;
  await assert.doesNotReject(async () => {
    result = await pending;
  });
  clearTimeout(abortTimer);

  assert.equal(result.status, null);
  assert.deepEqual(result.headers, {});
  assert.equal(result.body, "");
  assert.equal(result.protocol, "HTTP");
  assert.equal(result.error, "ABORT_ERR");
});
