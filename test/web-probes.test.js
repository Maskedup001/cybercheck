const http = require("node:http");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  request,
  checkSensitiveFiles,
  checkSecurityTxt,
  checkFingerprint,
} = require("../src/probes/web-probes");
const { BROWSER_UA } = require("../src/probes/http-headers");

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

test("checkSensitiveFiles: 200 с сигнатурой — exposed, 403 — blocked, 404 — ни то ни другое", async (t) => {
  const statusByPath = new Map([
    ["/.env", 200],
    ["/.git/config", 403],
    ["/.DS_Store", 404],
    ["/backup.zip", 301],
  ]);
  const bodyByPath = new Map([["/.env", "APP_KEY=secret\nDEBUG=false\n"]]);

  const server = await startServer((req, res) => {
    res.statusCode = statusByPath.get(req.url) ?? 404;
    res.end(bodyByPath.get(req.url) ?? "");
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

test("checkSensitiveFiles: экспозиция подтверждается сигнатурой каждого файла", async (t) => {
  // 200 сам по себе ничего не доказывает: тело должно быть настоящим
  // файлом утечки, а не HTML-заглушкой SPA.
  const bodyByPath = new Map([
    ["/.env", "DB_HOST=localhost\nDB_USER=root\n"],
    ["/.git/config", "[core]\n\trepositoryformatversion = 0\n"],
    ["/backup.zip", Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00])],
    [
      "/.DS_Store",
      Buffer.concat([
        Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31]),
        Buffer.from([0, 0, 0, 0]),
      ]),
    ],
  ]);

  const server = await startServer((req, res) => {
    res.statusCode = 200;
    res.end(bodyByPath.get(req.url) ?? "");
  });
  t.after(() => server.close());

  const result = await checkSensitiveFiles(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.deepEqual(result.exposed, [
    "/.env",
    "/.git/config",
    "/.DS_Store",
    "/backup.zip",
  ]);
  assert.deepEqual(result.blocked, []);
  for (const item of result.results) {
    assert.equal(item.status, 200, item.path);
    assert.equal(item.exposed, true, item.path);
    assert.equal(item.error, null, item.path);
  }
});

test("checkSensitiveFiles: 200 без сигнатуры — NO_SIGNATURE, а не exposed", async (t) => {
  // SPA/catch-all отдаёт 200 HTML на любой путь: это «не проверено», а не
  // «открыто» и не «закрыто».
  const server = await startServer((req, res) => {
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.end("<!doctype html><html><body><input value=\"x\"></body></html>");
  });
  t.after(() => server.close());

  const result = await checkSensitiveFiles(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.deepEqual(result.exposed, []);
  assert.deepEqual(result.blocked, []);
  for (const item of result.results) {
    assert.equal(item.status, 200, item.path);
    assert.equal(item.exposed, false, item.path);
    assert.equal(item.error, "NO_SIGNATURE", item.path);
  }
});

test("checkSensitiveFiles: использует GET для всех путей", async (t) => {
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
    seen.every((entry) => entry.method === "GET"),
    `Ожидали только GET, получили: ${seen.map((entry) => entry.method).join(", ")}`,
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
    if (status === 200) {
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end("Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n");
      return;
    }
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
    truncated: false,
    hasContact: true,
    hasExpires: true,
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
    truncated: false,
    hasContact: false,
    hasExpires: false,
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
    truncated: false,
    hasContact: false,
    hasExpires: false,
  });

  // 200 — один запрос, 404/410 — плюс legacy-путь, 403 — один.
  assert.deepEqual(accepts, [
    "text/plain",
    "text/plain",
    "text/plain",
    "text/plain",
  ]);
});

test("checkSecurityTxt: 200 с HTML-заглушкой не считается security.txt", async (t) => {
  const server = await startServer((req, res) => {
    // SPA/catch-all отдаёт 200 HTML на любой путь — это не security.txt.
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.end("<!doctype html><html><body>Not found</body></html>");
  });
  t.after(() => server.close());

  const result = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(result.status, 200);
  assert.equal(result.present, false);
  assert.equal(result.blocked, false);
  assert.equal(result.error, null);
});

test("checkSecurityTxt: 200 text/plain без Contact тоже не security.txt", async (t) => {
  const server = await startServer((req, res) => {
    res.setHeader("content-type", "text/plain");
    res.end("hello\n");
  });
  t.after(() => server.close());

  const result = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(result.status, 200);
  assert.equal(result.present, false);
  assert.equal(result.error, null);
  assert.equal(result.truncated, false);
});

test("checkSecurityTxt: обрезанное тело без Contact — TRUNCATED, не «нет»", async (t) => {
  const server = await startServer((req, res) => {
    res.setHeader("content-type", "text/plain");
    // 40 КБ > лимита 32 КБ, Contact в прочитанную часть не попадает.
    res.end("padding ".repeat(5000));
  });
  t.after(() => server.close());

  const result = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(result.status, 200);
  assert.equal(result.present, false);
  assert.equal(result.blocked, false);
  // Обрезка — «не проверено», а не «файла нет» и не «файл некорректен».
  assert.equal(result.error, "TRUNCATED");
  assert.equal(result.truncated, true);
});

test("checkSecurityTxt: Contact в начале обрезанного тела даёт present", async (t) => {
  const server = await startServer((req, res) => {
    res.setHeader("content-type", "text/plain");
    res.end(
      "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n" +
        "padding ".repeat(5000),
    );
  });
  t.after(() => server.close());

  const result = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.equal(result.status, 200);
  assert.equal(result.present, true);
  assert.equal(result.error, null);
  assert.equal(result.truncated, true);
});

test("checkSecurityTxt: legacy /security.txt используется, если well-known нет", async (t) => {
  const server = await startServer((req, res) => {
    if (req.url === "/security.txt") {
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end(
        "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n",
      );
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  t.after(() => server.close());

  const result = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.strictEqual(result.path, "/security.txt");
  assert.strictEqual(result.status, 200);
  assert.strictEqual(result.present, true);
});

test("checkSecurityTxt: без Expires файл считается некорректным", async (t) => {
  const server = await startServer((req, res) => {
    res.setHeader("content-type", "text/plain");
    res.end("Contact: mailto:security@example.com\n");
  });
  t.after(() => server.close());

  const result = await checkSecurityTxt(
    "127.0.0.1",
    server.port,
    "localhost",
    false,
  );

  assert.strictEqual(result.status, 200);
  assert.strictEqual(result.present, false);
  assert.strictEqual(result.hasContact, true);
  assert.strictEqual(result.hasExpires, false);
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
  // Проба обязана представляться браузером: предсказуемый UA сканера
  // позволяет цели отдавать ей другой ответ (клоакинг).
  assert.equal(captured.userAgent, BROWSER_UA);
  assert.ok(!captured.userAgent.includes("CyberCheck"));
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
      // Не 100 мс: на загруженном CI короткий таймаут срабатывал раньше,
      // чем сервер успевал принять соединение, и тест флейкал.
      timeoutMs: 400,
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

test("request: нелитеральный connectIp отклоняется fail-closed", async () => {
  // Имя хоста увело бы http.request в собственный DNS-резолв (SSRF).
  for (const connectIp of ["example.com", "localhost", undefined, ""]) {
    const result = await request({
      method: "GET",
      path: "/",
      connectIp,
      port: 80,
      hostname: "example.com",
      hasTls: false,
      timeoutMs: 100,
    });

    assert.equal(result.status, null, String(connectIp));
    assert.equal(result.error, "INVALID_CONNECT_IP", String(connectIp));
  }
});

test("request: таймаут тела сохраняет статус и заголовки", async (t) => {
  const server = await startServer((req, res) => {
    res.writeHead(200, {
      "content-type": "text/html",
      "cf-ray": "8f2a1b3c4d5e6f70-FRA",
    });
    res.write("<html><body>partial");
    // Тело не завершаем: проверяем, что таймаут не стирает уже полученное.
  });
  t.after(() => server.close());

  const result = await request({
    method: "GET",
    path: "/",
    connectIp: "127.0.0.1",
    port: server.port,
    hostname: "localhost",
    hasTls: false,
    readBody: true,
    timeoutMs: 400,
  });

  assert.equal(result.status, 200);
  assert.equal(result.headers["cf-ray"], "8f2a1b3c4d5e6f70-FRA");
  assert.match(result.body, /partial/);
  assert.equal(result.error, "ETIMEDOUT");
});

test("request: bodyBuffer содержит ровно прочитанные байты и признак обрезки", async (t) => {
  const server = await startServer((req, res) => {
    res.setHeader("content-type", "text/plain");
    res.end("abcdefgh");
  });
  t.after(() => server.close());

  const result = await request({
    method: "GET",
    path: "/",
    connectIp: "127.0.0.1",
    port: server.port,
    hostname: "localhost",
    hasTls: false,
    readBody: true,
    maxBody: 5,
    timeoutMs: 2000,
  });

  assert.equal(result.error, null);
  assert.equal(result.body, "abcde");
  // Байты, а не строка: сигнатуры файлов сравнивают бинарные начала.
  assert.ok(Buffer.isBuffer(result.bodyBuffer));
  assert.deepEqual(result.bodyBuffer, Buffer.from("abcde"));
  assert.equal(result.bodyBuffer.length, 5);
  assert.equal(result.truncated, true);
});

test("request: полное тело не помечается обрезанным", async (t) => {
  const server = await startServer((req, res) => {
    res.setHeader("content-type", "text/plain");
    res.end("hello");
  });
  t.after(() => server.close());

  const result = await request({
    method: "GET",
    path: "/",
    connectIp: "127.0.0.1",
    port: server.port,
    hostname: "localhost",
    hasTls: false,
    readBody: true,
    maxBody: 1024,
    timeoutMs: 2000,
  });

  assert.equal(result.error, null);
  assert.equal(result.body, "hello");
  assert.deepEqual(result.bodyBuffer, Buffer.from("hello"));
  assert.equal(result.truncated, false);
});

test("request: same-origin редирект преследуется, чужой origin — нет", async (t) => {
  const visited = [];

  const server = await startServer((req, res) => {
    visited.push(req.url);

    if (req.url === "/start") {
      res.statusCode = 302;
      res.setHeader("Location", "/final");
      res.end();
      return;
    }

    if (req.url === "/final") {
      res.statusCode = 200;
      res.end("final-body");
      return;
    }

    // Уводит на другой хост: такой переход выполнять нельзя.
    res.statusCode = 301;
    res.setHeader("Location", "http://example.test/elsewhere");
    res.end();
  });
  t.after(() => server.close());

  const followed = await request({
    path: "/start",
    connectIp: "127.0.0.1",
    port: server.port,
    hostname: "localhost",
    hasTls: false,
    readBody: true,
    timeoutMs: 2000,
  });

  assert.equal(followed.status, 200);
  assert.equal(followed.body, "final-body");
  assert.deepEqual(visited, ["/start", "/final"]);

  visited.length = 0;
  const crossOrigin = await request({
    path: "/offsite",
    connectIp: "127.0.0.1",
    port: server.port,
    hostname: "localhost",
    hasTls: false,
    timeoutMs: 2000,
  });

  // На чужой origin запрос не уходит: отдаётся сам редирект.
  assert.equal(crossOrigin.status, 301);
  assert.deepEqual(visited, ["/offsite"]);
});

test("request: не больше трёх переходов, цикл не зацикливает пробу", async (t) => {
  const visited = [];

  const server = await startServer((req, res) => {
    visited.push(req.url);
    // Бесконечная цепочка: каждый путь ведёт на следующий.
    const n = Number(/\d+/.exec(req.url)?.[0] || 0);
    res.statusCode = 302;
    res.setHeader("Location", `/hop-${n + 1}`);
    res.end();
  });
  t.after(() => server.close());

  const result = await request({
    path: "/hop-0",
    connectIp: "127.0.0.1",
    port: server.port,
    hostname: "localhost",
    hasTls: false,
    timeoutMs: 2000,
  });

  // Четыре запроса: исходный и три разрешённых перехода.
  assert.deepEqual(visited, ["/hop-0", "/hop-1", "/hop-2", "/hop-3"]);
  assert.equal(result.status, 302);
  assert.equal(result.error, null);
});
