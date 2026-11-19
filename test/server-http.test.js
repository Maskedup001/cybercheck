const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const net = require("node:net");
const { issueConsentToken, createHttpServer } = require("../src/core/server");
const { readConfig } = require("../src/core/config");

// HTTP-слой проверяется на живом сервере, но в том же процессе: приложение
// поднимается на случайном порту через createHttpServer, а тесты ходят в него
// через fetch. Отдельный процесс здесь не нужен и недоступен: spawn в
// песочнице запрещён, а из чужого процесса не видно реальных свойств server.
//
// 503 (потолок одновременных сканов) и 504 (таймаут скана) здесь не
// проверяются: чтобы получить их, нужны 25 параллельных сканов или
// зависший TLS-сервер, то есть подмена внутренних проверок. Это отдельная
// задача с внедрением зависимостей, а не HTTP-контракт.
const TEST_ENV = {
  TRUST_PROXY: "0",
  PUBLIC_ORIGIN: "http://localhost:3000",
  PORT: "0",
  NODE_ENV: "test",
  DEMO_MODE: "false",
};

// Потолок сокетов с одного адреса при прямом доступе (MAX_SOCKETS_PER_IP).
const MAX_SOCKETS_PER_IP = 64;

let server = null;
let limiter = null;
let baseUrl = null;

function listen(overrides = {}) {
  const config = readConfig({ ...process.env, ...TEST_ENV, ...overrides });
  const created = createHttpServer(config);

  return new Promise((resolve, reject) => {
    created.server.once("error", reject);
    created.server.listen(0, "127.0.0.1", () => {
      resolve({
        ...created,
        config,
        url: `http://127.0.0.1:${created.server.address().port}`,
      });
    });
  });
}

async function shutdown(started) {
  if (!started) return;

  started.limiter.stopSweeper();
  await new Promise((resolve) => {
    started.server.close(() => resolve());
    // Keep-alive соединения fetch держат сервер открытым: закрываем их сразу,
    // иначе after() ждал бы их истечения.
    started.server.closeAllConnections?.();
  });
}

test.before(async () => {
  const started = await listen();
  server = started.server;
  limiter = started.limiter;
  baseUrl = started.url;
});

test.after(() => shutdown({ server, limiter }));

// Сырой HTTP-запрос: fetch нормализует путь (убирает "./", раскрывает
// percent-encoding), а проверяем именно то, что уйдёт на сервер.
function rawGet(url, rawPath) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: rawPath,
        method: "GET",
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          resolve({ status: res.statusCode, headers: res.headers, body });
        });
      },
    );

    req.on("error", reject);
    req.end();
  });
}

function parseCsp(header) {
  const directives = new Map();
  for (const part of String(header || "").split(";")) {
    const [name, ...values] = part.trim().split(/\s+/).filter(Boolean);
    if (name) directives.set(name, values);
  }
  return directives;
}

// Открывает новый TCP-сокет и подтверждает, что сервер его принял и обработал
// запрос: только после ответа слот лимита точно занят. keep-alive оставляет
// соединение открытым, поэтому сокет продолжает занимать место.
function openKeepAliveSocket(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.setEncoding("utf8");

    let buffer = "";
    let settled = false;

    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("сервер не ответил по новому сокету за 5 с"));
    }, 5000);

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };

    // Ждём полный ответ, а не первый кусок: остаток иначе мог бы потом
    // сойти за ответ на следующий запрос по тому же сокету.
    socket.on("data", (chunk) => {
      buffer += chunk;
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;

      const header = buffer.slice(0, headerEnd);
      const length = Number(
        (/content-length:\s*(\d+)/i.exec(header) || [])[1] || 0,
      );
      if (buffer.slice(headerEnd + 4).length < length) return;

      finish(resolve, socket);
    });

    socket.once("error", (error) => finish(reject, error));
    socket.once("close", () =>
      finish(reject, new Error("сокет закрыт до ответа")),
    );

    socket.write(
      "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
    );
  });
}

test("GET /healthz отвечает 200 и JSON", async () => {
  const res = await fetch(`${baseUrl}/healthz`);

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get("cache-control"), "no-store");

  const body = await res.json();
  assert.strictEqual(body.ok, true);
  assert.strictEqual(typeof body.uptime, "number");
});

test("GET / отдаёт HTML с подставленным BASE_URL и security-заголовками", async () => {
  const res = await fetch(`${baseUrl}/`);

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get("cache-control"), "no-store");
  assert.strictEqual(res.headers.get("x-frame-options"), "DENY");
  assert.strictEqual(res.headers.get("x-content-type-options"), "nosniff");
  assert.match(
    res.headers.get("content-security-policy") || "",
    /script-src 'self'/,
  );
  assert.strictEqual(res.headers.get("x-powered-by"), null);

  const html = await res.text();
  assert.match(html, /CyberCheck/);
  assert.strictEqual(html.includes("__BASE_URL__"), false);
  assert.match(html, /maxlength="2048"/);
  assert.match(html, /id="url"[^>]*aria-describedby="form-hint"/);
});

test("CSP: директивы ровно те, на которые рассчитан фронт", async () => {
  const res = await fetch(`${baseUrl}/`);
  const csp = parseCsp(res.headers.get("content-security-policy"));

  // helmet с useDefaults добавляет свои директивы (script-src-attr, font-src,
  // img-src). Здесь зафиксирован фактический контракт отдаваемого заголовка:
  // скрипты и стили только со своего origin, вставки и eval запрещены.
  assert.deepStrictEqual(csp.get("script-src"), ["'self'"]);
  assert.deepStrictEqual(csp.get("script-src-attr"), ["'none'"]);
  assert.deepStrictEqual(csp.get("style-src"), ["'self'"]);
  assert.deepStrictEqual(csp.get("object-src"), ["'none'"]);
  assert.deepStrictEqual(csp.get("base-uri"), ["'self'"]);
  assert.deepStrictEqual(csp.get("frame-ancestors"), ["'none'"]);
  assert.deepStrictEqual(csp.get("form-action"), ["'self'"]);
  assert.deepStrictEqual(csp.get("default-src"), ["'self'"]);

  // В NODE_ENV=test окружение непроизводственное, и upgrade-insecure-requests
  // отключён, чтобы отладка по LAN-адресу не ломалась. Продакшен проверяется
  // отдельным тестом ниже.
  assert.strictEqual(csp.has("upgrade-insecure-requests"), false);

  for (const [name, values] of csp) {
    assert.ok(
      !values.includes("'unsafe-inline'"),
      `${name}: запрещён unsafe-inline`,
    );
    assert.ok(!values.includes("'unsafe-eval'"), `${name}: запрещён unsafe-eval`);
    assert.ok(!values.includes("*"), `${name}: запрещена звёздочка`);
  }
});

test("CSP: в production включён upgrade-insecure-requests", async (t) => {
  const started = await listen({ NODE_ENV: "production" });
  t.after(() => shutdown(started));

  const res = await fetch(`${started.url}/`);
  const csp = parseCsp(res.headers.get("content-security-policy"));

  assert.ok(
    csp.has("upgrade-insecure-requests"),
    "в продакшене HTTP-запросы должны апгрейдиться до HTTPS",
  );
  assert.deepStrictEqual(csp.get("script-src"), ["'self'"]);
  assert.deepStrictEqual(csp.get("style-src"), ["'self'"]);
});

test("HTTP-сервер: таймауты и потолки сокетов выставлены", () => {
  const config = readConfig({ ...process.env, ...TEST_ENV });
  const created = createHttpServer(config);

  assert.strictEqual(created.server.headersTimeout, 10_000);
  assert.strictEqual(created.server.requestTimeout, 15_000);
  assert.strictEqual(created.server.keepAliveTimeout, 5_000);
  assert.strictEqual(created.server.maxConnections, 4096);
  assert.strictEqual(created.server.maxRequestsPerSocket, 100);

  created.limiter.stopSweeper();
});

test("per-IP лимит сокетов включается только при прямом доступе", () => {
  // За прокси у всех клиентов один адрес edge, и лимит на адрес заблокировал
  // бы всех. Поэтому обработчик соединений добавляется только при trustProxy=0.
  const bare = http.createServer();
  const direct = createHttpServer(
    readConfig({ ...process.env, ...TEST_ENV, TRUST_PROXY: "0" }),
  );
  const viaProxy = createHttpServer(
    readConfig({ ...process.env, ...TEST_ENV, TRUST_PROXY: "1" }),
  );

  assert.strictEqual(
    direct.server.listenerCount("connection"),
    bare.listenerCount("connection") + 1,
  );
  assert.strictEqual(
    viaProxy.server.listenerCount("connection"),
    bare.listenerCount("connection"),
  );

  direct.limiter.stopSweeper();
  viaProxy.limiter.stopSweeper();
});

test("с одного IP принимается не больше 64 сокетов", async (t) => {
  const started = await listen();
  const sockets = [];

  // Тест проверяет лимит сокетов, а не закрытие простаивающих keep-alive
  // соединений: увеличиваем keepAliveTimeout, чтобы 64 сокета не начали
  // закрываться сами во время подготовки.
  started.server.keepAliveTimeout = 30_000;

  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await shutdown(started);
  });

  const port = Number(new URL(started.url).port);

  for (let index = 0; index < MAX_SOCKETS_PER_IP; index += 1) {
    sockets.push(await openKeepAliveSocket(port));
  }

  assert.strictEqual(sockets.length, MAX_SOCKETS_PER_IP);

  // 65-й сокет сервер обязан уничтожить: клиент увидит обрыв (ошибку или
  // закрытие) вместо HTTP-ответа. Таймаут не даёт тесту зависнуть.
  const outcome = await new Promise((resolve, reject) => {
    const extra = net.connect({ host: "127.0.0.1", port });
    sockets.push(extra);

    const timer = setTimeout(() => {
      extra.destroy();
      reject(
        new Error(
          "65-й сокет не был закрыт сервером за 5 с — лимит сокетов на IP не работает",
        ),
      );
    }, 5000);

    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    extra.once("error", () => done("closed"));
    extra.once("close", () => done("closed"));
    extra.on("data", () => done("served"));
    extra.write(
      "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
    );
  });

  assert.strictEqual(
    outcome,
    "closed",
    "65-й сокет должен быть сброшен, а не обслужен",
  );

  // И сервер при этом жив: уже принятый сокет продолжает обслуживаться.
  const reused = await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("сервер не ответил по уже принятому сокету")),
      5000,
    );

    sockets[0].once("data", () => {
      clearTimeout(timer);
      resolve(true);
    });
    sockets[0].write(
      "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
    );
  });
  assert.strictEqual(reused, true);
});

test("encoded и ./ варианты index.html не отдают шаблон из статики", async () => {
  // fetch нормализует URL и убирает "./", поэтому шлём сырой путь через http.
  for (const target of ["/%69ndex.html", "/./index.html"]) {
    const res = await rawGet(baseUrl, target);

    assert.strictEqual(res.status, 404, target);
    assert.strictEqual(res.body.includes("__BASE_URL__"), false, target);
  }
});

test("/index.html редиректит на /", async () => {
  const res = await fetch(`${baseUrl}/index.html`, { redirect: "manual" });

  assert.strictEqual(res.status, 302);
  assert.strictEqual(res.headers.get("location"), "/");
});

test("POST /api/scan: невалидные запросы — 400 JSON", async () => {
  const cases = [
    [{ url: "example.com" }, /право на проверку/],
    [
      { url: "    ", consent: true, consentToken: issueConsentToken() },
      /Некорректный адрес/,
    ],
    [{ url: "example.com", consent: true, consentToken: "fake" }, /устарело/],
    [
      {
        url: "ftp://example.com",
        consent: true,
        consentToken: issueConsentToken(),
      },
      /только http и https/,
    ],
    [
      {
        url: `example.com/${"x".repeat(2100)}`,
        consent: true,
        consentToken: issueConsentToken(),
      },
      /Некорректный адрес/,
    ],
  ];

  for (const [payload, pattern] of cases) {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    assert.strictEqual(res.status, 400, JSON.stringify(payload).slice(0, 60));
    const body = await res.json();
    assert.match(body.error, pattern);
  }
});

test("POST /api/scan: экранированный query с :// не ломает адрес", async () => {
  // Схема определяется в начале строки: "example.com/?next=https://x" —
  // валидный ввод, который должен дойти до проверки адреса, а не упасть
  // с 400 «Некорректный адрес» на парсинге.
  const res = await fetch(`${baseUrl}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: "http://127.0.0.1/?next=https://example.com",
      consent: true,
      consentToken: issueConsentToken(),
    }),
  });

  // Внутренний адрес отсекается, но ответ — про адрес, а не про парсинг.
  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.match(body.error, /Не удалось проверить адрес/);
});

test("POST /api/scan: после неудачной попытки включается кулдаун", async (t) => {
  // Отдельный сервер: кулдаун живёт в памяти сервера, и проверка не должна
  // зависеть от того, что успели сделать предыдущие тесты.
  const started = await listen();
  t.after(() => shutdown(started));

  const scan = (url, token) =>
    fetch(`${started.url}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        consent: true,
        consentToken: token || issueConsentToken(),
      }),
    });

  // Приватный адрес — валидный запрос, который дошёл до резолва и получил 400.
  const first = await scan("http://127.0.0.1/");
  assert.strictEqual(first.status, 400);
  assert.match((await first.json()).error, /Не удалось проверить адрес/);

  // Кулдаун ставится и после ошибки: такие ответы — оракул для перебора
  // внутренних имён, поэтому 10 секунд действуют на любой исход скана.
  const second = await scan("http://127.0.0.1/");
  assert.strictEqual(second.status, 429);

  const retryAfter = second.headers.get("retry-after");
  assert.match(retryAfter || "", /^[1-9]\d*$/);
  assert.ok(Number(retryAfter) <= 10);
  assert.match((await second.json()).error, /Подожди \d+ сек/);

  // Валидация выполняется раньше лимита: мусорный запрос получает свой 400,
  // а не 429, и кулдаун не продлевает.
  const invalid = await scan("    ");
  assert.strictEqual(invalid.status, 400);
});

test("POST /api/scan: не-JSON Content-Type — 415", async () => {
  const res = await fetch(`${baseUrl}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: JSON.stringify({
      url: "example.com",
      consent: true,
      consentToken: issueConsentToken(),
    }),
  });

  assert.strictEqual(res.status, 415);
  assert.match((await res.json()).error, /Поддерживается только JSON/);
});

test("POST /api/scan/unknown: 404, а не 415 про формат тела", async () => {
  const res = await fetch(`${baseUrl}/api/scan/unknown`, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: "не json",
  });

  assert.strictEqual(res.status, 404);
  assert.deepStrictEqual(await res.json(), { error: "Не найдено" });
});

test("POST /api/scan: тело больше 8 КБ — 413", async () => {
  const res = await fetch(`${baseUrl}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: "example.com",
      consent: true,
      consentToken: issueConsentToken(),
      padding: "x".repeat(9000),
    }),
  });

  assert.strictEqual(res.status, 413);
  assert.match((await res.json()).error, /Слишком большой запрос/);
});

test("CORS: свой origin разрешён, чужой — нет", async () => {
  const preflight = (origin) =>
    fetch(`${baseUrl}/api/scan`, {
      method: "OPTIONS",
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": "POST",
      },
    });

  const allowed = await preflight("http://localhost:3000");
  assert.strictEqual(allowed.status, 204);
  assert.strictEqual(
    allowed.headers.get("access-control-allow-origin"),
    "http://localhost:3000",
  );

  const foreign = await preflight("https://evil.example");
  assert.strictEqual(foreign.headers.get("access-control-allow-origin"), null);
});

test("неизвестный путь — JSON 404", async () => {
  const res = await fetch(`${baseUrl}/nope`);

  assert.strictEqual(res.status, 404);
  assert.match(res.headers.get("content-type") || "", /application\/json/);
  assert.deepStrictEqual(await res.json(), { error: "Не найдено" });
});
