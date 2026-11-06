const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const { spawn } = require("node:child_process");
const path = require("node:path");

// HTTP-слой проверяется на живом процессе: приложение поднимается на
// случайном порту, тесты ходят в него через fetch (Node 22).
//
// 503 (потолок одновременных сканов) и 504 (таймаут скана) здесь не
// проверяются: чтобы получить их, нужны 25 параллельных сканов или
// зависший TLS-сервер, то есть подмена внутренних проверок. Это отдельная
// задача с внедрением зависимостей, а не HTTP-контракт.
const SERVER_PATH = path.join(__dirname, "../src/server.js");

let child = null;
let baseUrl = null;

function startServer() {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [SERVER_PATH], {
      env: {
        ...process.env,
        TRUST_PROXY: "0",
        PUBLIC_ORIGIN: "http://localhost:3000",
        PORT: "0",
        NODE_ENV: "test",
        DEMO_MODE: "false",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let done = false;

    const fail = (message) => {
      if (done) return;
      done = true;
      proc.kill();
      reject(new Error(`${message}\nstderr=${stderr}`));
    };

    const timer = setTimeout(
      () => fail("сервер не запустился за 10 с"),
      10_000,
    );

    proc.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      const match = /localhost:(\d+)/.exec(stdout);
      if (!match || done) return;

      done = true;
      clearTimeout(timer);
      resolve({ proc, url: `http://127.0.0.1:${match[1]}` });
    });

    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("exit", (code) => {
      if (!done && code === 1) fail("сервер завершился с кодом 1");
    });
  });
}

test.before(async () => {
  const started = await startServer();
  child = started.proc;
  baseUrl = started.url;
});

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

test.after(() => {
  if (!child) return;

  child.kill();
  // Страховка: если graceful shutdown не успел, не держим тестовый процесс.
  const killer = setTimeout(() => child.kill("SIGKILL"), 2000);
  killer.unref();
});

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
      { url: "    ", consent: true, consentTimestamp: Date.now() },
      /Некорректный адрес/,
    ],
    [{ url: "example.com", consent: true, consentTimestamp: 1 }, /устарело/],
    [
      { url: "ftp://example.com", consent: true, consentTimestamp: Date.now() },
      /только http и https/,
    ],
    [
      {
        url: `example.com/${"x".repeat(2100)}`,
        consent: true,
        consentTimestamp: Date.now(),
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
      consentTimestamp: Date.now(),
    }),
  });

  // Внутренний адрес отсекается, но ответ — про адрес, а не про парсинг.
  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.match(body.error, /Не удалось проверить адрес/);
});

test("POST /api/scan: после неудачной попытки включается кулдаун", async (t) => {
  // Отдельный процесс: кулдаун живёт в памяти сервера, и проверка не должна
  // зависеть от того, что успели сделать предыдущие тесты.
  const started = await startServer();
  t.after(() => started.proc.kill());

  const scan = (url) =>
    fetch(`${started.url}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        consent: true,
        consentTimestamp: Date.now(),
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
      consentTimestamp: Date.now(),
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
      consentTimestamp: Date.now(),
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
