const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const path = require("node:path");
const { createApp } = require("../src/core/server");

test("TRUST_PROXY=0 не роняет сервер", async (t) => {
  const child = spawn(
    process.execPath,
    [path.join(__dirname, "../src/server.js")],
    {
      env: {
        ...process.env,
        TRUST_PROXY: "0",
        PUBLIC_ORIGIN: "http://localhost:3000",
        PORT: "0",
        NODE_ENV: "test",
        DEMO_MODE: "false",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  t.after(() => child.kill());

  let stdout = "";
  let stderr = "";

  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new Error(
          `Сервер не запустился за 10 с: stdout=${stdout}, stderr=${stderr}`,
        ),
      );
    }, 10_000);

    const finish = (error) => {
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.includes("Сканер запущен")) finish();
    });

    child.on("exit", (code) => {
      if (code === 1) {
        finish(new Error(`Сервер упал с кодом 1: ${stderr}`));
      }
    });
  });

  assert.match(stdout, /Сканер запущен/);
  assert.strictEqual(stderr.includes("ОШИБКА"), false, stderr);
});

test("Rate limit использует реальный IP прокси, а не подделку из X-Forwarded-For", async (t) => {
  const { app } = createApp({
    publicOrigin: "http://localhost:3000",
    publicDir: "public",
    pages: ["index.html", "legal.html", "privacy.html"],
    isProduction: false,
    demoMode: true,
    trustProxy: 1,
  });

  const server = app.listen(0);
  const port = server.address().port;
  const url = `http://127.0.0.1:${port}/api/scan`;
  t.after(() => server.close());

  const payload = {
    url: "http://localhost",
    consent: true,
    consentTimestamp: Date.now(),
  };

  // Первый запрос: клиент подделывает левый край, прокси дописывает 10.0.0.1
  const res1 = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-For": "1.1.1.1, 10.0.0.1",
    },
    body: JSON.stringify(payload),
  });

  assert.notStrictEqual(
    res1.status,
    429,
    "Первый запрос не должен быть заблокирован",
  );

  // Второй запрос: клиент меняет подделку, но реальный IP прокси (10.0.0.1) тот же
  const res2 = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-For": "2.2.2.2, 10.0.0.1",
    },
    body: JSON.stringify(payload),
  });

  assert.strictEqual(
    res2.status,
    429,
    "Второй запрос должен быть заблокирован (обход XFF не работает)",
  );
  assert.ok(
    res2.headers.get("retry-after"),
    "Заголовок Retry-After должен присутствовать",
  );
});

test("При trustProxy=0 заголовок X-Forwarded-For полностью игнорируется", async (t) => {
  const { app } = createApp({
    publicOrigin: "http://localhost:3000",
    publicDir: "public",
    pages: ["index.html", "legal.html", "privacy.html"],
    isProduction: false,
    demoMode: true,
    trustProxy: 0,
  });

  const server = app.listen(0);
  const port = server.address().port;
  const url = `http://127.0.0.1:${port}/api/scan`;
  t.after(() => server.close());

  const payload = {
    url: "http://localhost",
    consent: true,
    consentTimestamp: Date.now(),
  };

  // Первый запрос с XFF
  await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-For": "8.8.8.8",
    },
    body: JSON.stringify(payload),
  });

  // Второй запрос с другим XFF (но с того же сокета)
  const res2 = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-For": "9.9.9.9",
    },
    body: JSON.stringify(payload),
  });

  assert.strictEqual(
    res2.status,
    429,
    "Второй запрос должен быть заблокирован, несмотря на смену XFF",
  );
});
