const net = require("node:net");
const http = require("node:http");
const test = require("node:test");
const assert = require("node:assert");
const {
  createHttpServer,
  issueConsentToken,
  redirectsToHttps,
  clientIdentity,
} = require("../src/core/server");
const {
  readConfig,
  readNodeEnv,
  readPort,
  readTrustProxy,
} = require("../src/core/config");

// Валидное окружение для readConfig: любой тест, который проверяет одно поле,
// не должен падать на соседних. Значения совпадают с тем, что раньше
// выставлялось дочернему процессу.
function testEnv(overrides = {}) {
  return {
    TRUST_PROXY: "0",
    PUBLIC_ORIGIN: "http://localhost:3000",
    PORT: "0",
    NODE_ENV: "development", // Чтобы DEMO_MODE мог включиться
    DEMO_MODE: "false",
    ...overrides,
  };
}

// fail() в config.js печатает ошибку и завершает процесс. Подменяем оба выхода
// наружу, чтобы проверить реакцию на плохое значение в том же процессе: spawn
// в песочнице запрещён, а дочерний процесс к тому же скрыл бы сам вызов.
function captureFailures(run) {
  const originalExit = process.exit;
  const originalError = console.error;
  const exits = [];
  const messages = [];

  process.exit = (code) => {
    exits.push(code);
  };
  console.error = (message) => {
    messages.push(String(message));
  };

  try {
    run();
  } finally {
    process.exit = originalExit;
    console.error = originalError;
  }

  assert.ok(messages.length > 0, "fail() должен написать понятную ошибку");
  return { exits, messages };
}

// Хелпер: поднимает сервер на случайном порту и возвращает url + функцию очистки.
// options — тестовый шов createHttpServer (scanPorts/webPortOrder), по умолчанию
// поведение штатное.
async function listenServer(t, config, options = {}) {
  const { server, limiter } = createHttpServer(config, options);

  t.after(async () => {
    limiter.stopSweeper();
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const port = server.address().port;
  return { server, limiter, port, url: `http://127.0.0.1:${port}/api/scan` };
}

// Ждём условие с таймаутом вместо фиксированного sleep: на медленной машине
// 150 мс могло не хватить, а на быстрой мы зря тратили бы время.
async function waitFor(predicate, timeoutMs, message) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

test("TRUST_PROXY=0 не роняет сервер", async (t) => {
  const config = readConfig(testEnv({ TRUST_PROXY: "0" }));
  const { server, limiter } = createHttpServer(config);

  t.after(async () => {
    limiter.stopSweeper();
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  assert.ok(
    address && address.port > 0,
    "сервер должен слушать выбранный порт",
  );
  assert.strictEqual(config.trustProxy, 0);

  // Свойство прежнего теста было «сервер поднимается», но полезнее проверить,
  // что он ещё и отвечает: иначе успешный listen ничего не доказывает.
  const res = await fetch(`http://127.0.0.1:${address.port}/healthz`);
  assert.strictEqual(res.status, 200);
  assert.strictEqual((await res.json()).ok, true);
});

// --- NODE_ENV, PORT и TRUST_PROXY: валидация конфигурации ---------------

test("readNodeEnv: development, production и test допустимы", () => {
  for (const value of ["development", "production", "test"]) {
    assert.strictEqual(readNodeEnv(value), value);
  }

  // Незаданный NODE_ENV — штатный локальный запуск, а не ошибка.
  assert.strictEqual(readNodeEnv(undefined), undefined);
  assert.strictEqual(readNodeEnv(""), undefined);
});

test("readNodeEnv: prod, Production, staging и foo останавливают запуск", () => {
  // Раньше неизвестное значение молча выключало прод-контроли (CONSENT_SECRET,
  // upgrade-insecure-requests), поэтому теперь это отказ старта.
  for (const value of ["prod", "Production", "staging", "foo"]) {
    const { exits, messages } = captureFailures(() => readNodeEnv(value));

    assert.deepStrictEqual(exits, [1], `${value}: ожидался process.exit(1)`);
    assert.ok(
      messages.some((message) => message.includes("NODE_ENV")),
      `${value}: сообщение должно объяснять NODE_ENV, пришло: ${messages.join(" | ")}`,
    );
  }
});

test("readConfig: недопустимый NODE_ENV — exit(1) с объяснением", () => {
  const { exits, messages } = captureFailures(() =>
    readConfig(testEnv({ NODE_ENV: "Production" })),
  );

  assert.deepStrictEqual(exits, [1]);
  assert.ok(
    messages.some((message) => message.includes("NODE_ENV")),
    messages.join(" | "),
  );
});

test("readPort: целое число от 0 до 65535, пустое значение — 3000", () => {
  assert.strictEqual(readPort("3000"), 3000);
  assert.strictEqual(readPort("0"), 0);
  assert.strictEqual(readPort("65535"), 65535);
  assert.strictEqual(readPort(undefined), 3000);
  assert.strictEqual(readPort(""), 3000);

  for (const invalid of [
    "-1",
    "65536",
    "3.5",
    "abc",
    "3000abc",
    "0x50",
    "1e3",
    "+80",
  ]) {
    const { exits, messages } = captureFailures(() => readPort(invalid));

    assert.deepStrictEqual(exits, [1], `${invalid}: ожидался exit(1)`);
    assert.ok(
      messages.some((message) => message.includes("PORT")),
      `${invalid}: сообщение должно объяснять PORT`,
    );
  }
});

test("readTrustProxy: только целое 0..10", () => {
  assert.strictEqual(readTrustProxy(undefined), 0);
  assert.strictEqual(readTrustProxy(""), 0);
  assert.strictEqual(readTrustProxy("1"), 1);
  assert.strictEqual(readTrustProxy(" 10 "), 10);

  for (const invalid of ["true", "-1", "11", "1.5", "abc"]) {
    const { exits, messages } = captureFailures(() => readTrustProxy(invalid));

    // «true» и дробь проваливают и проверку формата, и проверку диапазона,
    // поэтому fail() может вызваться дважды — важен только код выхода.
    assert.ok(exits.length >= 1, `${invalid}: ожидался process.exit(1)`);
    assert.ok(
      exits.every((code) => code === 1),
      `${invalid}: ожидался только код 1, пришли: ${exits.join(", ")}`,
    );
    assert.ok(
      messages.some((message) => message.includes("TRUST_PROXY")),
      `${invalid}: сообщение должно объяснять TRUST_PROXY`,
    );
  }
});

test("clientIdentity: при двух прокси берётся клиент, а не адрес прокси", () => {
  const req = {
    socket: { remoteAddress: "10.0.0.5" },
    headers: { "x-forwarded-for": "1.1.1.1, 2.2.2.2" },
  };

  const two = clientIdentity(req, 2);
  assert.strictEqual(two.rawIp, "1.1.1.1");
  // За прокси edge-ключ тоже клиентский: иначе все клиенты делят два слота.
  assert.strictEqual(two.edgeKey, two.clientKey);

  const one = clientIdentity(req, 1);
  assert.strictEqual(one.rawIp, "2.2.2.2");

  // XFF короче числа доверенных прокси — падаем на адрес сокета.
  assert.strictEqual(
    clientIdentity({ ...req, headers: { "x-forwarded-for": "1.1.1.1" } }, 2)
      .rawIp,
    "10.0.0.5",
  );
});

test("явный порт в URL сканируется, а состояния портов возвращаются в portChecks", async (t) => {
  const target = http.createServer((req, res) => {
    res.setHeader("Content-Type", "text/plain");
    res.end("ok");
  });
  await new Promise((resolve, reject) => {
    target.once("error", reject);
    target.listen(0, "127.0.0.1", resolve);
  });
  const targetPort = target.address().port;
  t.after(
    () =>
      new Promise((resolve) => {
        target.closeAllConnections?.();
        target.close(resolve);
      }),
  );

  const config = readConfig(testEnv({ DEMO_MODE: "true" }));
  const { url } = await listenServer(t, config);

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: `http://127.0.0.1:${targetPort}`,
      consent: true,
      consentToken: issueConsentToken(),
    }),
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();

  // Раньше порт из URL молча игнорировался и скан шёл по 80/443.
  assert.ok(
    data.ports.some((port) => port.port === targetPort),
    "явный порт должен попасть в отчёт",
  );
  assert.ok(Array.isArray(data.portChecks));
  assert.ok(
    data.portChecks.some((port) => port.port === targetPort && port.status === "open"),
  );
  assert.strictEqual(data.headers.status, 200);
});

// --- Признак редиректа 80 → 443 (HSTS имеет смысл только с ним) ---------

test("redirectsToHttps: только 3xx с https Location на тот же хост", () => {
  assert.strictEqual(
    redirectsToHttps(
      { status: 301, location: "https://example.com/" },
      "example.com",
    ),
    true,
  );
  assert.strictEqual(
    redirectsToHttps(
      { status: 308, location: "HTTPS://Example.COM./path" },
      "example.com",
    ),
    true,
  );

  // Открытый HTTP на порту 80 — не «неизвестно», а подтверждённое отсутствие
  // редиректа.
  assert.strictEqual(
    redirectsToHttps({ status: 200, location: "" }, "example.com"),
    false,
  );
  assert.strictEqual(
    redirectsToHttps(
      { status: 302, location: "http://example.com/" },
      "example.com",
    ),
    false,
  );
  assert.strictEqual(
    redirectsToHttps({ status: 302, location: "/login" }, "example.com"),
    false,
  );
  // Чужой origin не защищает этот сайт, даже если редирект ведёт на HTTPS.
  assert.strictEqual(
    redirectsToHttps(
      { status: 301, location: "https://evil.example/" },
      "example.com",
    ),
    false,
  );
  assert.strictEqual(redirectsToHttps({ status: 302 }, "example.com"), false);
  assert.strictEqual(
    redirectsToHttps({ error: true }, "example.com"),
    false,
  );
  assert.strictEqual(redirectsToHttps(null, "example.com"), false);
});

// --- Rate limit и доверие к X-Forwarded-For -----------------------------

test("Rate limit использует реальный IP прокси, а не подделку из X-Forwarded-For", async (t) => {
  const config = readConfig(testEnv({ TRUST_PROXY: "1", DEMO_MODE: "true" }));
  const { url } = await listenServer(t, config);

  const payload = {
    url: "http://localhost",
    consent: true,
    consentToken: issueConsentToken(),
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
  const config = readConfig(testEnv({ TRUST_PROXY: "0", DEMO_MODE: "true" }));
  const { url } = await listenServer(t, config);

  const payload = {
    url: "http://localhost",
    consent: true,
    consentToken: issueConsentToken(),
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

test("Сервер отклоняет сканирование с поддельным токеном согласия", async (t) => {
  const config = readConfig(testEnv({ TRUST_PROXY: "0", DEMO_MODE: "true" }));
  const { url } = await listenServer(t, config);

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: "http://localhost",
      consent: true,
      consentToken: "12345.fake_mac_signature",
    }),
  });

  assert.strictEqual(res.status, 400);
  const data = await res.json();
  assert.match(data.error, /Подтверждение устарело или недействительно/);
});

test("Rate limit: за прокси ключ считается по реальному клиенту, а не по прокси", async (t) => {
  // Зависшая цель на случайном порту: скан подключается к ней как к веб-порту
  // и висит на TLS/HTTP-пробе, удерживая слоты. Фиксированный 8080 не
  // занимаем: при параллельном запуске или чужом процессе на этом порту тест
  // получал бы EADDRINUSE. Порт передаём серверу через options (scanPorts/
  // webPortOrder) — настоящие пробы и настоящий скан при этом сохраняются.
  const hangingSockets = new Set();
  const hangingTarget = net.createServer((socket) => {
    // Намеренно не отвечаем: любой ответ завершил бы скан.
    hangingSockets.add(socket);
    socket.on("close", () => hangingSockets.delete(socket));
    socket.on("error", () => {});
  });

  const controllers = [
    new AbortController(),
    new AbortController(),
    new AbortController(),
  ];
  t.after(async () => {
    controllers.forEach((c) => c.abort());
    for (const socket of hangingSockets) socket.destroy();
    await new Promise((resolve) => hangingTarget.close(resolve));
  });

  await new Promise((resolve, reject) => {
    hangingTarget.once("error", reject);
    hangingTarget.listen(0, "127.0.0.1", resolve);
  });
  const targetPort = hangingTarget.address().port;

  const config = readConfig(testEnv({ TRUST_PROXY: "1", DEMO_MODE: "true" }));
  const { url, limiter } = await listenServer(t, config, {
    scanPorts: [targetPort],
    webPortOrder: [targetPort],
  });

  const payload = {
    url: `http://127.0.0.1:${targetPort}`,
    consent: true,
    consentToken: issueConsentToken(),
  };

  const makeReq = (xff, signal) =>
    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": xff,
      },
      body: JSON.stringify(payload),
      signal,
    });

  const req1 = makeReq("1.1.1.1", controllers[0].signal).catch(() => {});
  const req2 = makeReq("2.2.2.2", controllers[1].signal).catch(() => {});
  const req3 = makeReq("3.3.3.3", controllers[2].signal).catch(() => {});

  // Три разных клиента за одним прокси должны получить три слота: раньше
  // edgeKey брался из адреса сокета (прокси) и третий запрос получал 429.
  await waitFor(
    () => limiter.activeScans === 3 && limiter.activeKeys === 3,
    3000,
    "три клиента за прокси не получили по слоту",
  );

  controllers.forEach((c) => c.abort());
  await Promise.all([req1, req2, req3]);

  // Слоты освобождаются на любом исходе скана (finally в роуте): утечка
  // навсегда съедала бы ёмкость лимитера.
  await waitFor(
    () => limiter.activeScans === 0,
    2000,
    "edge-слоты не освободились после отмены запросов",
  );
  assert.strictEqual(limiter.activeByEdge.size, 0);
});
