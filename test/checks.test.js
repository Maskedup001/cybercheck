const test = require("node:test");
const assert = require("node:assert");
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");

const { checkPort } = require("../src/probes/ports");
const { checkSSL } = require("../src/probes/tls");
const { checkHeaders } = require("../src/probes/http-headers");
const { selfSignedCertificate } = require("./fixtures/tls/self-signed");

// Локальный сервер на случайном порту: тесты не должны зависеть от внешней
// сети и от того, свободен ли конкретный порт.
async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server.address().port;
}

function closeServer(server) {
  // Keep-alive-соединения (глобальный агент Node включает keepAlive) иначе
  // держат server.close() до истечения таймаута — тест «висит» на ровном месте.
  if (typeof server.closeAllConnections === "function") {
    server.closeAllConnections();
  }
  return new Promise((resolve) => server.close(resolve));
}

// --- Открытый и закрытый порт --------------------------------------

test("checkPort: закрытый порт не висит вечно", async () => {
  const result = await checkPort("127.0.0.1", 1, 500, 1);

  assert.strictEqual(result.port, 1);
  // В зависимости от ОС и настроек сети сервер может явно отказать (refused)
  // или просто не ответить (closed). Важно, что он не "open".
  assert.ok(
    ["refused", "closed"].includes(result.status),
    `Ожидали refused или closed, получили: ${result.status}`,
  );
});

test("checkPort: открытый порт определяется", async () => {
  const server = net.createServer();
  const port = await listen(server);

  const result = await checkPort("127.0.0.1", port, 1000, 0);
  assert.strictEqual(result.status, "open");

  await closeServer(server);
});

// --- Заголовки -----------------------------------------------------

test("checkHeaders: находит заголовки, cookie-флаги и CORS", async () => {
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Set-Cookie", [
      "session=abc; Secure; HttpOnly; SameSite=Strict",
      "theme=dark; SameSite=Lax",
    ]);
    res.end("ok");
  });
  const port = await listen(server);

  const result = await checkHeaders("127.0.0.1", port, "localhost", 0);
  assert.strictEqual(result.csp, true);
  assert.strictEqual(result.xframe, true);
  assert.strictEqual(result.hsts, false); // Не установлен
  assert.strictEqual(result.referrerPolicy, true);
  assert.strictEqual(result.permissionsPolicy, true);
  assert.strictEqual(result.coop, true);
  assert.strictEqual(result.corsWildcard, true);
  assert.strictEqual(result.accessControlAllowOrigin, "*");

  assert.strictEqual(result.cookies.length, 2);
  assert.deepStrictEqual(result.cookies[0], {
    name: "session",
    secure: true,
    httpOnly: true,
    sameSite: true,
    sameSiteValue: "strict",
  });
  assert.deepStrictEqual(result.cookieSummary, {
    total: 2,
    secure: 1,
    httpOnly: 1,
    sameSite: 2,
    insecureNone: 0,
    missingSecure: 1,
    missingHttpOnly: 1,
    missingSameSite: 0,
  });

  await closeServer(server);
});

test("checkHeaders: небезопасные значения заголовков не дают защиты", async () => {
  const server = http.createServer((req, res) => {
    // Заголовки есть, но защиту не включают: max-age=0, wildcard в CSP,
    // неизвестные значения XFO/XCTO/Referrer-Policy/COOP.
    res.setHeader("Strict-Transport-Security", "max-age=0");
    res.setHeader("Content-Security-Policy", "default-src *");
    res.setHeader("X-Frame-Options", "ALLOW-FROM https://example.com");
    res.setHeader("X-Content-Type-Options", "foo");
    res.setHeader("Referrer-Policy", "unsafe-url");
    res.setHeader("Cross-Origin-Opener-Policy", "unsafe-none");
    res.end("ok");
  });
  const port = await listen(server);

  const result = await checkHeaders("127.0.0.1", port, "localhost", 0);

  for (const field of [
    "hsts",
    "csp",
    "xframe",
    "xcontent",
    "referrerPolicy",
    "coop",
  ]) {
    assert.strictEqual(
      result[field],
      false,
      `${field} не должен считаться защитой`,
    );
    assert.strictEqual(
      result[`${field}State`],
      "weak",
      `${field} должен быть weak`,
    );
  }

  // server нормализован: строка или null, без заглушки «не указан».
  assert.strictEqual(result.server, null);

  await closeServer(server);
});

test("checkHeaders: IPv6 в Host-заголовке заключён в скобки", async () => {
  let seenHost = "";
  const server = http.createServer((req, res) => {
    seenHost = req.headers.host;
    res.end("ok");
  });
  const port = await listen(server);

  const result = await checkHeaders(
    "127.0.0.1",
    port,
    "2001:db8::1",
    0,
    undefined,
    false,
    1000,
  );

  assert.strictEqual(result.error, undefined);
  assert.strictEqual(seenHost, `[2001:db8::1]:${port}`);

  await closeServer(server);
});

// --- TLS: успешный хендшейк ---------------------------------------

test("checkSSL: самоподписанный сертификат читается, но помечается невалидным", async (t) => {
  const { key, cert } = selfSignedCertificate();
  const server = https.createServer({ key, cert }, (req, res) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", "default-src 'self'");
    res.end("ok");
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

  // Дедлайн с запасом: хендшейк локальный, а проверка старых TLS должна
  // получить свой остаток, а не фиксированные 3 секунды.
  const result = await checkSSL(
    "127.0.0.1",
    port,
    "localhost",
    null,
    0,
    5000,
    Date.now() + 3000,
  );

  assert.strictEqual(result.hasSSL, true);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(typeof result.verifyError, "string");
  assert.ok(result.verifyError.length > 0);
  assert.strictEqual(typeof result.daysLeft, "number");
  assert.ok(result.daysLeft > 0, `daysLeft=${result.daysLeft}`);
  assert.strictEqual(typeof result.tlsVersion, "string");
  assert.match(result.tlsVersion, /^TLSv1\.[23]$/);
  assert.strictEqual(result.issuer, "localhost");
});

test("checkHeaders: по HTTPS возвращает protocol HTTPS", async (t) => {
  const { key, cert } = selfSignedCertificate();
  const server = https.createServer({ key, cert }, (req, res) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.end("ok");
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

  const headers = await checkHeaders(
    "127.0.0.1",
    port,
    "localhost",
    0,
    undefined,
    true,
    5000,
    Date.now() + 3000,
  );

  assert.strictEqual(headers.error, undefined);
  assert.strictEqual(headers.protocol, "HTTPS");
  assert.strictEqual(headers.xframe, true);
});

test("checkSSL: возвращает ошибку, если TLS не поднялся", async () => {
  // Стучимся на заведомо HTTP-порт (1), где TLS не может подняться
  const result = await checkSSL("127.0.0.1", 1, "localhost", null, 0);
  assert.strictEqual(result.hasSSL, false);
  assert.strictEqual(result.error, "HANDSHAKE_FAILED");
});

// --- Бюджет этапа --------------------------------------------------

test("checkSSL: молчащий TLS-сервер укладывается в дедлайн", async (t) => {
  // Сервер принимает TCP-соединение и не отвечает: клиент обязан выйти по
  // остатку бюджета, а не ждать два полных таймаута с паузой.
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => sockets.delete(socket));
  });
  const port = await listen(server);
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await closeServer(server);
  });

  const startedAt = Date.now();
  const result = await checkSSL(
    "127.0.0.1",
    port,
    "localhost",
    null,
    1,
    5000,
    Date.now() + 300,
  );
  const elapsed = Date.now() - startedAt;

  assert.strictEqual(result.hasSSL, false);
  assert.strictEqual(result.error, "HANDSHAKE_FAILED");
  assert.ok(elapsed < 1500, `этап TLS занял ${elapsed} мс`);
});

test("checkPort: истёкший дедлайн не открывает сокет", async () => {
  const startedAt = Date.now();
  const result = await checkPort(
    "127.0.0.1",
    80,
    5000,
    1,
    undefined,
    Date.now() - 1,
  );

  assert.strictEqual(result.status, "closed");
  assert.ok(Date.now() - startedAt < 500);
});

// --- Инвариант SSRF ------------------------------------------------

test("проверки отказываются от нелитерального connectIp", async () => {
  // Имя хоста увело бы сокет в собственный DNS-резолв Node — это обход
  // проверки адреса, поэтому отказ должен быть мгновенным и без сети.
  const startedAt = Date.now();

  const port = await checkPort("example.com", 80, 1000, 1);
  assert.deepStrictEqual(port, { port: 80, status: "closed" });

  const ssl = await checkSSL("example.com", 443, "example.com", null, 0);
  assert.strictEqual(ssl.hasSSL, false);
  assert.strictEqual(ssl.error, "INVALID_CONNECT_IP");

  const headers = await checkHeaders("example.com", 443, "example.com", 0);
  assert.deepStrictEqual(headers, { error: true });

  assert.ok(Date.now() - startedAt < 500);
});

// --- Устойчивость к сбоям ------------------------------------------

test("checkSSL: не бросает исключение при отмененном сигнале", async () => {
  const controller = new AbortController();
  controller.abort(); // Сигнал уже отменен

  // Вызываем проверку TLS с отмененным сигналом
  const result = await checkSSL(
    "127.0.0.1",
    443,
    "localhost",
    controller.signal,
  );

  // Главное: функция не упала с throw, а вернула безопасный объект
  assert.strictEqual(result.hasSSL, false);
  assert.ok(result.error); // Должна быть ошибка (HANDSHAKE_FAILED)
});
