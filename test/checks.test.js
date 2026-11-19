const test = require("node:test");
const assert = require("node:assert");
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const tls = require("node:tls");

const { checkPort } = require("../src/probes/ports");
const { checkSSL } = require("../src/probes/tls");
const { checkHeaders } = require("../src/probes/http-headers");
const { selfSignedCertificate } = require("./fixtures/tls/self-signed");

// Локальный сервер на случайном порту: тесты не должны зависеть от внешней
// сети и от того, свободен ли конкретный порт.
async function listen(server) {
  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", onError);
      resolve();
    });
  });
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

test("checkPort: закрытый порт — refused, а не open", async () => {
  // Порт освобождается после закрытия локального слушателя: отказ приходит
  // сразу и детерминированно, без похода во внешнюю сеть.
  const server = net.createServer();
  const port = await listen(server);
  await closeServer(server);

  const result = await checkPort("127.0.0.1", port, 1000, 0);

  assert.strictEqual(result.port, port);
  assert.strictEqual(result.status, "refused");
});

test("checkPort: открытый порт определяется", async (t) => {
  const server = net.createServer();
  const port = await listen(server);
  t.after(() => closeServer(server));

  const result = await checkPort("127.0.0.1", port, 1000, 0);
  assert.strictEqual(result.status, "open");
});

test("checkPort: таймаут — filtered, а не closed", async (t) => {
  // Молчащий порт без внешней сети: connect не выполняется, а по таймеру
  // приходит событие timeout — так же, как при DROP со стороны firewall.
  const originalConnect = net.Socket.prototype.connect;
  let connectCalls = 0;

  net.Socket.prototype.connect = function () {
    connectCalls += 1;
    setImmediate(() => this.emit("timeout"));
    return this;
  };
  t.after(() => {
    net.Socket.prototype.connect = originalConnect;
  });

  const result = await checkPort("127.0.0.1", 65000, 1000, 1);

  // Таймаут — «не измерено», а не «закрыто».
  assert.strictEqual(result.status, "filtered");
  // Ретрай не должен повторять таймаут и съедать бюджет: попытка одна.
  assert.strictEqual(connectCalls, 1);
});

test("checkPort: прочие сетевые ошибки — filtered, ретрай остаётся", async (t) => {
  // Быстрый сбой (EHOSTUNREACH/EACCES/ECONNRESET) — не доказательство
  // закрытости и не таймаут: повтор может дать ответ.
  const originalConnect = net.Socket.prototype.connect;
  const sockets = [];
  let connectCalls = 0;

  net.Socket.prototype.connect = function () {
    connectCalls += 1;
    sockets.push(this);
    const error = new Error("host unreachable");
    error.code = "EHOSTUNREACH";
    setImmediate(() => {
      this.emit("error", error);
      this.emit("close");
    });
    return this;
  };
  t.after(() => {
    net.Socket.prototype.connect = originalConnect;
    // Снимаем слушатели до destroy(): иначе искусственное close может
    // запустить ещё один ретрай после завершения теста.
    for (const socket of sockets) {
      socket.removeAllListeners("close");
      socket.removeAllListeners("error");
      socket.removeAllListeners("timeout");
      socket.destroy();
    }
  });

  const result = await checkPort("127.0.0.1", 65001, 1000, 1);

  assert.strictEqual(result.status, "filtered");
  // Бюджета хватает на ретрай: быстрый сбой повторяется один раз.
  assert.strictEqual(connectCalls, 2);
});

// --- Заголовки -----------------------------------------------------

test("checkHeaders: находит заголовки, cookie-флаги и CORS", async (t) => {
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
  t.after(() => closeServer(server));

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
});

test("checkHeaders: небезопасные значения заголовков не дают защиты", async (t) => {
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
  t.after(() => closeServer(server));

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
});

test("checkHeaders: IPv6 в Host-заголовке заключён в скобки", async (t) => {
  let seenHost = "";
  const server = http.createServer((req, res) => {
    seenHost = req.headers.host;
    res.end("ok");
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

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
});

test("checkHeaders: CSP из <meta> читается из тела", async (t) => {
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(
      [
        "<!doctype html><html><head>",
        '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">',
        "</head><body>ok</body></html>",
      ].join(""),
    );
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

  const result = await checkHeaders("127.0.0.1", port, "localhost", 0);

  assert.strictEqual(result.error, undefined);
  assert.strictEqual(result.csp, true);
  assert.strictEqual(result.cspState, "ok");
  // meta не может задавать frame-ancestors — XFO по-прежнему отсутствует.
  assert.strictEqual(result.cspFrameAncestors, false);
  assert.strictEqual(result.xframeState, "missing");
});

test("checkHeaders: несколько CSP-заголовков не склеиваются в weak", async (t) => {
  const server = http.createServer((req, res) => {
    // Два отдельных заголовка CSP: браузер применяет обе политики.
    res.setHeader("Content-Security-Policy", [
      "img-src 'self'",
      "default-src 'self'",
    ]);
    res.end("ok");
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

  const result = await checkHeaders("127.0.0.1", port, "localhost", 0);

  assert.strictEqual(result.csp, true);
  assert.strictEqual(result.cspState, "ok");
});

test("checkHeaders: CSP frame-ancestors засчитывается без X-Frame-Options", async (t) => {
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
    res.end("ok");
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

  const result = await checkHeaders("127.0.0.1", port, "localhost", 0);

  assert.strictEqual(result.cspFrameAncestors, true);
  assert.strictEqual(result.xframeState, "missing");
  assert.strictEqual(result.xframe, false);
});

test("checkHeaders: таймаут на теле не стирает заголовки", async (t) => {
  // Заголовки уже получены, тело не завершается: отчёт по заголовкам
  // обязан вернуться, а не превратиться в error.
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "X-Frame-Options": "DENY" });
    res.write("<html><body>partial");
    // Тело намеренно не завершается.
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

  const result = await checkHeaders(
    "127.0.0.1",
    port,
    "localhost",
    0,
    undefined,
    false,
    300,
  );

  assert.strictEqual(result.error, undefined);
  assert.strictEqual(result.status, 200);
  assert.strictEqual(result.xframe, true);
});

test("checkHeaders: same-origin редирект сохраняет статус конечной страницы", async (t) => {
  const server = http.createServer((req, res) => {
    if (req.url === "/") {
      res.writeHead(302, { Location: "/final" });
      res.end();
      return;
    }
    res.writeHead(200, {
      "X-Frame-Options": "SAMEORIGIN",
      "Content-Security-Policy": "default-src 'self'",
    });
    res.end("ok");
  });
  const port = await listen(server);
  t.after(() => closeServer(server));

  const result = await checkHeaders("127.0.0.1", port, "localhost", 0);

  assert.strictEqual(result.error, undefined);
  assert.strictEqual(result.status, 200);
  // location относится к конечному ответу, у него Location нет.
  assert.strictEqual(result.location, null);
  assert.strictEqual(result.xframe, true);
  assert.strictEqual(result.cspState, "ok");
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
  // Порт закрыт (слушатель освобождён): TCP-отказ, TLS не поднимается.
  const server = net.createServer();
  const port = await listen(server);
  await closeServer(server);

  const result = await checkSSL("127.0.0.1", port, "localhost", null, 0);
  assert.strictEqual(result.hasSSL, false);
  // Отказ соединения — ошибка рукопожатия, а не таймаут и не отмена.
  assert.strictEqual(result.error, "HANDSHAKE_FAILED");
});

// --- Бюджет этапа --------------------------------------------------

test("checkSSL: молчащий TLS-сервер не повторяет попытку без бюджета", async (t) => {
  // Сервер принимает TCP-соединение и не отвечает: клиент обязан выйти по
  // остатку бюджета, а не ждать два полных таймаута с паузой.
  const sockets = new Set();
  let connections = 0;
  const server = net.createServer((socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => sockets.delete(socket));
  });
  const port = await listen(server);
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await closeServer(server);
  });

  const result = await checkSSL(
    "127.0.0.1",
    port,
    "localhost",
    null,
    1,
    5000,
    Date.now() + 300,
  );

  assert.strictEqual(result.hasSSL, false);
  assert.strictEqual(result.error, "TIMEOUT");
  // Дедлайн съеден первой попыткой: ретрай не имеет бюджета и не должен
  // открывать второе соединение. Это и есть проверка «этап ограничен
  // дедлайном» — без зависимости от скорости машины.
  assert.strictEqual(connections, 1);
});

test("checkPort: истёкший дедлайн не открывает сокет", async (t) => {
  const originalConnect = net.Socket.prototype.connect;
  let connectCalls = 0;

  net.Socket.prototype.connect = function () {
    connectCalls += 1;
    return this;
  };
  t.after(() => {
    net.Socket.prototype.connect = originalConnect;
  });

  const result = await checkPort(
    "127.0.0.1",
    80,
    5000,
    1,
    undefined,
    Date.now() - 1,
  );

  assert.strictEqual(result.status, "closed");
  // Локальный отказ до сети: сокет вообще не создавал соединения.
  assert.strictEqual(connectCalls, 0);
});

// --- Инвариант SSRF ------------------------------------------------

test("проверки отказываются от нелитерального connectIp", async () => {
  // Имя хоста увело бы сокет в собственный DNS-резолв Node — это обход
  // проверки адреса, поэтому сокет не должен создаваться вообще.
  const originalConnect = net.Socket.prototype.connect;
  const originalTlsConnect = tls.connect;
  let netConnectCalls = 0;
  let tlsConnectCalls = 0;

  net.Socket.prototype.connect = function () {
    netConnectCalls += 1;
    return this;
  };
  tls.connect = function () {
    tlsConnectCalls += 1;
    throw new Error("tls.connect не должен вызываться");
  };

  try {
    const port = await checkPort("example.com", 80, 1000, 1);
    assert.deepStrictEqual(port, { port: 80, status: "closed" });

    const ssl = await checkSSL("example.com", 443, "example.com", null, 0);
    assert.strictEqual(ssl.hasSSL, false);
    assert.strictEqual(ssl.error, "INVALID_CONNECT_IP");

    const headers = await checkHeaders("example.com", 443, "example.com", 0);
    assert.deepStrictEqual(headers, { error: true });
  } finally {
    net.Socket.prototype.connect = originalConnect;
    tls.connect = originalTlsConnect;
  }

  assert.strictEqual(netConnectCalls, 0);
  assert.strictEqual(tlsConnectCalls, 0);
});

// --- Устойчивость к сбоям ------------------------------------------

test("checkSSL: отменённый сигнал даёт код ABORTED, а не ошибку рукопожатия", async () => {
  const controller = new AbortController();
  controller.abort(); // Сигнал уже отменен

  const result = await checkSSL(
    "127.0.0.1",
    443,
    "localhost",
    controller.signal,
  );

  // Главное: функция не упала с throw, а вернула безопасный объект
  // с различимой причиной — скан отменён, а не TLS сломан.
  assert.strictEqual(result.hasSSL, false);
  assert.strictEqual(result.error, "ABORTED");
});
