const test = require("node:test");
const assert = require("node:assert");
const { checkPort } = require("../src/checks");

test("checkPort: закрытый порт не висит вечно", async () => {
  // Стучимся на заведомо закрытый порт
  const result = await checkPort("127.0.0.1", 1, 500, 1);
  assert.strictEqual(result.port, 1);
  // В зависимости от ОС и настроек сети, сервер может явно отказать (refused)
  // или просто не ответить (closed). Нам важно, что он не "open".
  assert.ok(
    ["refused", "closed"].includes(result.status),
    `Ожидали refused или closed, получили: ${result.status}`,
  );
});

test("checkPort: открытый порт определяется", async () => {
  // Запускаем временный сервер на случайном порту
  const net = require("net");
  const server = net.createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  const result = await checkPort("127.0.0.1", port, 1000, 0);
  assert.strictEqual(result.status, "open");

  server.close();
});
