const test = require("node:test");
const assert = require("node:assert");

const { CooldownGate, ScanLimiter } = require("../src/rate-limit");

// Часы подменяются: кулдаун 10 секунд проверяется мгновенно, без sleep и
// без флейков на медленном CI.
function fakeClock(start = 1_000_000) {
  let current = start;

  return {
    now: () => current,
    advance: (ms) => {
      current += ms;
    },
  };
}

// --- Кулдаун -------------------------------------------------------

test("CooldownGate: первый раз не ждём, повтор — 10 секунд", () => {
  const clock = fakeClock();
  const gate = new CooldownGate({ now: clock.now });

  assert.strictEqual(gate.wait("203.0.113.5"), 0);

  gate.touch("203.0.113.5");
  assert.strictEqual(gate.wait("203.0.113.5"), 10);

  clock.advance(4000);
  assert.strictEqual(gate.wait("203.0.113.5"), 6);

  clock.advance(6000);
  assert.strictEqual(gate.wait("203.0.113.5"), 0);
});

test("CooldownGate: повторный touch продлевает кулдаун", () => {
  const clock = fakeClock();
  const gate = new CooldownGate({ now: clock.now });

  gate.touch("k");
  clock.advance(9000);
  gate.touch("k");
  assert.strictEqual(gate.wait("k"), 10);

  clock.advance(10_000);
  assert.strictEqual(gate.wait("k"), 0);
});

test("CooldownGate: старые ключи вытесняются, свежие остаются", () => {
  const clock = fakeClock();
  const gate = new CooldownGate({ maxKeys: 2, now: clock.now });

  gate.touch("a");
  clock.advance(1000);
  gate.touch("b");
  clock.advance(1000);
  gate.touch("a"); // "a" снова свежий, теперь первым должен уйти "b"
  clock.advance(1000);
  gate.touch("c");

  assert.strictEqual(gate.size, 2);
  assert.strictEqual(gate.wait("b"), 0);
  assert.ok(gate.wait("a") > 0);
  assert.strictEqual(gate.wait("c"), 10);
});

test("CooldownGate: sweep убирает только истёкшие записи", () => {
  const clock = fakeClock();
  const gate = new CooldownGate({ now: clock.now });

  gate.touch("old");
  clock.advance(5000);
  gate.touch("fresh");

  clock.advance(5000);
  gate.sweep();

  assert.strictEqual(gate.wait("old"), 0);
  assert.strictEqual(gate.size, 1);
  assert.ok(gate.wait("fresh") > 0);
});

// --- Лимиты сканирования -------------------------------------------

test("ScanLimiter: второй скан с того же ключа — 429 с Retry-After", () => {
  const clock = fakeClock();
  const limiter = new ScanLimiter({ now: clock.now });

  assert.strictEqual(limiter.attempt("k"), null);

  const denial = limiter.attempt("k");
  assert.strictEqual(denial.status, 429);
  assert.strictEqual(denial.retryAfter, 10);
  assert.match(denial.error, /уже идёт сканирование/);

  limiter.finish("k");
  assert.strictEqual(limiter.activeScans, 0);

  // После завершения кулдаун отсчитывается заново.
  const cooled = limiter.attempt("k");
  assert.strictEqual(cooled.status, 429);
  assert.strictEqual(cooled.retryAfter, 10);
  assert.match(cooled.error, /^Подожди 10 сек/);
});

test("ScanLimiter: кулдаун ставится и после неуспешного скана", () => {
  // Осознанное решение: ответы «приватный адрес» и «DNS не ответил» — оракул
  // для перебора внутренних имён, поэтому 10 секунд действуют и на ошибке.
  // Валидация (400 «Некорректный адрес») до лимита не доходит и кулдаун
  // не включает.
  const clock = fakeClock();
  const limiter = new ScanLimiter({ now: clock.now });

  assert.strictEqual(limiter.attempt("k"), null);
  limiter.finish("k"); // скан завершился ошибкой — сервер вызывает тот же finish

  const denial = limiter.attempt("k");
  assert.strictEqual(denial.status, 429);
  assert.ok(denial.retryAfter > 0);

  clock.advance(10_000);
  assert.strictEqual(limiter.attempt("k"), null);
});

test("ScanLimiter: потолок одновременных сканов — 503 с Retry-After 60", () => {
  const limiter = new ScanLimiter({ maxConcurrent: 1 });

  assert.strictEqual(limiter.attempt("a"), null);

  const denial = limiter.attempt("b");
  assert.strictEqual(denial.status, 503);
  assert.strictEqual(denial.retryAfter, 60);
  assert.match(denial.error, /Сервис занят/);

  // 503 не ставит кулдаун: после освобождения места тот же клиент проходит.
  limiter.finish("a");
  assert.strictEqual(limiter.attempt("b"), null);
});

test("ScanLimiter: разные ключи не мешают друг другу", () => {
  const limiter = new ScanLimiter({ maxPerKey: 2 });

  assert.strictEqual(limiter.attempt("a"), null);
  assert.strictEqual(limiter.attempt("b"), null);
  assert.strictEqual(limiter.attempt("a"), null);
  assert.strictEqual(limiter.activeScans, 3);
  assert.strictEqual(limiter.activeKeys, 2);

  // Третий скан с того же ключа уже не проходит — ключ «a» исчерпан.
  const denial = limiter.attempt("a");
  assert.strictEqual(denial.status, 429);
  assert.match(denial.error, /уже идёт сканирование/);

  // Завершаем ровно те три скана, которые были допущены.
  limiter.finish("a");
  limiter.finish("b");
  limiter.finish("a");
  assert.strictEqual(limiter.activeScans, 0);
  assert.strictEqual(limiter.activeKeys, 0);
});

test("ScanLimiter: лишний finish не уводит счётчики в минус", () => {
  const limiter = new ScanLimiter();

  limiter.finish("nobody");
  limiter.finish("nobody");

  assert.strictEqual(limiter.activeScans, 0);
  assert.strictEqual(limiter.activeKeys, 0);
});

test("ScanLimiter: таймер чистки включается и выключается", () => {
  const limiter = new ScanLimiter();

  limiter.startSweeper(60_000);
  assert.ok(limiter.sweeper);
  limiter.startSweeper(60_000); // второй вызов не создаёт второй таймер

  limiter.stopSweeper();
  assert.strictEqual(limiter.sweeper, null);
});
