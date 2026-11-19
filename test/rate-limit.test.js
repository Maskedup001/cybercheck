const test = require("node:test");
const assert = require("node:assert");

const {
  CooldownGate,
  ScanLimiter,
  DEFAULT_MAX_PER_EDGE,
} = require("../src/utils/rate-limit");

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

// --- Лимит на сокет-адрес: ротация XFF не расширяет пул -----------------

test("ScanLimiter: лимит на edgeKey блокирует обход через смену ключа (XFF)", () => {
  const limiter = new ScanLimiter({ maxPerEdge: 2, maxConcurrent: 5 });

  // Два запроса с разными clientKey, но с одного edgeKey (сокета)
  assert.strictEqual(limiter.attempt("client1", "edge1"), null);
  assert.strictEqual(limiter.attempt("client2", "edge1"), null);

  // Третий запрос с того же сокета (пусть даже с новым XFF) — блокируется
  const denial = limiter.attempt("client3", "edge1");
  assert.strictEqual(denial.status, 429);
  assert.match(denial.error, /С этого сетевого адреса/);

  // Завершаем один скан, место освобождается
  limiter.finish("client1", "edge1");
  assert.strictEqual(limiter.attempt("client3", "edge1"), null);
});

test("ScanLimiter: DEFAULT_MAX_PER_EDGE — 2", () => {
  assert.strictEqual(DEFAULT_MAX_PER_EDGE, 2);
});

test("ScanLimiter: третий параллельный скан с одного edge блокируется при разных clientKey", () => {
  // Один и тот же сокет-адрес с тремя разными XFF: каждый clientKey проходит
  // лимит на ключ, но edge-счётчик общий, поэтому третий уже нет.
  const limiter = new ScanLimiter({ maxPerEdge: 2, maxConcurrent: 25 });

  assert.strictEqual(limiter.attempt("1.1.1.1", "edge"), null);
  assert.strictEqual(limiter.attempt("2.2.2.2", "edge"), null);

  const denial = limiter.attempt("3.3.3.3", "edge");
  assert.strictEqual(denial.status, 429);
  assert.match(denial.error, /С этого сетевого адреса/);
});

test("ScanLimiter: finish освобождает edge-слот и возвращает limiter", () => {
  const limiter = new ScanLimiter({ maxPerEdge: 1 });

  assert.strictEqual(limiter.attempt("a", "edge"), null);
  assert.strictEqual(limiter.attempt("b", "edge").status, 429);

  const returned = limiter.finish("a", "edge");
  assert.strictEqual(
    returned,
    limiter,
    "finish должен быть chainable, как остальные методы",
  );

  assert.strictEqual(limiter.attempt("b", "edge"), null);
});

test("ScanLimiter: один edge не занимает больше maxPerEdge слотов при большом maxConcurrent", () => {
  const limiter = new ScanLimiter({ maxPerEdge: 2, maxConcurrent: 25 });

  assert.strictEqual(limiter.attempt("client-1", "edge"), null);
  assert.strictEqual(limiter.attempt("client-2", "edge"), null);

  for (const key of ["client-3", "client-4", "client-5"]) {
    const denial = limiter.attempt(key, "edge");
    assert.strictEqual(denial.status, 429, key);
  }

  // Занято ровно 2 из 25 слотов: edge-лимит срабатывает раньше общего.
  assert.strictEqual(limiter.activeScans, 2);
  assert.strictEqual(limiter.activeByKey.size, 2);

  // Другой edge при этом не страдает.
  assert.strictEqual(limiter.attempt("client-6", "other-edge"), null);
  assert.strictEqual(limiter.activeScans, 3);
});

test("ScanLimiter: clientKey и edgeKey не смешиваются", () => {
  const limiter = new ScanLimiter({ maxPerEdge: 1, maxPerKey: 1 });

  assert.strictEqual(limiter.attempt("client-a", "edge-a"), null);

  // Ключ, совпадающий с чужим edgeKey, — это отдельный clientKey: счётчики
  // лежат в разных картах, и он не наследует занятый edge-слот.
  assert.strictEqual(limiter.attempt("edge-a", "edge-b"), null);
  assert.strictEqual(limiter.activeByKey.size, 2);
  assert.strictEqual(limiter.activeByEdge.size, 2);

  // Тот же clientKey блокируется по лимиту на ключ.
  const keyDenial = limiter.attempt("client-a", "edge-b");
  assert.strictEqual(keyDenial.status, 429);
  assert.match(keyDenial.error, /уже идёт сканирование/);

  // Тот же edge с новым clientKey блокируется по лимиту на сокет-адрес.
  const edgeDenial = limiter.attempt("client-b", "edge-a");
  assert.strictEqual(edgeDenial.status, 429);
  assert.match(edgeDenial.error, /С этого сетевого адреса/);
});

test("ScanLimiter: без edgeKey лимит считается по самому ключу", () => {
  const limiter = new ScanLimiter({ maxPerEdge: 1, maxPerKey: 5 });

  assert.strictEqual(limiter.attempt("k"), null);
  assert.strictEqual(limiter.activeByEdge.get("k"), 1);

  const denial = limiter.attempt("k");
  assert.strictEqual(denial.status, 429);
  assert.match(denial.error, /С этого сетевого адреса/);

  limiter.finish("k");
  assert.strictEqual(limiter.activeByEdge.has("k"), false);
});
