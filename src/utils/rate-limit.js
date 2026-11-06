// Лимиты сканирования без Express и без сети: кулдаун на ключ (IP или /64),
// потолок одновременных сканов и лимит на один ключ. Часы подменяются через
// options.now — поэтому поведение проверяется тестами мгновенно, без sleep.

const DEFAULT_COOLDOWN_MS = 10_000;
const DEFAULT_MAX_KEYS = 10_000;
const DEFAULT_MAX_CONCURRENT = 25;
const DEFAULT_MAX_PER_KEY = 1;
const DEFAULT_SWEEP_INTERVAL_MS = 30_000;

// Сколько ждать после скана: Retry-After для 429 «повторный скан».
const RETRY_AFTER_CONCURRENT = 60;
const RETRY_AFTER_PER_KEY = 10;

// Кулдаун с LRU-вытеснением: Map хранит ключи в порядке вставки, поэтому
// самый старый ключ — это первый элемент. Без потолка карта росла бы от
// каждого нового IP и превратилась в утечку памяти.
class CooldownGate {
  constructor(options = {}) {
    const {
      cooldownMs = DEFAULT_COOLDOWN_MS,
      maxKeys = DEFAULT_MAX_KEYS,
      now = Date.now,
    } = options;

    this.cooldownMs = Number.isFinite(cooldownMs) && cooldownMs >= 0
      ? cooldownMs
      : DEFAULT_COOLDOWN_MS;
    this.maxKeys = Number.isInteger(maxKeys) && maxKeys > 0
      ? maxKeys
      : DEFAULT_MAX_KEYS;
    this.now = typeof now === "function" ? now : Date.now;
    this.entries = new Map();
  }

  get size() {
    return this.entries.size;
  }

  // Сколько секунд осталось ждать. Ключ, который ещё не сканировался,
  // не должен получать «полный кулдаун» — иначе первый же запрос получал бы 429.
  wait(key) {
    if (!this.entries.has(key)) return 0;

    const elapsed = Math.max(0, this.now() - this.entries.get(key));
    if (elapsed >= this.cooldownMs) return 0;

    return Math.ceil((this.cooldownMs - elapsed) / 1000);
  }

  // Отмечает завершение скана и переносит ключ в конец очереди (свежий).
  touch(key) {
    if (this.entries.has(key)) {
      this.entries.delete(key);
    } else if (this.entries.size >= this.maxKeys) {
      this.entries.delete(this.entries.keys().next().value);
    }

    this.entries.set(key, this.now());
    return this;
  }

  // Удаляет истёкшие записи. Вызывается по таймеру, а не на каждом запросе.
  sweep() {
    const now = this.now();
    for (const [key, time] of this.entries.entries()) {
      if (now - time >= this.cooldownMs) this.entries.delete(key);
    }
    return this;
  }

  clear() {
    this.entries.clear();
    return this;
  }
}

// Полный лимит скана: потолок одновременных проверок, лимит на ключ и
// кулдаун после завершения.
class ScanLimiter {
  constructor(options = {}) {
    const {
      maxConcurrent = DEFAULT_MAX_CONCURRENT,
      maxPerKey = DEFAULT_MAX_PER_KEY,
      cooldownMs = DEFAULT_COOLDOWN_MS,
      maxKeys = DEFAULT_MAX_KEYS,
      now = Date.now,
    } = options;

    this.maxConcurrent = Number.isInteger(maxConcurrent) && maxConcurrent > 0
      ? maxConcurrent
      : DEFAULT_MAX_CONCURRENT;
    this.maxPerKey = Number.isInteger(maxPerKey) && maxPerKey > 0
      ? maxPerKey
      : DEFAULT_MAX_PER_KEY;
    this.now = typeof now === "function" ? now : Date.now;
    this.cooldown = new CooldownGate({ cooldownMs, maxKeys, now: this.now });

    this.activeScans = 0;
    this.activeByKey = new Map();
    this.sweeper = null;
  }

  get activeKeys() {
    return this.activeByKey.size;
  }

  get cooldownMs() {
    return this.cooldown.cooldownMs;
  }

  // Пропускает скан или объясняет отказ. null — можно сканировать,
  // иначе { status, retryAfter, error } для прямого ответа клиенту.
  attempt(key) {
    if (this.activeScans >= this.maxConcurrent) {
      return {
        status: 503,
        retryAfter: RETRY_AFTER_CONCURRENT,
        error: "Сервис занят, попробуй через минуту",
      };
    }

    const wait = this.cooldown.wait(key);
    if (wait > 0) {
      return {
        status: 429,
        retryAfter: wait,
        error: `Подожди ${wait} сек. перед следующим сканом`,
      };
    }

    const active = this.activeByKey.get(key) || 0;
    if (active >= this.maxPerKey) {
      return {
        status: 429,
        retryAfter: RETRY_AFTER_PER_KEY,
        error: "С этого адреса уже идёт сканирование, дождись результата",
      };
    }

    this.activeScans += 1;
    this.activeByKey.set(key, active + 1);
    return null;
  }

  // Завершение скана. Кулдаун ставится на любом исходе — включая ошибку
  // резолва и 504. Это осознанно: ответы «приватный адрес» и «DNS не
  // ответил» — тот самый оракул, которым перебирают внутренние имена, а
  // каждый такой запрос уже сходил в резолвер. Плюс 429 говорит, сколько
  // ждать, и валидация (400 «Некорректный адрес») до лимита не доходит,
  // поэтому опечатка в адресе кулдаун не включает.
  finish(key) {
    this.cooldown.touch(key);

    this.activeScans = Math.max(0, this.activeScans - 1);

    const perKey = (this.activeByKey.get(key) || 0) - 1;
    if (perKey > 0) this.activeByKey.set(key, perKey);
    else this.activeByKey.delete(key);
  }

  // Периодическая чистка истёкших записей. unref: таймер не держит процесс.
  startSweeper(intervalMs = DEFAULT_SWEEP_INTERVAL_MS) {
    if (this.sweeper) return this;

    this.sweeper = setInterval(() => this.cooldown.sweep(), intervalMs);
    if (typeof this.sweeper.unref === "function") this.sweeper.unref();
    return this;
  }

  stopSweeper() {
    if (this.sweeper) {
      clearInterval(this.sweeper);
      this.sweeper = null;
    }
    return this;
  }
}

module.exports = {
  CooldownGate,
  ScanLimiter,
  DEFAULT_COOLDOWN_MS,
  DEFAULT_MAX_KEYS,
  DEFAULT_MAX_CONCURRENT,
  DEFAULT_MAX_PER_KEY,
};
