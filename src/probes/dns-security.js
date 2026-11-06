const net = require("node:net");
const dns = require("node:dns").promises;

// DNS/email-проверки (SPF, DMARC, CAA) — это запросы к DNS-резолверу, а не
// сетевые соединения с целевым хостом. Правило SSRF про connectIp относится
// к HTTP/TCP-пробам (порты, TLS, HTTP): здесь мы не открываем сокет на
// целевой адрес, поэтому connectIp для TXT/CAA-запросов не нужен и не
// используется.
const DEFAULT_TIMEOUT_MS = 3000;

// Штатные ответы DNS, при которых записей просто нет. Возвращаем их кодом,
// а не текстом ошибки.
const KNOWN_DNS_ERRORS = new Set([
  "ENODATA",
  "ENOTFOUND",
  "ETIMEOUT",
  "ESERVFAIL",
]);

// Склеивает chunks каждого TXT-рекорда в одну строку.
// dns.resolveTxt возвращает string[][]: один TXT-рекорд может быть разбит
// на несколько частей по 255 байт.
function joinTxtRecords(records) {
  if (!Array.isArray(records)) return [];

  return records.map((chunks) => {
    if (Array.isArray(chunks)) {
      return chunks.map((chunk) => String(chunk ?? "")).join("");
    }
    return String(chunks ?? "");
  });
}

// SPF, который разрешает отправку всем (+all / ?all) или не содержит
// механизмов, защитой не является: по RFC 7208 такой домен либо открыт для
// подделки, либо получает permerror. -all и ~all считаются рабочими.
function spfIsWeak(record) {
  const mechanisms = String(record).trim().split(/\s+/).slice(1);
  if (mechanisms.length === 0) return true;

  for (const mechanism of mechanisms) {
    if (!/^[+\-~?]?all$/i.test(mechanism)) continue;
    const qualifier = /^[+\-~?]/.test(mechanism) ? mechanism[0] : "+";
    return qualifier === "+" || qualifier === "?";
  }

  // Нет механизма all — по RFC 7208 действует неявный ?all. Это не защита:
  // домен не сообщает получателю, что делать с чужими письмами.
  return true;
}

// Ищет SPF-запись среди TXT-рекордов.
// SPF начинается с "v=spf1" (без учёта регистра), после версии должен быть
// пробел или конец строки — так "v=spf10" не считается SPF.
// multiple — несколько SPF-записей: по RFC 7208 это permerror, а не защита.
function parseSpfTxt(records) {
  // TXT-запись может прийти с ведущими/хвостовыми пробелами: RFC 7208
  // разрешает их вокруг версии, а без trim `v=spf1` не распознавался бы.
  const txtRecords = joinTxtRecords(records).map((txt) => txt.trim());
  const spfRecords = txtRecords.filter((txt) =>
    /^v=spf1(?:\s|$)/i.test(txt),
  );

  if (spfRecords.length === 0) {
    return { present: false, record: null, multiple: false, weak: false };
  }

  const record = spfRecords[0];

  return {
    present: true,
    record,
    multiple: spfRecords.length > 1,
    weak: spfIsWeak(record),
  };
}

// Ищет DMARC-запись и разбирает её теги.
// Теги разделены ';', значения могут содержать пробелы, поэтому ключ и
// значение обрезаются. Политика p приводится к нижнему регистру.
// multiple — несколько DMARC-записей: по RFC 7489 они не применяются,
// поэтому такая запись не должна давать баллов.
function parseDmarcTxt(records) {
  const txtRecords = joinTxtRecords(records).map((txt) => txt.trim());
  const matches = txtRecords.filter((txt) =>
    /^v=DMARC1(?:;|\s|$)/i.test(txt),
  );
  const multiple = matches.length > 1;
  const record = matches[0];

  if (!record) {
    return {
      present: false,
      record: null,
      policy: null,
      strict: false,
      weak: false,
      multiple: false,
      error: null,
    };
  }

  const tags = new Map();
  for (const part of record.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;

    const key = part.slice(0, separator).trim().toLowerCase();
    const value = part.slice(separator + 1).trim();

    // Первое вхождение тега считаем основным (дубликаты не перетирают его).
    if (key && !tags.has(key)) tags.set(key, value);
  }

  const rawPolicy = tags.get("p");
  const policy = rawPolicy ? rawPolicy.toLowerCase() : null;
  const validPolicy =
    policy === "none" || policy === "quarantine" || policy === "reject"
      ? policy
      : null;

  return {
    present: true,
    record,
    policy: validPolicy,
    strict: validPolicy === "reject" || validPolicy === "quarantine",
    weak: validPolicy === "none",
    multiple,
    error: null,
  };
}

// Приводит ответ dns.resolveCaa к единому виду.
// Сами CAA-записи (critical/issue/issuewild/iodef) отдаём как есть.
// restrictive — есть issue/issuewild: только они ограничивают выпуск
// сертификатов. Запись iodef — это адрес для отчётов, а не ограничение.
function parseCaaRecords(records) {
  if (!Array.isArray(records)) {
    return { present: false, records: [], restrictive: false, error: null };
  }

  const restrictive = records.some(
    (record) =>
      record &&
      typeof record === "object" &&
      (record.issue !== undefined || record.issuewild !== undefined),
  );

  return {
    present: records.length > 0,
    records,
    restrictive,
    error: null,
  };
}

function emptySpf(error = null) {
  return { present: false, record: null, multiple: false, weak: false, error };
}

function emptyDmarc(error = null) {
  return {
    present: false,
    record: null,
    policy: null,
    strict: false,
    weak: false,
    multiple: false,
    error,
  };
}

function emptyCaa(error = null) {
  return { present: false, records: [], restrictive: false, error };
}

// Для известных DNS-кодов отдаём код, для остальных — текст ошибки.
function formatDnsError(err) {
  if (typeof err === "string") return err;

  if (err && typeof err === "object") {
    if (KNOWN_DNS_ERRORS.has(err.code)) return err.code;
    if (typeof err.message === "string" && err.message) return err.message;
    if (typeof err.code === "string" && err.code) return err.code;
  }

  return String(err);
}

// Оборачивает один DNS-запрос в Promise.race: результат, таймаут или отмена.
// Таймер и обработчик abort всегда снимаются, чтобы не держать event loop.
function runDnsQuery(run, timeoutMs, signal) {
  const task = Promise.resolve().then(async () => {
    // Если сигнал отменили до запуска запроса — не трогаем резолвер.
    if (signal?.aborted) return { ok: false, error: "ABORTED" };

    try {
      return { ok: true, value: await run() };
    } catch (err) {
      return { ok: false, error: formatDnsError(err) };
    }
  });

  let timer = null;
  let onAbort = null;

  const timeout = new Promise((resolve) => {
    timer = setTimeout(
      () => resolve({ ok: false, error: "TIMEOUT" }),
      timeoutMs,
    );
  });

  const aborted = new Promise((resolve) => {
    if (!signal) return;

    if (signal.aborted) {
      resolve({ ok: false, error: "ABORTED" });
      return;
    }

    onAbort = () => resolve({ ok: false, error: "ABORTED" });
    signal.addEventListener("abort", onAbort, { once: true });
  });

  return Promise.race([task, timeout, aborted]).finally(() => {
    clearTimeout(timer);
    if (signal && onAbort) signal.removeEventListener("abort", onAbort);
  });
}

function abortedResult() {
  return {
    applicable: true,
    spf: emptySpf("ABORTED"),
    dmarc: emptyDmarc("ABORTED"),
    caa: emptyCaa("ABORTED"),
  };
}

// Проверяет SPF, DMARC и CAA для домена.
//
// ВАЖНО: это DNS-запросы к резолверу, а не соединения с целевым хостом.
// Правило SSRF (connectIp) применяется к HTTP/TCP-пробам, а не к DNS
// TXT/CAA: здесь мы не подключаемся к проверяемому адресу.
async function checkDnsSecurity(hostname, options = {}) {
  const host = typeof hostname === "string" ? hostname.trim() : "";

  // Для IP и localhost SPF/DMARC/CAA не имеют смысла — резолвер не вызываем.
  if (net.isIP(host) || host.toLowerCase() === "localhost") {
    return {
      applicable: false,
      spf: emptySpf(),
      dmarc: emptyDmarc(),
      caa: emptyCaa(),
    };
  }

  const resolver = options.resolver || dns;
  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? Math.max(0, options.timeoutMs)
    : DEFAULT_TIMEOUT_MS;
  const signal = options.signal;

  if (signal?.aborted) return abortedResult();

  // Все три запроса идут параллельно, у каждого свой таймаут.
  const [spfResult, dmarcResult, caaResult] = await Promise.all([
    runDnsQuery(() => resolver.resolveTxt(host), timeoutMs, signal),
    runDnsQuery(() => resolver.resolveTxt(`_dmarc.${host}`), timeoutMs, signal),
    runDnsQuery(() => resolver.resolveCaa(host), timeoutMs, signal),
  ]);

  // Если сигнал отменили, пока запросы летели, все секции помечаем ABORTED.
  if (signal?.aborted) return abortedResult();

  const spf = spfResult.ok
    ? { ...parseSpfTxt(spfResult.value), error: null }
    : emptySpf(spfResult.error);

  const dmarc = dmarcResult.ok
    ? { ...parseDmarcTxt(dmarcResult.value), error: null }
    : emptyDmarc(dmarcResult.error);

  const caa = caaResult.ok
    ? { ...parseCaaRecords(caaResult.value), error: null }
    : emptyCaa(caaResult.error);

  return { applicable: true, spf, dmarc, caa };
}

module.exports = {
  parseSpfTxt,
  parseDmarcTxt,
  parseCaaRecords,
  checkDnsSecurity,
};
