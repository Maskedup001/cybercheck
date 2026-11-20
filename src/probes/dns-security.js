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

// redirect=<domain> — валидный механизм RFC 7208: политика домена берётся из
// SPF другого домена. Проверяем только форму значения (непустой domain-spec,
// допускаем макросы); DNS-резолв здесь не нужен и не делается.
const SPF_REDIRECT_PREFIX_RE = /^redirect=/i;
const SPF_REDIRECT_VALUE_RE = /^[a-z0-9._%{}@+-]+$/i;

function isSpfRedirect(mechanism) {
  if (!SPF_REDIRECT_PREFIX_RE.test(mechanism)) return false;
  const domain = mechanism.slice("redirect=".length).trim();
  return domain !== "" && SPF_REDIRECT_VALUE_RE.test(domain);
}

// SPF, который разрешает отправку всем (+all / ?all) или не содержит
// механизмов, защитой не является: по RFC 7208 такой домен либо открыт для
// подделки, либо получает permerror. -all и ~all считаются рабочими.
//
// redirect=<domain> без all — тоже полноценная политика: правила берутся из
// SPF другого домена, поэтому неявный ?all здесь не действует.
function spfIsWeak(record) {
  const mechanisms = String(record).trim().split(/\s+/).slice(1);
  if (mechanisms.length === 0) return true;

  let hasRedirect = false;
  for (const mechanism of mechanisms) {
    if (SPF_REDIRECT_PREFIX_RE.test(mechanism)) {
      if (isSpfRedirect(mechanism)) hasRedirect = true;
      continue;
    }
    if (!/^[+\-~?]?all$/i.test(mechanism)) continue;
    const qualifier = /^[+\-~?]/.test(mechanism) ? mechanism[0] : "+";
    return qualifier === "+" || qualifier === "?";
  }

  // Нет ни all, ни redirect — по RFC 7208 действует неявный ?all. Это не
  // защита: домен не сообщает получателю, что делать с чужими письмами.
  return !hasRedirect;
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
      sp: null,
      pct: null,
      pctInvalid: false,
      partial: false,
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

  // sp — политика для поддоменов (RFC 7489 §6.3). Нужна, когда запись
  // находится на организационном домене, а сканируется поддомен.
  const rawSubdomainPolicy = tags.get("sp");
  const subdomainPolicy = rawSubdomainPolicy
    ? rawSubdomainPolicy.toLowerCase()
    : null;
  const validSubdomainPolicy =
    subdomainPolicy === "none" ||
    subdomainPolicy === "quarantine" ||
    subdomainPolicy === "reject"
      ? subdomainPolicy
      : null;

  // pct (RFC 7489) — доля писем, к которым применяется политика. Значение вне
  // 0..100 — мусор: отдаём null, чтобы «pct=150» не выглядел полной политикой.
  const pctTag = tags.get("pct");
  let pct = null;
  if (pctTag !== undefined) {
    const trimmedPct = pctTag.trim();
    if (/^\d{1,3}$/.test(trimmedPct)) {
      const value = Number(trimmedPct);
      if (value >= 0 && value <= 100) pct = value;
    }
  }

  // Политика reject/quarantine применяется полностью только при pct=100 или
  // без pct: при pct<100 часть писем политику не получает. Мусорное значение
  // (pct=150) — тоже не подтверждение полной политики.
  const pctMissing = pctTag === undefined;
  const pctInvalid = !pctMissing && pct === null;
  const appliesFully = pctMissing || pct === 100;

  return {
    present: true,
    record,
    policy: validPolicy,
    sp: validSubdomainPolicy,
    pct,
    pctInvalid,
    partial: pct !== null && pct < 100,
    strict:
      (validPolicy === "reject" || validPolicy === "quarantine") &&
      appliesFully,
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
    sp: null,
    pct: null,
    pctInvalid: false,
    partial: false,
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

// Распространённые многоуровневые публичные суффиксы (приближение PSL без
// внешней зависимости). Для остальных доменов организационный домен — две
// последние метки. Этого достаточно, чтобы `www.example.com` и
// `www.example.co.uk` проверялись по `example.com` / `example.co.uk`, а не
// получали ложное «нет DMARC/CAA» на поддомене.
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "com.br",
  "com.cn",
  "com.tw",
  "com.hk",
  "co.kr",
  "co.in",
  "co.za",
  "com.mx",
  "com.ar",
  "com.tr",
  "com.sg",
  "com.my",
  "co.id",
  "co.th",
  "com.vn",
  "com.ph",
  "com.pk",
  "com.ua",
  "com.pl",
  "co.il",
  "com.sa",
  "com.eg",
  "com.ng",
  "co.ke",
  "github.io",
  "pages.dev",
  "vercel.app",
  "netlify.app",
  "herokuapp.com",
  "azurewebsites.net",
  "cloudfront.net",
  "blogspot.com",
  "wordpress.com",
]);

function registrableDomain(host) {
  const value = typeof host === "string" ? host.trim().toLowerCase() : "";
  if (!value || net.isIP(value)) return null;

  const labels = value.replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length < 2) return null;

  const lastTwo = labels.slice(-2).join(".");
  const take = MULTI_LABEL_SUFFIXES.has(lastTwo) ? 3 : 2;
  return labels.slice(Math.max(0, labels.length - take)).join(".");
}

// Кандидаты для CAA: подъём по дереву от хоста до организационного домена
// (RFC 8659). Именно так поступает удостоверяющий центр: CAA на example.com
// действует и для www.example.com.
function caaLookups(host, orgDomain) {
  const labels = host.replace(/\.$/, "").toLowerCase().split(".").filter(Boolean);
  const candidates = [];

  for (let index = 0; index <= labels.length - 2; index += 1) {
    const candidate = labels.slice(index).join(".");
    candidates.push(candidate);
    if (orgDomain && candidate === orgDomain) break;
  }

  return candidates.length > 0 ? candidates : [host];
}

function isMissingDnsError(error) {
  return error === "ENODATA" || error === "ENOTFOUND";
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

  const orgDomain = registrableDomain(host);
  const inherited = orgDomain && orgDomain !== host ? orgDomain : null;
  const caaCandidates = caaLookups(host, orgDomain);

  // Все запросы идут параллельно, у каждого свой таймаут. Для поддомена
  // дополнительно проверяются SPF/DMARC организационного домена и CAA
  // каждого родителя.
  const spfHostPromise = runDnsQuery(
    () => resolver.resolveTxt(host),
    timeoutMs,
    signal,
  );
  const dmarcHostPromise = runDnsQuery(
    () => resolver.resolveTxt(`_dmarc.${host}`),
    timeoutMs,
    signal,
  );
  const spfOrgPromise = inherited
    ? runDnsQuery(() => resolver.resolveTxt(inherited), timeoutMs, signal)
    : Promise.resolve(null);
  const dmarcOrgPromise = inherited
    ? runDnsQuery(
        () => resolver.resolveTxt(`_dmarc.${inherited}`),
        timeoutMs,
        signal,
      )
    : Promise.resolve(null);
  const caaPromises = caaCandidates.map((candidate) =>
    runDnsQuery(() => resolver.resolveCaa(candidate), timeoutMs, signal),
  );

  const [spfHost, dmarcHost, spfOrg, dmarcOrg, ...caaResults] =
    await Promise.all([
      spfHostPromise,
      dmarcHostPromise,
      spfOrgPromise,
      dmarcOrgPromise,
      ...caaPromises,
    ]);

  // Если сигнал отменили, пока запросы летели, все секции помечаем ABORTED.
  if (signal?.aborted) return abortedResult();

  let spf;
  if (spfHost.ok) {
    spf = { ...parseSpfTxt(spfHost.value), error: null };
  } else if (isMissingDnsError(spfHost.error) && spfOrg && spfOrg.ok) {
    const parent = parseSpfTxt(spfOrg.value);
    // SPF не наследуется поддоменами: запись example.com не разрешает
    // отправку от www.example.com. Поэтому present остаётся false, но
    // сохраняем контекст, чтобы отчёт не выглядел как «у домена вообще нет
    // SPF» и не советовал чинить уже настроенный родительский домен.
    spf = parent.present
      ? {
          ...emptySpf(null),
          inheritedFrom: inherited,
          parentPresent: true,
        }
      : emptySpf(spfHost.error);
  } else {
    spf = emptySpf(spfHost.error);
  }

  let dmarc;
  if (dmarcHost.ok) {
    const parsed = parseDmarcTxt(dmarcHost.value);
    // TXT-записи на _dmarc.<host> могут быть, но без v=DMARC1: это всё равно
    // «своей политики нет», поэтому смотрим организационный домен.
    if (!parsed.present && dmarcOrg && dmarcOrg.ok) {
      const parent = parseDmarcTxt(dmarcOrg.value);
      if (parent.present) {
        const effectivePolicy = parent.sp || parent.policy;
        dmarc = {
          ...parent,
          policy: effectivePolicy,
          error: null,
          inheritedFrom: inherited,
          spApplied: Boolean(parent.sp),
        };
      } else {
        dmarc = { ...parsed, error: null };
      }
    } else {
      dmarc = { ...parsed, error: null };
    }
  } else if (isMissingDnsError(dmarcHost.error) && dmarcOrg) {
    if (dmarcOrg.ok) {
      const parent = parseDmarcTxt(dmarcOrg.value);
      if (parent.present) {
        // Для поддомена действует sp (если задана), иначе p родительского
        // домена. Это то, что реально применит почтовый сервер получателя.
        const effectivePolicy = parent.sp || parent.policy;
        dmarc = {
          ...parent,
          policy: effectivePolicy,
          error: null,
          inheritedFrom: inherited,
          spApplied: Boolean(parent.sp),
        };
      } else {
        dmarc = emptyDmarc(dmarcHost.error);
      }
    } else if (!isMissingDnsError(dmarcOrg.error)) {
      // Своей записи нет, а родительскую проверить не удалось: «DMARC нет»
      // было бы ложью — политику родителя мы не видели.
      dmarc = emptyDmarc(dmarcOrg.error);
    } else {
      dmarc = emptyDmarc(dmarcHost.error);
    }
  } else {
    dmarc = emptyDmarc(dmarcHost.error);
  }

  let caa = null;
  for (let index = 0; index < caaResults.length; index += 1) {
    const result = caaResults[index];
    if (result.ok && Array.isArray(result.value) && result.value.length > 0) {
      caa = {
        ...parseCaaRecords(result.value),
        error: null,
        foundAt: caaCandidates[index],
      };
      break;
    }
  }

  if (!caa) {
    const failed = caaResults.find(
      (result) => !result.ok && !isMissingDnsError(result.error),
    );
    caa = emptyCaa(failed ? failed.error : caaResults[0]?.error || "ENODATA");
  }

  return { applicable: true, spf, dmarc, caa };
}

module.exports = {
  parseSpfTxt,
  parseDmarcTxt,
  parseCaaRecords,
  registrableDomain,
  checkDnsSecurity,
};
