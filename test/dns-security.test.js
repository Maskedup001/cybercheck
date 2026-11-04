const test = require("node:test");
const assert = require("node:assert");

const {
  parseSpfTxt,
  parseDmarcTxt,
  parseCaaRecords,
  checkDnsSecurity,
} = require("../src/dns-security");

// Фейковый резолвер: никаких реальных DNS-запросов.
// txt/caa — объекты вида { "имя": records } или { "имя": Error }.
function makeResolver({ txt = {}, caa = {} } = {}) {
  const calls = [];

  return {
    calls,
    async resolveTxt(name) {
      calls.push({ type: "TXT", name });
      const value = txt[name];
      if (value instanceof Error) throw value;
      return value ?? [];
    },
    async resolveCaa(name) {
      calls.push({ type: "CAA", name });
      const value = caa[name];
      if (value instanceof Error) throw value;
      return value ?? [];
    },
  };
}

function dnsError(code) {
  const err = new Error(`query failed: ${code}`);
  err.code = code;
  return err;
}

const notApplicable = {
  applicable: false,
  spf: { present: false, record: null, multiple: false, weak: false, error: null },
  dmarc: {
    present: false,
    record: null,
    policy: null,
    strict: false,
    weak: false,
    multiple: false,
    error: null,
  },
  caa: { present: false, records: [], restrictive: false, error: null },
};

// --- SPF ------------------------------------------------------------------

test("parseSpfTxt: находит SPF и склеивает chunks", () => {
  const result = parseSpfTxt([
    ["v=spf1 ", "include:_spf.example.com ", "-all"],
  ]);

  assert.deepStrictEqual(result, {
    present: true,
    record: "v=spf1 include:_spf.example.com -all",
    multiple: false,
    weak: false,
  });
});

test("parseSpfTxt: возвращает absent, если SPF нет", () => {
  assert.deepStrictEqual(
    parseSpfTxt([
      ["google-site-verification=abc"],
      ["v=spf10 -all"], // не SPF: после версии нет пробела/конца строки
    ]),
    { present: false, record: null, multiple: false, weak: false },
  );

  assert.deepStrictEqual(parseSpfTxt([]), {
    present: false,
    record: null,
    multiple: false,
    weak: false,
  });
});

test("parseSpfTxt: несколько SPF-записей помечает multiple", () => {
  const result = parseSpfTxt([
    ["other=1"],
    ["v=spf1 include:first.example -all"],
    ["v=spf1 include:second.example -all"],
  ]);

  assert.deepStrictEqual(result, {
    present: true,
    record: "v=spf1 include:first.example -all",
    multiple: true,
    weak: false,
  });
});

test("parseSpfTxt: версия не чувствительна к регистру", () => {
  const result = parseSpfTxt([["V=SPF1 -all"]]);

  assert.deepStrictEqual(result, {
    present: true,
    record: "V=SPF1 -all",
    multiple: false,
    weak: false,
  });
});

test("parseSpfTxt: +all, ?all и пустой SPF помечаются weak", () => {
  for (const record of [
    "v=spf1 +all",
    "v=spf1 ?all",
    "v=spf1 all",
    "v=spf1",
    "v=spf1 ",
  ]) {
    const result = parseSpfTxt([[record]]);
    assert.strictEqual(result.present, true, record);
    assert.strictEqual(result.weak, true, `должен быть weak: ${record}`);
  }

  // -all и ~all — рабочие конфигурации, слабыми не считаются.
  for (const record of ["v=spf1 -all", "v=spf1 ~all"]) {
    assert.strictEqual(parseSpfTxt([[record]]).weak, false, record);
  }
});

// --- DMARC ----------------------------------------------------------------

test("parseDmarcTxt: p=reject считается strict", () => {
  const record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com";

  assert.deepStrictEqual(parseDmarcTxt([[record]]), {
    present: true,
    record,
    policy: "reject",
    strict: true,
    weak: false,
    multiple: false,
    error: null,
  });
});

test("parseDmarcTxt: p=quarantine считается strict", () => {
  const record = "v=DMARC1; p=quarantine; pct=100";

  assert.deepStrictEqual(parseDmarcTxt([[record]]), {
    present: true,
    record,
    policy: "quarantine",
    strict: true,
    weak: false,
    multiple: false,
    error: null,
  });
});

test("parseDmarcTxt: p=none считается weak", () => {
  const record = "v=DMARC1; p=none";

  assert.deepStrictEqual(parseDmarcTxt([[record]]), {
    present: true,
    record,
    policy: "none",
    strict: false,
    weak: true,
    multiple: false,
    error: null,
  });
});

test("parseDmarcTxt: отсутствие DMARC-записи", () => {
  const expected = {
    present: false,
    record: null,
    policy: null,
    strict: false,
    weak: false,
    multiple: false,
    error: null,
  };

  assert.deepStrictEqual(parseDmarcTxt([["v=spf1 -all"]]), expected);
  assert.deepStrictEqual(parseDmarcTxt([]), expected);
});

test("parseDmarcTxt: несколько DMARC-записей помечаются multiple", () => {
  const result = parseDmarcTxt([
    ["v=DMARC1; p=reject"],
    ["v=DMARC1; p=none"],
  ]);

  assert.strictEqual(result.present, true);
  assert.strictEqual(result.multiple, true);
  // Поля первой записи сохраняются: решение принимает scoring, а не парсер.
  assert.strictEqual(result.policy, "reject");
});

test("parseDmarcTxt: некорректная политика даёт policy=null", () => {
  const record = "v=DMARC1; p=maybe; rua=mailto:dmarc@example.com";

  assert.deepStrictEqual(parseDmarcTxt([[record]]), {
    present: true,
    record,
    policy: null,
    strict: false,
    weak: false,
    multiple: false,
    error: null,
  });

  // Без тега p политики тоже нет.
  assert.strictEqual(parseDmarcTxt([["v=DMARC1; sp=none"]]).policy, null);
});

test("parseDmarcTxt: разбирает теги с пробелами вокруг значений", () => {
  const result = parseDmarcTxt([
    ["v=dmarc1; p = Reject ; sp = none"],
  ]);

  assert.strictEqual(result.present, true);
  assert.strictEqual(result.policy, "reject");
  assert.strictEqual(result.strict, true);
  assert.strictEqual(result.weak, false);
});

// --- CAA ------------------------------------------------------------------

test("parseCaaRecords: возвращает непустые CAA-записи", () => {
  const records = [
    { critical: 0, issue: "letsencrypt.org" },
    { critical: 0, iodef: "mailto:security@example.com" },
  ];

  assert.deepStrictEqual(parseCaaRecords(records), {
    present: true,
    records,
    restrictive: true,
    error: null,
  });
});

test("parseCaaRecords: только iodef не ограничивает выпуск", () => {
  const records = [{ critical: 0, iodef: "mailto:security@example.com" }];

  const result = parseCaaRecords(records);
  assert.strictEqual(result.present, true);
  assert.strictEqual(result.restrictive, false);
});

test("parseCaaRecords: issuewild тоже ограничение", () => {
  const result = parseCaaRecords([
    { critical: 0, issuewild: "letsencrypt.org" },
  ]);
  assert.strictEqual(result.restrictive, true);
});

test("parseCaaRecords: пустой массив", () => {
  assert.deepStrictEqual(parseCaaRecords([]), {
    present: false,
    records: [],
    restrictive: false,
    error: null,
  });
});

test("checkDnsSecurity: ошибка CAA возвращается в caa.error", async () => {
  const resolver = makeResolver({
    txt: {},
    caa: { "example.com": dnsError("ESERVFAIL") },
  });

  const result = await checkDnsSecurity("example.com", { resolver });

  assert.strictEqual(result.applicable, true);
  assert.deepStrictEqual(result.caa, {
    present: false,
    records: [],
    restrictive: false,
    error: "ESERVFAIL",
  });
});

// --- checkDnsSecurity -----------------------------------------------------

test("checkDnsSecurity: IP и localhost не применимы и не дергают резолвер", async () => {
  for (const hostname of ["127.0.0.1", "::1", "localhost"]) {
    let calls = 0;
    const resolver = {
      async resolveTxt() {
        calls += 1;
        return [];
      },
      async resolveCaa() {
        calls += 1;
        return [];
      },
    };

    const result = await checkDnsSecurity(hostname, { resolver });

    assert.deepStrictEqual(result, notApplicable);
    assert.strictEqual(calls, 0, `резолвер не должен вызываться для ${hostname}`);
  }
});

test("checkDnsSecurity: собирает SPF, DMARC и CAA", async () => {
  const caaRecords = [{ critical: 0, issue: "letsencrypt.org" }];
  const resolver = makeResolver({
    txt: {
      "example.com": [["v=spf1 ", "include:_spf.example.com -all"]],
      "_dmarc.example.com": [
        ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"],
      ],
    },
    caa: { "example.com": caaRecords },
  });

  const result = await checkDnsSecurity("example.com", { resolver });

  assert.deepStrictEqual(result, {
    applicable: true,
    spf: {
      present: true,
      record: "v=spf1 include:_spf.example.com -all",
      multiple: false,
      weak: false,
      error: null,
    },
    dmarc: {
      present: true,
      record: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
      policy: "quarantine",
      strict: true,
      weak: false,
      multiple: false,
      error: null,
    },
    caa: {
      present: true,
      records: caaRecords,
      restrictive: true,
      error: null,
    },
  });

  // Все три запроса уходят параллельно и именно с нужными именами.
  assert.deepStrictEqual(resolver.calls, [
    { type: "TXT", name: "example.com" },
    { type: "TXT", name: "_dmarc.example.com" },
    { type: "CAA", name: "example.com" },
  ]);
});

test("checkDnsSecurity: известные DNS-ошибки возвращаются кодом, без throw", async () => {
  for (const code of ["ENODATA", "ENOTFOUND", "ETIMEOUT", "ESERVFAIL"]) {
    const resolver = makeResolver({
      txt: {
        "example.com": dnsError(code),
        "_dmarc.example.com": dnsError(code),
      },
      caa: { "example.com": dnsError(code) },
    });

    const result = await checkDnsSecurity("example.com", { resolver });

    assert.deepStrictEqual(result, {
      applicable: true,
      spf: {
        present: false,
        record: null,
        multiple: false,
        weak: false,
        error: code,
      },
      dmarc: {
        present: false,
        record: null,
        policy: null,
        strict: false,
        weak: false,
        multiple: false,
        error: code,
      },
      caa: { present: false, records: [], restrictive: false, error: code },
    });
  }
});

test("checkDnsSecurity: неожиданная ошибка возвращается текстом, без throw", async () => {
  const unexpected = new Error("resolver exploded");
  unexpected.code = "EUNEXPECTED";

  const resolver = makeResolver({
    txt: {
      "example.com": unexpected,
      "_dmarc.example.com": unexpected,
    },
    caa: { "example.com": unexpected },
  });

  const result = await checkDnsSecurity("example.com", { resolver });

  assert.strictEqual(result.spf.error, "resolver exploded");
  assert.strictEqual(result.dmarc.error, "resolver exploded");
  assert.strictEqual(result.caa.error, "resolver exploded");
});

test("checkDnsSecurity: каждый запрос завершается по таймауту", async () => {
  let calls = 0;
  const resolver = {
    resolveTxt() {
      calls += 1;
      return new Promise(() => {}); // никогда не резолвится
    },
    resolveCaa() {
      calls += 1;
      return new Promise(() => {});
    },
  };

  const result = await checkDnsSecurity("example.com", {
    resolver,
    timeoutMs: 20,
  });

  assert.strictEqual(calls, 3);
  assert.deepStrictEqual(result, {
    applicable: true,
    spf: {
      present: false,
      record: null,
      multiple: false,
      weak: false,
      error: "TIMEOUT",
    },
    dmarc: {
      present: false,
      record: null,
      policy: null,
      strict: false,
      weak: false,
      multiple: false,
      error: "TIMEOUT",
    },
    caa: { present: false, records: [], restrictive: false, error: "TIMEOUT" },
  });
});

test("checkDnsSecurity: отменённый signal даёт ABORTED, без throw", async () => {
  const controller = new AbortController();
  controller.abort();

  let calls = 0;
  const resolver = {
    async resolveTxt() {
      calls += 1;
      return [];
    },
    async resolveCaa() {
      calls += 1;
      return [];
    },
  };

  const result = await checkDnsSecurity("example.com", {
    resolver,
    signal: controller.signal,
  });

  assert.deepStrictEqual(result, {
    applicable: true,
    spf: {
      present: false,
      record: null,
      multiple: false,
      weak: false,
      error: "ABORTED",
    },
    dmarc: {
      present: false,
      record: null,
      policy: null,
      strict: false,
      weak: false,
      multiple: false,
      error: "ABORTED",
    },
    caa: { present: false, records: [], restrictive: false, error: "ABORTED" },
  });
  assert.strictEqual(calls, 0);
});
