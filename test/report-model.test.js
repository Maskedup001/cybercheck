const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const MODEL_PATH = path.join(__dirname, "../public/assets/js/ui/report-model.js");

// report-model.js — ES-модуль без DOM: снимаем export и забираем функции.
function loadModel() {
  const source = fs.readFileSync(MODEL_PATH, "utf8");
  const runnable = source.replace(/^export\s+/gm, "");

  const context = {};
  vm.createContext(context);
  vm.runInContext(
    `${runnable}
     globalThis.__model = {
       sanitizeText,
       plural,
       getCriticalPaths,
       getExposedFiles,
       getProbeStats,
       filesNote,
       tlsNotice,
       caaState,
       secureContextState,
       reportTitleFor,
       buildShareText,
     };`,
    context,
  );

  return context.__model;
}

const model = loadModel();

// Объекты из vm-контекста принадлежат другому realm: deepStrictEqual
// сравнивает прототипы, поэтому приводим их к обычным значениям.
const plain = (value) => JSON.parse(JSON.stringify(value));

function results(items) {
  return items.map(([probePath, status, error = null]) => ({
    path: probePath,
    status,
    exposed: status === 200,
    blocked: status === 403,
    error,
  }));
}

// --- Недоверенный текст -------------------------------------------

test("sanitizeText: убирает управляющие и bidi-символы", () => {
  assert.strictEqual(model.sanitizeText("nginx\u202e1.0\u0000"), "nginx1.0");
  assert.strictEqual(model.sanitizeText("  a\n\tb  "), "a b");
  assert.strictEqual(model.sanitizeText(null), "");
  assert.strictEqual(model.sanitizeText(42), "");
});

test("sanitizeText: ограничивает длину", () => {
  assert.strictEqual(model.sanitizeText("x".repeat(500)).length, 120);
  assert.strictEqual(model.sanitizeText("x".repeat(500), 10).length, 10);
});

// --- Критичность путей только из files.critical --------------------

test("getCriticalPaths: строки и объекты {path}", () => {
  const paths = model.getCriticalPaths({
    critical: ["/.env", { path: "/backup.zip", severity: "high" }, null, 42],
  });

  assert.deepStrictEqual(Array.from(paths), ["/.env", "/backup.zip"]);
  assert.deepStrictEqual(Array.from(model.getCriticalPaths(null)), []);
  assert.deepStrictEqual(Array.from(model.getCriticalPaths({})), []);
});

test("getExposedFiles: объединяет exposed и critical, старый контракт — из results", () => {
  assert.deepStrictEqual(
    plain(
      model.getExposedFiles({
        exposed: ["/.DS_Store"],
        critical: [{ path: "/.env" }],
      }),
    ),
    ["/.DS_Store", "/.env"],
  );

  assert.deepStrictEqual(
    plain(
      model.getExposedFiles({
        results: results([
          ["/.env", 200],
          ["/.git/config", 404],
        ]),
      }),
    ),
    ["/.env"],
  );
});

test("getProbeStats: считает ошибки, блокировки и открытые пути", () => {
  const stats = model.getProbeStats({
    results: results([
      ["/.env", 200],
      ["/.git/config", 403],
      ["/.DS_Store", null, "ETIMEDOUT"],
      ["/backup.zip", 404],
    ]),
  });

  assert.deepStrictEqual(plain(stats), {
    total: 4,
    failed: 1,
    blocked: 1,
    exposed: 1,
  });
});

// --- «Не найдено» только когда всё проверено ---------------

test("filesNote: все пробы упали — «не подтверждено», а не «не найдено»", () => {
  const note = model.filesNote({
    exposed: [],
    blocked: [],
    results: results([
      ["/.env", null, "ETIMEDOUT"],
      ["/.git/config", null, "ETIMEDOUT"],
      ["/.DS_Store", null, "ETIMEDOUT"],
      ["/backup.zip", null, "ETIMEDOUT"],
    ]),
  });

  assert.match(note, /Не удалось проверить ни один из 4 путей/);
  assert.doesNotMatch(note, /Открытых файлов не найдено/);
});

test("filesNote: смешанный результат — N из M", () => {
  const note = model.filesNote({
    exposed: [],
    blocked: ["/.git/config"],
    results: results([
      ["/.env", null, "ETIMEDOUT"],
      ["/.git/config", 403],
      ["/.DS_Store", 404],
      ["/backup.zip", 404],
    ]),
  });

  assert.match(note, /Открытых файлов не найдено/);
  assert.match(note, /Не удалось проверить 1 из 4/);
  assert.match(note, /заблокирован 1 путь \(403\/WAF\)/);
});

test("filesNote: склонение «путь / пути / путей»", () => {
  const noteFor = (blockedCount) => {
    const blocked = Array.from(
      { length: blockedCount },
      (_, i) => `/path-${i}`,
    );
    return model.filesNote({
      exposed: [],
      blocked,
      results: results(blocked.map((path) => [path, 403])),
    });
  };

  assert.match(noteFor(1), /заблокирован 1 путь/);
  assert.match(noteFor(2), /заблокированы 2 пути/);
  assert.match(noteFor(5), /заблокировано 5 путей/);
  assert.match(noteFor(11), /заблокировано 11 путей/);
  assert.match(noteFor(21), /заблокирован 21 путь/);
});

test("filesNote: найдены только низкорисковые пути — без «критично»", () => {
  const note = model.filesNote({
    exposed: ["/.DS_Store"],
    critical: [],
    results: results([["/.DS_Store", 200]]),
  });

  assert.match(note, /\.DS_Store/);
  assert.doesNotMatch(note, /критично/i);
});

test("filesNote: критический путь перечисляется по имени", () => {
  const note = model.filesNote({
    exposed: ["/.env", "/.DS_Store"],
    critical: [{ path: "/.env", severity: "high" }],
    results: results([]),
  });

  assert.match(note, /\/\.env/);
  assert.match(note, /критично/i);
  assert.doesNotMatch(note, /\/\.DS_Store.*критично/i);
});

test("filesNote: files === null — честное «не удалось проверить»", () => {
  assert.match(model.filesNote(null), /Не удалось проверить/);
});

test("filesNote: пустой объект и пустые results — «проверка не выполнялась»", () => {
  assert.match(model.filesNote({}), /не выполнялись/);
  assert.match(
    model.filesNote({ exposed: [], critical: [], results: [] }),
    /не выполнялись/,
  );
  assert.doesNotMatch(model.filesNote({}), /Открытых файлов не найдено/);
});

// --- TLS без веб-порта --------------------------------------------

test("tlsNotice: нет веб-порта — «TLS не проверялся»", () => {
  const text = model.tlsNotice({ hasSSL: false, error: "NO_WEB_PORT" }, []);
  assert.match(text, /не проверялся/);

  assert.match(model.tlsNotice({ hasSSL: false }, []), /не проверялся/);
});

test("tlsNotice: обычные случаи не подменяются", () => {
  assert.strictEqual(model.tlsNotice({ hasSSL: true }, []), null);
  assert.strictEqual(model.tlsNotice({ hasSSL: false }, [{ port: 80 }]), null);
  assert.strictEqual(
    model.tlsNotice({ hasSSL: false, error: "HANDSHAKE_FAILED" }, []),
    null,
  );
});

test("tlsNotice: HTTPS подтверждён, но сертификат не прочитан", () => {
  const text = model.tlsNotice(
    { hasSSL: false, error: "HANDSHAKE_FAILED", tlsConfirmed: true },
    [{ port: 443 }],
  );

  assert.match(text, /HTTPS работает/);
  assert.doesNotMatch(text, /SSL не настроен/);
});

// --- Склонение -----------------------------------------------------

test("plural: 1 путь, 2 пути, 5 путей", () => {
  const forms = ["путь", "пути", "путей"];

  assert.strictEqual(model.plural(1, forms), "путь");
  assert.strictEqual(model.plural(2, forms), "пути");
  assert.strictEqual(model.plural(4, forms), "пути");
  assert.strictEqual(model.plural(5, forms), "путей");
  assert.strictEqual(model.plural(11, forms), "путей");
  assert.strictEqual(model.plural(21, forms), "путь");
  assert.strictEqual(model.plural(22, forms), "пути");
  assert.strictEqual(model.plural(111, forms), "путей");
});

// --- Текст для буфера обмена ---------------------------------------

test("buildShareText: топ-5 находок, без WAF/CMS и с рекомендациями", () => {
  const report = {
    host: "example.com",
    score: 72.4,
    grade: "B",
    findings: [
      {
        id: "no-csp",
        title: "Нет CSP",
        severity: "high",
        recommendation: "Добавьте Content-Security-Policy.",
      },
      {
        id: "waf-detected",
        title: "Обнаружен WAF",
        severity: "low",
        recommendation: "Это не проблема.",
      },
      {
        id: "no-hsts",
        title: "Нет HSTS",
        severity: "medium",
        recommendation: "Добавьте Strict-Transport-Security.",
      },
      {
        id: "no-xframe",
        title: "Нет X-Frame-Options",
        severity: "medium",
        recommendation: "Добавьте X-Frame-Options: DENY.",
      },
      {
        id: "no-xcontent",
        title: "Нет X-Content-Type-Options",
        severity: "low",
        recommendation: "Добавьте nosniff.",
      },
      {
        id: "cookie-no-secure",
        title: "Cookie без Secure",
        severity: "high",
        recommendation: "Поставьте Secure.",
      },
      {
        id: "cms-detected",
        title: "WordPress",
        severity: "low",
        recommendation: "Обновляйте CMS.",
      },
      {
        id: "no-referrer-policy",
        title: "Нет Referrer-Policy",
        severity: "low",
        recommendation: "Добавьте заголовок.",
      },
    ],
  };

  const text = model.buildShareText(report);

  assert.match(text, /example\.com/);
  assert.match(text, /72\/100 \(B\)/);
  assert.match(text, /\[Критично\] Нет CSP/);
  assert.match(text, /\[Важно\] Нет HSTS/);
  assert.match(text, /Добавьте Content-Security-Policy/);
  assert.doesNotMatch(text, /Обнаружен WAF/);
  assert.doesNotMatch(text, /WordPress/);

  // Ровно пять пунктов: 1..5 и никакого шестого.
  assert.match(text, /^5\. /m);
  assert.doesNotMatch(text, /^6\. /m);
  // Обрезанная часть не теряется молча.
  assert.match(text, /ещё 1 замечание/);
});

test("buildShareText: пустой отчёт и отсутствие рекомендации не ломают текст", () => {
  assert.strictEqual(model.buildShareText(null), "");
  assert.strictEqual(model.buildShareText("garbage"), "");

  const text = model.buildShareText({
    host: "",
    score: Number.NaN,
    grade: "?",
    findings: [{ title: "  ", severity: "unknown" }],
  });

  assert.match(text, /отчёт для сайта/);
  assert.match(text, /0\/100 \(\?\)/);
  assert.match(text, /\[Замечание\] Замечание/);
  assert.doesNotMatch(text, /undefined/);
});

// --- CAA: present ещё не значит «ограничивает» ---------------------

test("caaState: iodef-only — weak, обычная запись — ok", () => {
  assert.strictEqual(
    model.caaState({ present: true, restrictive: false }),
    "weak",
  );
  assert.strictEqual(
    model.caaState({ present: true, restrictive: true }),
    "ok",
  );
  // Старый контракт без restrictive считается ограничивающим, как в scoring.
  assert.strictEqual(model.caaState({ present: true }), "ok");
  assert.strictEqual(model.caaState({ present: false }), "missing");
});

test("caaState: неизвестный сбой DNS — unknown, ENODATA — missing", () => {
  assert.strictEqual(
    model.caaState({ present: false, error: "TIMEOUT" }),
    "unknown",
  );
  assert.strictEqual(
    model.caaState({ present: false, error: "ENODATA" }),
    "missing",
  );
  // Apex уже разрешился: ENOTFOUND — сбой резолвера, а не отсутствие записи.
  assert.strictEqual(
    model.caaState({ present: false, error: "ENOTFOUND" }),
    "unknown",
  );
  assert.strictEqual(model.caaState(null), "unknown");
  assert.strictEqual(model.caaState("garbage"), "unknown");
});

// --- HSTS/Secure: когда их вообще можно требовать -------------------

test("secureContextState: HTTPS с валидным сертификатом — ok", () => {
  assert.strictEqual(
    model.secureContextState({ hasSSL: true, valid: true }),
    "ok",
  );
});

test("secureContextState: невалидный сертификат — invalid-cert", () => {
  assert.strictEqual(
    model.secureContextState({ hasSSL: true, valid: false }),
    "invalid-cert",
  );
});

test("secureContextState: HTTP и непроверенный TLS", () => {
  assert.strictEqual(model.secureContextState({ hasSSL: false }), "no-https");
  assert.strictEqual(
    model.secureContextState({ hasSSL: false, error: "HANDSHAKE_FAILED" }),
    "unknown",
  );
  assert.strictEqual(model.secureContextState(null), "unknown");
});

test("secureContextState: HTTPS подтверждён, сертификат не прочитан", () => {
  assert.strictEqual(
    model.secureContextState({
      hasSSL: false,
      error: "HANDSHAKE_FAILED",
      tlsConfirmed: true,
    }),
    "unverified",
  );
});

// --- Имя отчёта ----------------------------------------------------

test("reportTitleFor: имя PDF только для настоящего хоста", () => {
  assert.strictEqual(
    model.reportTitleFor("example.com", "2026-11-05"),
    "CyberCheck_example.com_2026-11-05",
  );

  // host "—" — заглушка нормализации, а не домен.
  assert.strictEqual(model.reportTitleFor("—", "2026-11-05"), "");
  assert.strictEqual(model.reportTitleFor("", "2026-11-05"), "");
  assert.strictEqual(model.reportTitleFor(null, "2026-11-05"), "");

  // Недоверенный host не должен ломать имя файла управляющими символами.
  assert.strictEqual(
    model.reportTitleFor("exa\u202emple.com", "2026-11-05"),
    "CyberCheck_example.com_2026-11-05",
  );
});
