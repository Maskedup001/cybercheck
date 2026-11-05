const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const MODEL_PATH = path.join(__dirname, "../public/assets/js/report-model.js");

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
       getCriticalPaths,
       getExposedFiles,
       getProbeStats,
       filesNote,
       tlsNotice,
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
  assert.strictEqual(
    model.sanitizeText("nginx\u202e1.0\u0000"),
    "nginx1.0",
  );
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
  assert.match(note, /1 путей заблокировано/);
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

// --- TLS без веб-порта --------------------------------------------

test("tlsNotice: нет веб-порта — «TLS не проверялся»", () => {
  const text = model.tlsNotice({ hasSSL: false, error: "NO_WEB_PORT" }, []);
  assert.match(text, /не проверялся/);

  assert.match(
    model.tlsNotice({ hasSSL: false }, []),
    /не проверялся/,
  );
});

test("tlsNotice: обычные случаи не подменяются", () => {
  assert.strictEqual(model.tlsNotice({ hasSSL: true }, []), null);
  assert.strictEqual(model.tlsNotice({ hasSSL: false }, [{ port: 80 }]), null);
  assert.strictEqual(
    model.tlsNotice({ hasSSL: false, error: "HANDSHAKE_FAILED" }, []),
    null,
  );
});
