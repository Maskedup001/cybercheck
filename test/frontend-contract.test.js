const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const API_PATH = path.join(ROOT, "public/assets/js/api/client.js");
const RENDER_PATH = path.join(ROOT, "public/assets/js/ui/render-result.js");
const MODEL_PATH = path.join(ROOT, "public/assets/js/ui/report-model.js");

// ES-модули без DOM: снимаем export и забираем нужные функции из контекста.
function loadModule(filePath, names, extraContext = {}) {
  const source = fs.readFileSync(filePath, "utf8");
  const runnable = source.replace(/^export\s+/gm, "");

  const context = {
    AbortController,
    setTimeout,
    clearTimeout,
    console,
    ...extraContext,
  };
  vm.createContext(context);
  vm.runInContext(
    `${runnable}\nglobalThis.__exports = { ${names.join(", ")} };`,
    context,
  );

  return context.__exports;
}

function loadApiNormalizer() {
  return loadModule(API_PATH, ["normalizeFinding"]);
}

// render-result.js — ES-модуль с DOM. Для проверки экспортов достаточно
// заглушек document/window: на загрузке модуль только читает document.title
// и подписывается на beforeprint/afterprint, а рендер вызывается из тестов
// отдельно (DOM-тестов в проекте нет).
function loadRenderModule() {
  const source = fs
    .readFileSync(RENDER_PATH, "utf8")
    .replace(/^import\b[\s\S]*?from\s+["'][^"']+["'];?/m, "")
    .replace(/^export\s+/gm, "");

  const context = {
    document: {
      title: "CyberCheck",
      // Минимальный SVG-DOM: createInfoIcon вызывается только из нового теста,
      // но модуль не должен зависеть от браузера при загрузке.
      createElementNS(namespace, tag) {
        return {
          namespace,
          tag,
          attrs: {},
          children: [],
          setAttribute(name, value) {
            this.attrs[name] = String(value);
          },
          append(...children) {
            this.children.push(...children);
          },
        };
      },
    },
    window: { addEventListener() {} },
    console,
  };
  vm.createContext(context);
  vm.runInContext(
    `${source}
     globalThis.__render = {
       renderResult,
       resetReportTitle,
       createMailCard,
       createHeadersCard,
       createTlsCard,
       createCookieCard,
       createInfoIcon,
       dnsSectionUnavailable,
     };`,
    context,
  );

  return context.__render;
}

// Ответ сервера подменяем: сеть в тестах не нужна.
function loadApiWithResponse(payload) {
  const fakeFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => payload,
  });

  return loadModule(API_PATH, ["scanTarget"], { fetch: fakeFetch });
}

test("api.js нормализует OWASP и не теряет новые поля отчёта", () => {
  const { normalizeFinding } = loadApiNormalizer();

  const finding = normalizeFinding({
    id: "exposed-env",
    title: "Открыт /.env",
    desc: "Файл доступен",
    severity: "high",
    weight: 7,
    owasp: "A03:2021 Injection",
    recommendation: "Закройте доступ",
  });

  assert.strictEqual(finding.owasp, "A03:2021 Injection");
  assert.strictEqual(finding.severity, "high");
  assert.strictEqual(finding.weight, 7);

  const fallback = normalizeFinding({
    title: 42,
    severity: "critical",
    weight: "7",
    owasp: null,
  });

  assert.strictEqual(fallback.title, "Замечание");
  assert.strictEqual(fallback.desc, "");
  assert.strictEqual(fallback.severity, "low");
  assert.strictEqual(fallback.weight, 0);
  assert.strictEqual(fallback.owasp, "");

  const source = fs.readFileSync(API_PATH, "utf8");
  for (const field of ["data.dns", "data.files", "data.securityTxt", "data.fingerprint"]) {
    assert.ok(source.includes(field), `api.js должен сохранять ${field}`);
  }
});

test("api.js: мусорные score/grade/ports не попадают в рендер", async () => {
  const { scanTarget } = loadApiWithResponse({
    host: 42,
    ports: [
      { port: 80, status: "open" },
      { port: 81, status: "closed" },
      { port: "x", status: "open" },
      { port: 443 },
    ],
    score: Number.NaN,
    grade: "__proto__",
    findings: [],
  });

  const data = await scanTarget({ url: "example.com", consent: true });

  assert.strictEqual(data.host, "—");
  // Закрытый порт и запись без числового port отброшены.
  // Array.from — чтобы получить массив текущего realm (vm-массив имеет
  // другой прототип, а deepStrictEqual сравнивает прототипы).
  assert.deepStrictEqual(
    Array.from(data.ports, (port) => port.port),
    [80, 443],
  );
  assert.strictEqual(data.score, 0);
  assert.strictEqual(data.grade, "?");
});

test("api.js: корректные score/grade проходят как есть", async () => {
  const { scanTarget } = loadApiWithResponse({
    host: "example.com",
    ports: [{ port: 443, status: "open" }],
    score: 87.6,
    grade: "B",
    findings: [{ id: "no-csp", severity: "high", weight: 10 }],
  });

  const data = await scanTarget({ url: "example.com", consent: true });

  assert.strictEqual(data.host, "example.com");
  assert.strictEqual(data.score, 87.6);
  assert.strictEqual(data.grade, "B");
  assert.strictEqual(data.findings[0].owasp, "");
});

test("api.js: сетевой сбой и таймаут — понятный русский текст", async () => {
  const failingFetch = loadModule(API_PATH, ["scanTarget"], {
    fetch: async () => {
      throw new TypeError("Failed to fetch");
    },
  });

  await assert.rejects(
    () => failingFetch.scanTarget({ url: "example.com", consent: true }),
    /Не удалось связаться с сервером/,
  );

  const hungFetch = loadModule(API_PATH, ["scanTarget"], {
    fetch: async () => {
      const error = new Error("aborted");
      error.name = "AbortError";
      throw error;
    },
  });

  await assert.rejects(
    () => hungFetch.scanTarget({ url: "example.com", consent: true }),
    /Превышено время ожидания/,
  );
});

test("render-result.js: подсказка — SVG-иконка, а не текстовый символ", () => {
  const render = loadRenderModule();
  const icon = render.createInfoIcon();

  assert.strictEqual(icon.tag, "svg");
  assert.strictEqual(icon.namespace, "http://www.w3.org/2000/svg");
  assert.strictEqual(icon.attrs.class, "tooltip-icon");
  assert.strictEqual(icon.attrs["aria-hidden"], "true");
  assert.strictEqual(icon.attrs.width, "14");
  assert.strictEqual(icon.attrs.height, "14");
  assert.deepStrictEqual(
    Array.from(icon.children, (child) => child.tag),
    ["circle", "line", "line"],
  );
  assert.strictEqual(icon.children[0].attrs.r, "10");

  // Текстовый символ не должен вернуться: он зависит от шрифта и выглядит
  // по-разному на Windows/macOS/Android.
  const source = fs.readFileSync(RENDER_PATH, "utf8");
  assert.strictEqual(source.includes("ⓘ"), false);
  assert.match(source, /term\.append\(createInfoIcon\(\)\)/);

  const details = fs.readFileSync(
    path.join(ROOT, "public/assets/css/components/details.css"),
    "utf8",
  );
  assert.match(details, /\.tooltip-icon\s*\{[^}]*margin-left:\s*4px/s);
  assert.match(details, /\.tooltip-icon\s*\{[^}]*vertical-align:\s*middle/s);
  assert.match(details, /\.tooltip-icon\s*\{[^}]*color:\s*var\(--color-text-muted\)/s);
  assert.doesNotMatch(details, /\.detail__label--hint/);

  const print = fs.readFileSync(
    path.join(ROOT, "public/assets/css/print.css"),
    "utf8",
  );
  assert.match(print, /\.tooltip-icon\s*\{\s*display:\s*none !important/s);
});

test("render-result.js: ENOTFOUND для SPF не выдаётся за отсутствие записи", () => {
  const render = loadRenderModule();

  // SPF: только ENODATA — доказательство отсутствия. ENOTFOUND у apex —
  // сбой/рассинхрон резолвера, поэтому карточка должна писать «не удалось».
  assert.strictEqual(
    render.dnsSectionUnavailable({ present: false, error: "ENOTFOUND" }, [
      "ENODATA",
    ]),
    true,
  );
  assert.strictEqual(
    render.dnsSectionUnavailable({ present: false, error: "ENODATA" }, [
      "ENODATA",
    ]),
    false,
  );

  // DMARC: ENOTFOUND — штатное отсутствие поддоменной записи.
  assert.strictEqual(
    render.dnsSectionUnavailable({ present: false, error: "ENOTFOUND" }),
    false,
  );
  assert.strictEqual(render.dnsSectionUnavailable(null), true);
});

test("render-result.js: экспортируемые функции и безопасный DOM", () => {
  const render = loadRenderModule();
  const source = fs.readFileSync(RENDER_PATH, "utf8");

  // Загрузчик снимает import/export, поэтому одного typeof мало: без
  // `export` модуль исполнится, а app.js упадёт на линковке. Проверяем оба
  // факта — объявление export и то, что функция реально загрузилась.
  for (const name of ["renderResult", "resetReportTitle"]) {
    assert.match(
      source,
      new RegExp(`^export function ${name}\\b`, "m"),
      `${name} должен быть экспортирован`,
    );
    assert.strictEqual(typeof render[name], "function", `${name} не загрузилась`);
  }

  // Карточки — внутренние функции: экспорт им не нужен, важно, что объявлены.
  for (const name of [
    "createMailCard",
    "createHeadersCard",
    "createTlsCard",
    "createCookieCard",
  ]) {
    assert.strictEqual(
      typeof render[name],
      "function",
      `${name} не объявлена в модуле`,
    );
  }

  // Пути и тексты карточек больше не дублируются в рендере.
  assert.strictEqual(source.includes("files.critical"), false);
  assert.strictEqual(source.includes(".innerHTML"), false);
  assert.strictEqual(source.includes("insertAdjacentHTML"), false);

  // Решения о CAA и контексте HSTS/Secure живут в report-model.
  assert.ok(source.includes("caaState("));
  assert.ok(source.includes("secureContextState("));

  // Заголовок вкладки сбрасывается только когда отчёт убран; после печати
  // вкладка остаётся с именем отчёта.
  const pageTitleAssignments = source.match(/document\.title\s*=\s*PAGE_TITLE\b/g) || [];
  assert.strictEqual(
    pageTitleAssignments.length,
    1,
    "PAGE_TITLE должен ставиться только в resetReportTitle",
  );
  assert.match(
    source,
    /addEventListener\("afterprint"[\s\S]*?document\.title = reportTitle \|\| PAGE_TITLE/,
  );

  const model = fs.readFileSync(MODEL_PATH, "utf8");
  assert.ok(model.includes("files.critical"), "report-model.js читает files.critical");
  assert.ok(model.includes("failed"), "report-model.js считает упавшие пробы");
});
