const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");
const API_PATH = path.join(ROOT, "public/assets/js/api.js");
const RENDER_PATH = path.join(ROOT, "public/assets/js/render-result.js");

function loadApiNormalizer() {
  const source = fs.readFileSync(API_PATH, "utf8");
  const runnable = source.replace(
    "export async function scanTarget",
    "async function scanTarget",
  );
  const context = {
    AbortController,
    setTimeout,
    clearTimeout,
    console,
    __exports: null,
  };
  vm.createContext(context);
  vm.runInContext(`${runnable}\nglobalThis.__exports = { normalizeFinding };`, context);
  return context.__exports;
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

test("render-result.js содержит новые карточки, OWASP-бейдж и безопасный DOM", () => {
  const source = fs.readFileSync(RENDER_PATH, "utf8");

  for (const token of [
    "createMailCard",
    "createCookieCard",
    "createTechCard",
    "createFilesCard",
    "securityTxtValue",
    "finding__owasp",
    "detail__file-item",
    "files.critical",
  ]) {
    assert.ok(source.includes(token), `render-result.js должен содержать ${token}`);
  }

  assert.strictEqual(source.includes(".innerHTML"), false);
  assert.strictEqual(source.includes("insertAdjacentHTML"), false);
});
