import { scanTarget } from "./api/client.js";
import { renderResult, resetReportTitle } from "./ui/render-result.js";
import { buildShareText } from "./ui/report-model.js";

const form = document.querySelector('[data-js="scan-form"]');
const input = document.querySelector('[data-js="url"]');
const consent = document.querySelector('[data-js="consent"]');
const submitBtn = document.querySelector('[data-js="scan-submit"]');
const resultSection = document.querySelector('[data-js="result"]');
const resultBody = document.querySelector('[data-js="result-body"]');
const formError = document.querySelector('[data-js="form-error"]');
const statusRegion = document.querySelector('[data-js="status"]');
const printBtn = document.querySelector('[data-js="print"]');
const copyBtn = document.querySelector('[data-js="copy"]');
const copyStatus = document.querySelector('[data-js="copy-status"]');
const scanStatus = document.querySelector('[data-js="scan-status"]');
const scanStatusText = document.querySelector('[data-js="scan-status-text"]');

const SCAN_IDLE_TEXT = "Проверяем порты, TLS и заголовки…";
const COPY_IDLE_TEXT = "Скопировать отчёт";
let elapsedTimer = 0;
let feedbackTimer = 0;
// Последний удачный отчёт: копирование не должно зависеть от DOM и от того,
// какая вкладка фильтра открыта.
let lastReport = null;

function startScanStatus() {
  // Разметка может быть старой (сервер отдаёт HTML, прочитанный при старте),
  // поэтому индикатор — необязательная часть и не должен ронять скан.
  if (!scanStatus || !scanStatusText) return;

  // Повторный вход (программный submit, bfcache) не должен оставлять
  // второй setInterval: иначе таймеры копятся и пишут в один узел.
  stopScanStatus();

  const startedAt = Date.now();

  scanStatus.hidden = false;
  scanStatusText.textContent = SCAN_IDLE_TEXT;

  elapsedTimer = window.setInterval(() => {
    const seconds = Math.round((Date.now() - startedAt) / 1000);
    scanStatusText.textContent = `Проверяем порты, TLS и заголовки · ${seconds} с`;
  }, 1000);
}

function stopScanStatus() {
  window.clearInterval(elapsedTimer);
  elapsedTimer = 0;

  if (scanStatus) scanStatus.hidden = true;
}

function clearError() {
  if (formError.hidden) return;

  formError.hidden = true;
  formError.textContent = "";
  input.removeAttribute("aria-invalid");
  consent.removeAttribute("aria-invalid");
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

function setCopyFeedback(message) {
  if (!copyStatus) return;

  window.clearTimeout(feedbackTimer);
  copyStatus.textContent = message;
  feedbackTimer = window.setTimeout(() => {
    copyStatus.textContent = "";
  }, 4000);
}

async function copyReport() {
  if (!lastReport || !copyBtn) return;

  const text = buildShareText(lastReport);

  try {
    // Clipboard API доступен только в защищённом контексте (HTTPS или
    // localhost). Если его нет или браузер отказал — честно говорим об этом,
    // а не делаем вид, что отчёт скопирован.
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      throw new Error("clipboard-unavailable");
    }

    await navigator.clipboard.writeText(text);

    copyBtn.textContent = "Скопировано";
    setCopyFeedback("Отчёт скопирован в буфер обмена.");
    window.setTimeout(() => {
      copyBtn.textContent = COPY_IDLE_TEXT;
    }, 2500);
  } catch {
    copyBtn.textContent = "Не удалось";
    setCopyFeedback(
      "Браузер не дал доступ к буферу обмена. Выделите текст отчёта вручную.",
    );
    window.setTimeout(() => {
      copyBtn.textContent = COPY_IDLE_TEXT;
    }, 2500);
  }
}

async function handleSubmit(event) {
  event.preventDefault();

  clearError();

  const url = input.value.trim();
  const isConsent = consent.checked;

  if (!url) {
    // Плашка одна на всю форму, поэтому aria-invalid ставим ровно на то
    // поле, о котором она говорит: иначе скринридер объявит неверным
    // соседний контрол.
    showError("Введи адрес сайта");
    input.setAttribute("aria-invalid", "true");
    input.focus();
    return;
  }

  if (!isConsent) {
    showError("Подтверди согласие на проверку");
    consent.setAttribute("aria-invalid", "true");
    consent.focus();
    return;
  }

  // Прячем предыдущий отчёт только когда скан действительно стартовал:
  // ошибка валидации не должна стирать уже полученный результат.
  const hadReport = !resultSection.hidden;

  resultSection.hidden = true;
  submitBtn.disabled = true;
  submitBtn.textContent = "Проверяем…";
  statusRegion.textContent = "Сканирование началось";
  form.setAttribute("aria-busy", "true");
  if (copyBtn) copyBtn.textContent = COPY_IDLE_TEXT;
  if (copyStatus) copyStatus.textContent = "";
  startScanStatus();

  try {
    const data = await scanTarget({ url, consent: isConsent });

    // Сначала убираем индикатор, потом показываем отчёт:
    // иначе страница дёргается уже после переноса фокуса.
    stopScanStatus();

    renderResult(resultSection, resultBody, data);
    lastReport = data;
    // host "—" — заглушка нормализации: «Отчёт для — готов» выглядит поломкой.
    statusRegion.textContent =
      data.host && data.host !== "—" ? `Отчёт для ${data.host} готов` : "Отчёт готов";

    const resultTitle = resultSection.querySelector(".result__title");
    if (resultTitle) {
      resultTitle.setAttribute("tabindex", "-1");
      resultTitle.focus();
    }
  } catch (error) {
    // Неудачная попытка не должна отнимать уже полученный отчёт
    // (частый случай — 429 после быстрого повторного скана).
    if (hadReport) resultSection.hidden = false;
    else {
      // Без отчёта в заголовке вкладки не должно оставаться имени прошлого
      // сайта: иначе пустая страница печатается с чужим названием.
      resetReportTitle();
      lastReport = null;
    }

    const message = error instanceof Error ? error.message : "неизвестная ошибка";

    // Сетевой сбой, таймаут и 429 к содержимому поля отношения не имеют:
    // aria-invalid на адресе только сбивал бы с толку.
    showError(`Ошибка: ${message}`);
    statusRegion.textContent = "Ошибка сканирования";
  } finally {
    stopScanStatus();
    submitBtn.disabled = false;
    submitBtn.textContent = "Проверить";
    form.removeAttribute("aria-busy");
  }
}

form.addEventListener("submit", handleSubmit);
printBtn.addEventListener("click", () => window.print());

if (copyBtn) {
  copyBtn.addEventListener("click", copyReport);
}

// Ctrl+P доступен и без кнопки: печать до первого скана давала пустой A4 с
// одной шапкой. Класс на body прячет разметку и показывает пояснение.
function syncPrintState() {
  document.body.classList.toggle("is-print-empty", resultSection.hidden);
}

window.addEventListener("beforeprint", syncPrintState);
window.addEventListener("afterprint", () => {
  document.body.classList.remove("is-print-empty");
});

// Ошибка снимается, как только пользователь начал править адрес или
// отметил согласие: держать красную плашку до следующего сабмита нечестно.
input.addEventListener("input", clearError);
consent.addEventListener("change", clearError);
