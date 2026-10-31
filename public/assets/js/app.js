import { scanTarget } from "./api.js";
import { renderResult } from "./render-result.js";

const form = document.querySelector('[data-js="scan-form"]');
const input = document.querySelector('[data-js="url"]');
const consent = document.querySelector('[data-js="consent"]');
const submitBtn = document.querySelector('[data-js="scan-submit"]');
const resultSection = document.querySelector('[data-js="result"]');
const resultBody = document.querySelector('[data-js="result-body"]');
const formError = document.querySelector('[data-js="form-error"]');
const statusRegion = document.querySelector('[data-js="status"]');
const printBtn = document.querySelector('[data-js="print"]');
const scanStatus = document.querySelector('[data-js="scan-status"]');
const scanStatusText = document.querySelector('[data-js="scan-status-text"]');

const SCAN_IDLE_TEXT = "Проверяем порты, TLS и заголовки…";
let elapsedTimer = 0;

function startScanStatus() {
  // Разметка может быть старой (сервер отдаёт HTML, прочитанный при старте),
  // поэтому индикатор — необязательная часть и не должен ронять скан.
  if (!scanStatus || !scanStatusText) return;

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
  startScanStatus();

  try {
    const data = await scanTarget({ url, consent: isConsent });

    // Сначала убираем индикатор, потом показываем отчёт:
    // иначе страница дёргается уже после переноса фокуса.
    stopScanStatus();

    renderResult(resultSection, resultBody, data);
    statusRegion.textContent = `Отчёт для ${data.host} готов`;

    const resultTitle = resultSection.querySelector(".result__title");
    if (resultTitle) {
      resultTitle.setAttribute("tabindex", "-1");
      resultTitle.focus();
    }
  } catch (error) {
    // Неудачная попытка не должна отнимать уже полученный отчёт
    // (частый случай — 429 после быстрого повторного скана).
    if (hadReport) resultSection.hidden = false;

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

// Ошибка снимается, как только пользователь начал править адрес или
// отметил согласие: держать красную плашку до следующего сабмита нечестно.
input.addEventListener("input", clearError);
consent.addEventListener("change", clearError);
