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

async function handleSubmit(event) {
  event.preventDefault();

  formError.hidden = true;
  formError.textContent = "";
  resultSection.hidden = true;
  input.removeAttribute("aria-invalid");

  const url = input.value.trim();
  const isConsent = consent.checked;

  if (!url) {
    formError.textContent = "Введи адрес сайта";
    formError.hidden = false;
    input.setAttribute("aria-invalid", "true");
    input.focus();
    return;
  }

  if (!isConsent) {
    formError.textContent = "Подтверди согласие на проверку";
    formError.hidden = false;
    consent.focus();
    return;
  }

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
    formError.textContent = `Ошибка: ${error.message}`;
    formError.hidden = false;
    statusRegion.textContent = "Ошибка сканирования";
    input.setAttribute("aria-invalid", "true");
  } finally {
    stopScanStatus();
    submitBtn.disabled = false;
    submitBtn.textContent = "Проверить";
    form.removeAttribute("aria-busy");
  }
}

form.addEventListener("submit", handleSubmit);
printBtn.addEventListener("click", () => window.print());

// Ошибка снимается, как только пользователь начал править адрес:
// держать красную плашку и aria-invalid до следующего сабмита нечестно.
input.addEventListener("input", () => {
  if (formError.hidden) return;

  formError.hidden = true;
  formError.textContent = "";
  input.removeAttribute("aria-invalid");
});
