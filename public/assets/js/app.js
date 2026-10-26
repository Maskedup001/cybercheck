import { scanTarget } from "./api.js";
import { renderResult } from "./render-result.js";

// Находим все элементы через data-js (как в топовых проектах)
const form = document.querySelector('[data-js="scan-form"]');
const input = document.querySelector('[data-js="url"]');
const consent = document.querySelector('[data-js="consent"]');
const submitBtn = document.querySelector('[data-js="scan-submit"]');
const resultSection = document.querySelector('[data-js="result"]');
const resultBody = document.querySelector('[data-js="result-body"]');
const formError = document.querySelector('[data-js="form-error"]');
const statusRegion = document.querySelector('[data-js="status"]');
const printBtn = document.querySelector('[data-js="print"]');

async function handleSubmit(e) {
  e.preventDefault();
  formError.hidden = true;
  resultSection.hidden = true;
  input.removeAttribute("aria-invalid");

  const url = input.value.trim();
  const isConsent = consent.checked;

  // Валидация UX
  if (!url) {
    formError.textContent = "Введи адрес сайта";
    formError.hidden = false;
    return;
  }
  if (!isConsent) {
    formError.textContent = "Подтверди согласие на проверку";
    formError.hidden = false;
    return;
  }

  // Состояние загрузки
  submitBtn.disabled = true;
  submitBtn.textContent = "Проверяем...";
  statusRegion.textContent = "Сканирование началось";
  form.setAttribute("aria-busy", "true");

  try {
    const data = await scanTarget({ url, consent: isConsent });
    renderResult(resultSection, resultBody, data);
    statusRegion.textContent = `Отчёт для ${data.host} готов`;
  } catch (error) {
    formError.textContent = `Ошибка: ${error.message}`;
    formError.hidden = false;
    statusRegion.textContent = "Ошибка сканирования";
    input.setAttribute("aria-invalid", "true");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Проверить";
    form.removeAttribute("aria-busy");
  }
}

form.addEventListener("submit", handleSubmit);
printBtn.addEventListener("click", () => window.print());
