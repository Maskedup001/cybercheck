import { escapeHtml } from "./escape-html.js";

export function renderResult(container, body, report) {
  // 1. Заполняем шапку
  document.querySelector('[data-js="report-host"]').textContent = report.host;
  const dateStr = new Date().toLocaleString("ru-RU");
  document.querySelector('[data-js="report-date"]').textContent = dateStr;
  document.querySelector('[data-js="report-date-footer"]').textContent =
    dateStr;

  // 2. Строим тело отчета (через безопасные шаблоны + escapeHtml)
  let out = "";

  out += `<div class="result__section">
    <h3 class="result__section-title">Порты</h3>`;

  if (report.ports.length === 0) {
    out += `<p class="result__value">Открытых портов не найдено</p>`;
  } else {
    out += `<div class="result__rows">`;
    report.ports.forEach((p) => {
      out += `<div class="result__row">
        <dt class="result__label">Порт ${p.port}</dt>
        <dd class="result__value"><span class="result__status result__status--good">открыт</span></dd>
      </div>`;
    });
    out += `</div>`;
  }
  out += `</div>`;

  out += `<div class="result__section">
    <h3 class="result__section-title">SSL</h3>
    <div class="result__rows">`;

  if (report.ssl.hasSSL) {
    const statusClass = report.ssl.valid ? "good" : "bad";
    const statusText = report.ssl.valid ? "валиден" : "невалиден";
    out += `<div class="result__row">
      <dt class="result__label">Сертификат</dt>
      <dd class="result__value"><span class="result__status result__status--${statusClass}">${statusText}</span></dd>
    </div>`;
    if (!report.ssl.valid && report.ssl.verifyError) {
      out += `<div class="result__row">
        <dt class="result__label">Причина</dt>
        <dd class="result__value"><span class="result__status result__status--bad">${escapeHtml(report.ssl.verifyError)}</span></dd>
      </div>`;
    }
    out += `<div class="result__row"><dt class="result__label">Истекает</dt><dd class="result__value">${escapeHtml(report.ssl.validTo || "н/д")}</dd></div>`;
    out += `<div class="result__row"><dt class="result__label">Издатель</dt><dd class="result__value">${escapeHtml(report.ssl.issuer || "неизвестен")}</dd></div>`;
  } else {
    out += `<div class="result__row"><dd class="result__value"><span class="result__status result__status--bad">SSL отсутствует</span></dd></div>`;
  }
  out += `</div></div>`;

  out += `<div class="result__section">
    <h3 class="result__section-title">Заголовки безопасности</h3>`;

  const h = report.headers;
  if (h.error) {
    out += `<p class="result__value"><span class="result__status result__status--bad">Не удалось получить</span></p>`;
  } else {
    const checkHeader = (val) =>
      val
        ? `<span class="result__status result__status--good">есть</span>`
        : `<span class="result__status result__status--bad">НЕТ</span>`;

    out += `<div class="result__rows">
      <div class="result__row"><dt class="result__label">Server</dt><dd class="result__value">${escapeHtml(h.server)}</dd></div>
      <div class="result__row"><dt class="result__label">Протокол</dt><dd class="result__value">${escapeHtml(h.protocol)}</dd></div>
      <div class="result__row"><dt class="result__label">Content-Security-Policy</dt><dd class="result__value">${checkHeader(h.csp)}</dd></div>
      <div class="result__row"><dt class="result__label">X-Frame-Options</dt><dd class="result__value">${checkHeader(h.xframe)}</dd></div>
      <div class="result__row"><dt class="result__label">Strict-Transport-Security</dt><dd class="result__value">${checkHeader(h.hsts)}</dd></div>
      <div class="result__row"><dt class="result__label">X-Content-Type-Options</dt><dd class="result__value">${checkHeader(h.xcontent)}</dd></div>
    </div>`;
  }
  out += `</div>`;

  // Вставляем безопасно, так как все данные извне обернуты в escapeHtml
  body.innerHTML = out;
  container.hidden = false; // Показываем блок
}
