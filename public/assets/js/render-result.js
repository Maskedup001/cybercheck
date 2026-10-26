export function renderResult(container, body, report) {
  // 1. Заполняем шапку через безопасный textContent
  document.querySelector('[data-js="report-host"]').textContent = report.host;
  const dateStr = new Date().toLocaleString("ru-RU");
  document.querySelector('[data-js="report-date"]').textContent = dateStr;
  document.querySelector('[data-js="report-date-footer"]').textContent = dateStr;

  // Очищаем контейнер от предыдущих отчетов
  body.replaceChildren();

  // Хелпер: создание статуса (зеленый/красный бейджик)
  function createStatus(isGood, text) {
    const span = document.createElement("span");
    span.className = `result__status result__status--${isGood ? "good" : "bad"}`;
    span.textContent = text;
    return span;
  }

  // Хелпер: создание строки отчета (dt + dd)
  function createRow(labelText, valueNode) {
    const row = document.createElement("div");
    row.className = "result__row";

    const dt = document.createElement("dt");
    dt.className = "result__label";
    dt.textContent = labelText;

    const dd = document.createElement("dd");
    dd.className = "result__value";
    
    if (typeof valueNode === "string") {
      dd.textContent = valueNode;
    } else {
      dd.appendChild(valueNode); // Если передан готовый элемент (бейджик)
    }

    row.append(dt, dd);
    return row;
  }

  // Хелпер: создание секции с заголовком
  function createSection(titleText) {
    const section = document.createElement("div");
    section.className = "result__section";
    
    const title = document.createElement("h3");
    title.className = "result__section-title";
    title.textContent = titleText;
    
    const rowsContainer = document.createElement("div");
    rowsContainer.className = "result__rows";
    
    section.append(title, rowsContainer);
    return { section, rowsContainer };
  }

  // --- СЕКЦИЯ: ПОРТЫ ---
  const ports = createSection("Порты");
  if (report.ports.length === 0) {
    const p = document.createElement("p");
    p.className = "result__value";
    p.textContent = "Открытых портов не найдено";
    ports.rowsContainer.appendChild(p);
  } else {
    report.ports.forEach((p) => {
      const status = createStatus(true, "открыт");
      ports.rowsContainer.appendChild(createRow(`Порт ${p.port}`, status));
    });
  }
  body.appendChild(ports.section);

  // --- СЕКЦИЯ: SSL ---
  const ssl = createSection("SSL");
  if (report.ssl.hasSSL) {
    const status = createStatus(report.ssl.valid, report.ssl.valid ? "валиден" : "невалиден");
    ssl.rowsContainer.appendChild(createRow("Сертификат", status));

    if (!report.ssl.valid && report.ssl.verifyError) {
      const errStatus = createStatus(false, report.ssl.verifyError);
      ssl.rowsContainer.appendChild(createRow("Причина", errStatus));
    }
    ssl.rowsContainer.appendChild(createRow("Истекает", report.ssl.validTo || "н/д"));
    ssl.rowsContainer.appendChild(createRow("Издатель", report.ssl.issuer || "неизвестен"));
  } else {
    const status = createStatus(false, "SSL отсутствует");
    ssl.rowsContainer.appendChild(createRow("Статус", status));
  }
  body.appendChild(ssl.section);

  // --- СЕКЦИЯ: ЗАГОЛОВКИ БЕЗОПАСНОСТИ ---
  const headers = createSection("Заголовки безопасности");
  const h = report.headers;
  
  if (h.error) {
    const status = createStatus(false, "Не удалось получить");
    headers.rowsContainer.appendChild(createRow("Статус", status));
  } else {
    headers.rowsContainer.appendChild(createRow("Server", h.server));
    headers.rowsContainer.appendChild(createRow("Протокол", h.protocol));
    
    const headersList = [
      { name: "Content-Security-Policy", val: h.csp },
      { name: "X-Frame-Options", val: h.xframe },
      { name: "Strict-Transport-Security", val: h.hsts },
      { name: "X-Content-Type-Options", val: h.xcontent },
    ];

    headersList.forEach((item) => {
      const status = createStatus(item.val, item.val ? "есть" : "НЕТ");
      headers.rowsContainer.appendChild(createRow(item.name, status));
    });
  }
  body.appendChild(headers.section);

  // Показываем результат
  container.hidden = false;
}