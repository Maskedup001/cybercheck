/* Рендер отчёта: оценка → что чинить → детали проверки.
   Только DOM API и textContent, без innerHTML и инлайн-разметки. */

const PAGE_TITLE = document.title;
let reportTitle = "";

const GRADE_LABELS = {
  A: "Отличная защита",
  B: "Хорошая защита",
  C: "Средняя защита",
  D: "Слабая защита",
  E: "Высокий риск",
  F: "Критический риск",
};

const SEVERITY = {
  high: { label: "Критично", tone: "bad" },
  medium: { label: "Важно", tone: "warn" },
  low: { label: "Замечание", tone: "muted" },
};

const PORT_TONES = { 80: "ok", 443: "ok", 22: "bad", 3306: "bad", 8080: "warn" };
const PORT_LABELS = { ok: "открыт", bad: "опасный", warn: "риск" };

function plural(count, forms) {
  const abs = Math.abs(count) % 100;
  const last = abs % 10;

  if (abs > 10 && abs < 20) return forms[2];
  if (last > 1 && last < 5) return forms[1];
  if (last === 1) return forms[0];
  return forms[2];
}

function toneForGrade(grade) {
  if (grade === "A" || grade === "B") return "good";
  if (grade === "C") return "warn";
  return "bad";
}

function createBadge(tone, text) {
  const badge = document.createElement("span");
  badge.className = `badge badge--${tone}`;
  badge.textContent = text;
  return badge;
}

function describeFindings(findings) {
  if (findings.length === 0) {
    return "Замечаний нет — базовая гигиена в порядке.";
  }

  const total = `${findings.length} ${plural(findings.length, ["замечание", "замечания", "замечаний"])}`;
  const critical = findings.filter((item) => item.severity === "high").length;

  if (critical === 0) return `${total}, критичных нет.`;

  const criticalText = `${critical} ${plural(critical, ["критичное", "критичных", "критичных"])}`;
  return `${total}, из них ${criticalText}.`;
}

function createScore(report, score) {
  const tone = toneForGrade(report.grade);

  const block = document.createElement("div");
  block.className = `score score--${tone}`;

  const gauge = document.createElement("div");
  gauge.className = "score__gauge";

  const gaugeBody = document.createElement("div");
  gaugeBody.className = "score__gauge-body";

  const grade = document.createElement("span");
  grade.className = "score__grade";
  grade.textContent = report.grade;

  const value = document.createElement("span");
  value.className = "score__value";
  value.textContent = `${score}/100`;

  gaugeBody.append(grade, value);
  gauge.append(gaugeBody);

  const verdict = document.createElement("div");
  verdict.className = "score__verdict";

  const title = document.createElement("p");
  title.className = "score__title";
  title.textContent = GRADE_LABELS[report.grade] ?? "Оценка";

  const text = document.createElement("p");
  text.className = "score__text";
  text.textContent = describeFindings(report.findings);

  verdict.append(title, text);
  block.append(gauge, verdict);

  return { block, gauge };
}

function createFindings(findings) {
  const section = document.createElement("section");
  section.className = "findings";

  const title = document.createElement("h3");
  title.className = "result__section-title";
  title.textContent = findings.length === 0 ? "Замечаний нет" : "Что исправить";
  section.append(title);

  if (findings.length === 0) {
    const clean = document.createElement("div");
    clean.className = "findings__clean";

    const mark = document.createElement("span");
    mark.className = "findings__clean-mark";
    mark.setAttribute("aria-hidden", "true");
    mark.textContent = "✓";

    const text = document.createElement("p");
    text.textContent = "Порты, сертификат и заголовки — всё в порядке.";

    clean.append(mark, text);
    section.append(clean);
    return section;
  }

  const list = document.createElement("ul");
  list.className = "findings__list";

  for (const finding of findings) {
    const severity = SEVERITY[finding.severity] ?? SEVERITY.low;

    const item = document.createElement("li");
    item.className = `finding finding--${severity.tone}`;

    const head = document.createElement("div");
    head.className = "finding__head";

    const heading = document.createElement("h4");
    heading.className = "finding__title";
    heading.textContent = finding.title;

    head.append(createBadge(severity.tone, severity.label), heading);

    const desc = document.createElement("p");
    desc.className = "finding__desc";
    desc.textContent = finding.desc;

    const fix = document.createElement("p");
    fix.className = "finding__fix";

    const fixLabel = document.createElement("span");
    fixLabel.className = "finding__fix-label";
    fixLabel.textContent = "Как исправить:";

    fix.append(fixLabel, document.createTextNode(` ${finding.recommendation}`));

    item.append(head, desc, fix);
    list.append(item);
  }

  section.append(list);
  return section;
}

function createRow(label, value) {
  const row = document.createElement("div");
  row.className = "detail__row";

  const term = document.createElement("dt");
  term.className = "detail__label";
  term.textContent = label;

  const cell = document.createElement("dd");
  cell.className = "detail__value";

  if (typeof value === "string") cell.textContent = value;
  else cell.append(value);

  row.append(term, cell);
  return row;
}

function createCard(titleText, rows, note) {
  const card = document.createElement("section");
  card.className = "detail";

  const title = document.createElement("h4");
  title.className = "detail__title";
  title.textContent = titleText;
  card.append(title);

  if (rows.length > 0) {
    const list = document.createElement("dl");
    list.className = "detail__rows";

    for (const row of rows) {
      list.append(createRow(row.label, row.value));
    }

    card.append(list);
  }

  if (note) {
    const text = document.createElement("p");
    text.className = "detail__note";
    text.textContent = note;
    card.append(text);
  }

  return card;
}

function createPortsCard(ports) {
  const rows = ports.map((port) => {
    const tone = PORT_TONES[port.port] ?? "warn";
    return {
      label: `Порт ${port.port}`,
      value: createBadge(tone, PORT_LABELS[tone]),
    };
  });

  return createCard(
    "Порты",
    rows,
    ports.length === 0 ? "Открытых портов не найдено" : "",
  );
}

function formatDate(raw) {
  if (!raw) return "н/д";

  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return "н/д";

  return date.toLocaleString("ru-RU", { dateStyle: "medium" });
}

function createTlsCard(ssl) {
  if (!ssl.hasSSL) {
    return createCard(
      "TLS",
      [],
      "SSL не настроен: сайт отвечает по HTTP, трафик не шифруется.",
    );
  }

  const validBadge = createBadge(
    ssl.valid ? "ok" : "bad",
    ssl.valid ? "валиден" : "невалиден",
  );

  const rows = [{ label: "Сертификат", value: validBadge }];

  if (!ssl.valid && ssl.verifyError) {
    rows.push({ label: "Причина", value: ssl.verifyError });
  }

  const daysLeft = ssl.daysLeft;

  rows.push({ label: "Истекает", value: formatDate(ssl.validToISO || ssl.validTo) });

  // Срок отдельной строкой: в узкой карточке «дата — осталось N дн.»
  // переносится на три строки и разваливает сетку.
  if (Number.isFinite(daysLeft)) {
    const expired = daysLeft < 0;
    const tone = expired ? "bad" : daysLeft <= 30 ? "warn" : "ok";
    const text = expired ? `${Math.abs(daysLeft)} дн. назад` : `${daysLeft} дн.`;

    rows.push({
      label: expired ? "Истёк" : "Осталось",
      value: createBadge(tone, text),
    });
  }

  if (ssl.issuer) rows.push({ label: "Издатель", value: ssl.issuer });
  if (ssl.tlsVersion) rows.push({ label: "Версия TLS", value: ssl.tlsVersion });

  if (ssl.supportsOldTls) {
    rows.push({
      label: "Старые протоколы",
      value: createBadge("warn", "TLS 1.0/1.1"),
    });
  }

  return createCard("TLS", rows);
}

function createHeadersCard(headers) {
  if (headers.error) {
    return createCard(
      "Заголовки",
      [],
      "Сервер не ответил на HTTP-запрос — заголовки не проверены.",
    );
  }

  const flag = (present) => createBadge(present ? "ok" : "bad", present ? "есть" : "нет");

  const rows = [
    { label: "Server", value: headers.server || "не указан" },
    { label: "Протокол", value: headers.protocol || "—" },
    { label: "CSP", value: flag(headers.csp) },
    { label: "X-Frame-Options", value: flag(headers.xframe) },
    { label: "HSTS", value: flag(headers.hsts) },
    { label: "X-Content-Type-Options", value: flag(headers.xcontent) },
  ];

  return createCard("Заголовки", rows);
}

function createDetails(report) {
  const section = document.createElement("section");
  section.className = "details";

  const title = document.createElement("h3");
  title.className = "result__section-title";
  title.textContent = "Детали проверки";

  const grid = document.createElement("div");
  grid.className = "details__grid";
  grid.append(
    createPortsCard(report.ports),
    createTlsCard(report.ssl),
    createHeadersCard(report.headers),
  );

  section.append(title, grid);
  return section;
}

/**
 * Кольцо заполняется через CSS-переменную --value.
 * Это CSSOM-запись, а не inline-разметка, поэтому строгий
 * style-src 'self' её не блокирует.
 */
function animateGauge(gauge, score) {
  const apply = (value) => gauge.style.setProperty("--value", String(value));

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    apply(score);
    return;
  }

  const duration = 700;
  const startedAt = performance.now();

  const tick = (now) => {
    const progress = Math.min(1, Math.max(0, (now - startedAt) / duration));
    const eased = 1 - (1 - progress) ** 3;

    apply((score * eased).toFixed(1));

    if (progress < 1) window.requestAnimationFrame(tick);
  };

  window.requestAnimationFrame(tick);
}

function setText(selector, text) {
  const node = document.querySelector(selector);
  if (node) node.textContent = text ?? "";
}

export function renderResult(container, body, report) {
  const now = new Date();
  const localDate = new Intl.DateTimeFormat("sv-SE").format(now);
  const shortHost = (report.host || "").slice(0, 60);

  reportTitle = `CyberCheck_${shortHost}_${localDate}`;
  document.title = reportTitle;

  const dateText = now.toLocaleString("ru-RU", {
    dateStyle: "short",
    timeStyle: "short",
  });

  setText('[data-js="report-host"]', report.host);
  setText('[data-js="report-date"]', dateText);
  setText('[data-js="report-date-footer"]', dateText);

  const findings = Array.isArray(report.findings) ? report.findings : [];
  const ports = Array.isArray(report.ports) ? report.ports : [];
  const ssl = report.ssl && typeof report.ssl === "object" ? report.ssl : { hasSSL: false };
  const headers =
    report.headers && typeof report.headers === "object" ? report.headers : { error: true };

  const score = Number.isFinite(report.score) ? report.score : 0;

  const normalized = { ...report, findings, ports, ssl, headers };
  const { block: scoreBlock, gauge } = createScore(normalized, score);

  body.replaceChildren();
  body.append(scoreBlock, createFindings(findings), createDetails(normalized));

  container.hidden = false;
  animateGauge(gauge, score);
}

window.addEventListener("beforeprint", () => {
  // Печать может быть повторной: заголовок нужен для имени PDF каждый раз.
  if (reportTitle) document.title = reportTitle;
});

window.addEventListener("afterprint", () => {
  document.title = PAGE_TITLE;
});
