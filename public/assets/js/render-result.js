/* Рендер отчёта: оценка → что чинить → детали проверки.
   Только DOM API и textContent, без innerHTML и инлайн-разметки. */

const PAGE_TITLE = document.title;
let reportTitle = "";
let currentGauge = null;
let currentScore = 0;

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

const CRITICAL_FILE_PATHS = new Set([
  "/.env",
  "/.git/config",
  "/backup.zip",
]);

const TECH_LABELS = {
  cloudflare: "Cloudflare",
  sucuri: "Sucuri",
  akamai: "Akamai",
  wordpress: "WordPress",
  drupal: "Drupal",
  joomla: "Joomla",
  bitrix: "Bitrix",
};

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

function owaspTag(value) {
  if (typeof value !== "string") return "";
  const match = /^(A\d{2}):/.exec(value.trim());
  return match ? match[1] : "";
}

function createMuted(text) {
  const span = document.createElement("span");
  span.className = "detail__muted";
  span.textContent = text;
  return span;
}

function formatTechName(value) {
  if (typeof value !== "string" || value.length === 0) return "";
  const key = value.toLowerCase();
  if (TECH_LABELS[key]) return TECH_LABELS[key];
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function dnsSectionUnavailable(section) {
  if (!section || typeof section !== "object") return true;
  return Boolean(section.error) && !["ENODATA", "ENOTFOUND"].includes(section.error);
}

function getCookieSummary(headers) {
  const summary = headers.cookieSummary;
  if (summary && Number.isFinite(summary.total)) return summary;

  if (!Array.isArray(headers.cookies)) return null;

  const total = headers.cookies.length;
  let secure = 0;
  let httpOnly = 0;
  let sameSite = 0;

  for (const cookie of headers.cookies) {
    if (!cookie || typeof cookie !== "object") continue;
    if (cookie.secure) secure += 1;
    if (cookie.httpOnly) httpOnly += 1;
    if (cookie.sameSite) sameSite += 1;
  }

  return {
    total,
    secure,
    httpOnly,
    sameSite,
    missingSecure: total - secure,
    missingHttpOnly: total - httpOnly,
    missingSameSite: total - sameSite,
  };
}

function cookieFlagBadge(summary, missingKey, missingTone) {
  const total = summary.total;
  const missing = Number.isFinite(summary[missingKey])
    ? summary[missingKey]
    : total;
  const present = Math.max(0, total - missing);
  const tone = missing === 0 ? "ok" : missing >= total ? missingTone : "warn";
  const badge = createBadge(tone, `${present}/${total}`);
  badge.setAttribute("title", `${present} из ${total} cookie`);
  return badge;
}

function getExposedFiles(files) {
  const paths = new Set();

  if (Array.isArray(files.exposed)) {
    for (const path of files.exposed) {
      if (typeof path === "string") paths.add(path);
    }
  }

  if (Array.isArray(files.critical)) {
    for (const item of files.critical) {
      if (typeof item === "string") paths.add(item);
      else if (item && typeof item.path === "string") paths.add(item.path);
    }
  }

  if (paths.size === 0 && Array.isArray(files.results)) {
    for (const item of files.results) {
      if (item && item.status === 200 && typeof item.path === "string") {
        paths.add(item.path);
      }
    }
  }

  return Array.from(paths);
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
  grade.textContent = report.grade || "?";

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
    text.textContent =
      "Явных замечаний нет. Недоступные проверки отмечены в деталях.";

    clean.append(mark, text);
    section.append(clean);
    return section;
  }

  const list = document.createElement("ul");
  list.className = "findings__list";
  // list-style: none убирает список из дерева доступности в Safari —
  // возвращаем роль явно.
  list.setAttribute("role", "list");

  for (const finding of findings) {
    const severity = SEVERITY[finding.severity] ?? SEVERITY.low;

    const item = document.createElement("li");
    item.className = `finding finding--${severity.tone}`;

    const head = document.createElement("div");
    head.className = "finding__head";

    const heading = document.createElement("h4");
    heading.className = "finding__title";
    heading.textContent = finding.title;

    head.append(createBadge(severity.tone, severity.label));

    const owasp = owaspTag(finding.owasp);
    if (owasp) {
      const owaspBadge = createBadge("muted", owasp);
      owaspBadge.classList.add("finding__owasp");
      owaspBadge.setAttribute("title", finding.owasp);
      head.append(owaspBadge);
    }

    head.append(heading);

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
  if (ssl.error) {
    return createCard(
      "TLS",
      [],
      "Не удалось проверить TLS: сервер не ответил на TLS-хендшейк или сертификат не разобран. Повторите скан позже.",
    );
  }

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

  const flag = (present) =>
    createBadge(present ? "ok" : "bad", present ? "есть" : "нет");
  const optionalFlag = (value) =>
    value === undefined ? createMuted("н/д") : flag(Boolean(value));

  const cors =
    headers.corsWildcard === true
      ? createBadge("bad", "*")
      : headers.corsWildcard === false
        ? createBadge("ok", "ограничен")
        : createMuted("н/д");

  const rows = [
    { label: "Server", value: headers.server || "не указан" },
    { label: "Протокол", value: headers.protocol || "—" },
    { label: "CSP", value: flag(headers.csp) },
    { label: "X-Frame-Options", value: flag(headers.xframe) },
    { label: "HSTS", value: flag(headers.hsts) },
    { label: "X-Content-Type-Options", value: flag(headers.xcontent) },
    { label: "Referrer-Policy", value: optionalFlag(headers.referrerPolicy) },
    {
      label: "Permissions-Policy",
      value: optionalFlag(headers.permissionsPolicy),
    },
    { label: "COOP", value: optionalFlag(headers.coop) },
    { label: "CORS", value: cors },
  ];

  return createCard("Заголовки", rows);
}

function createMailCard(dns) {
  if (!dns || typeof dns !== "object") {
    return createCard(
      "Почтовая безопасность",
      [],
      "Не удалось проверить: данные DNS не получены.",
    );
  }

  if (dns.applicable === false) {
    return createCard(
      "Почтовая безопасность",
      [],
      "Не применимо для IP-адреса или localhost.",
    );
  }

  const spf = dns.spf;
  const spfValue = dnsSectionUnavailable(spf)
    ? createMuted("Не удалось проверить")
    : spf.present
      ? createBadge("ok", "есть")
      : createBadge("bad", "нет");

  const dmarc = dns.dmarc;
  let dmarcValue;
  if (dnsSectionUnavailable(dmarc)) {
    dmarcValue = createMuted("Не удалось проверить");
  } else if (!dmarc.present) {
    dmarcValue = createBadge("bad", "нет");
  } else {
    const policy =
      typeof dmarc.policy === "string" ? dmarc.policy.toLowerCase() : null;
    if (policy === "reject" || policy === "quarantine") {
      dmarcValue = createBadge("ok", `p=${policy}`);
    } else if (policy === "none") {
      dmarcValue = createBadge("warn", "p=none");
    } else {
      dmarcValue = createBadge("warn", "некорректный");
    }
  }

  const caa = dns.caa;
  const caaValue = dnsSectionUnavailable(caa)
    ? createMuted("Не удалось проверить")
    : caa.present
      ? createBadge("ok", "есть")
      : createBadge("warn", "нет");

  const rows = [
    { label: "SPF", value: spfValue },
    { label: "DMARC", value: dmarcValue },
    { label: "CAA", value: caaValue },
  ];

  const unavailable = ["spf", "dmarc", "caa"].filter((key) =>
    dnsSectionUnavailable(dns[key]),
  ).length;

  return createCard(
    "Почтовая безопасность",
    rows,
    unavailable > 0
      ? "Часть DNS-проверок не ответила — значения отмечены как «Не удалось проверить»."
      : "",
  );
}

function createCookieCard(headers) {
  if (!headers || headers.error) {
    return createCard(
      "Флаги Cookie",
      [],
      "Заголовки не проверены — cookie-флаги недоступны.",
    );
  }

  const summary = getCookieSummary(headers);
  if (!summary) {
    return createCard(
      "Флаги Cookie",
      [],
      "Не удалось проверить: данные cookie не получены.",
    );
  }

  if (summary.total === 0) {
    return createCard("Флаги Cookie", [], "Cookie не найдены.");
  }

  const rows = [
    {
      label: "Secure",
      value: cookieFlagBadge(summary, "missingSecure", "bad"),
    },
    {
      label: "HttpOnly",
      value: cookieFlagBadge(summary, "missingHttpOnly", "bad"),
    },
    {
      label: "SameSite",
      value: cookieFlagBadge(summary, "missingSameSite", "warn"),
    },
  ];

  return createCard(
    "Флаги Cookie",
    rows,
    `Всего cookie: ${summary.total}.`,
  );
}

function createTechCard(fingerprint) {
  if (!fingerprint || typeof fingerprint !== "object") {
    return createCard(
      "Информация о технологиях",
      [],
      "Не удалось проверить: данные фингерпринта не получены.",
    );
  }

  const wafName =
    fingerprint.waf && typeof fingerprint.waf === "object"
      ? fingerprint.waf.name
      : typeof fingerprint.waf === "string"
        ? fingerprint.waf
        : null;
  const cmsName =
    fingerprint.cms && typeof fingerprint.cms === "object"
      ? fingerprint.cms.name
      : typeof fingerprint.cms === "string"
        ? fingerprint.cms
        : null;

  const rows = [
    {
      label: "WAF",
      value: wafName
        ? createBadge("ok", formatTechName(wafName))
        : createMuted("не обнаружен"),
    },
    {
      label: "CMS",
      value: cmsName
        ? createBadge("muted", formatTechName(cmsName))
        : createMuted("не обнаружена"),
    },
  ];

  let note = "";
  if (fingerprint.error) {
    note = "Не удалось проверить полностью: страница не ответила.";
  } else if (
    Number.isInteger(fingerprint.status) &&
    fingerprint.status !== 200
  ) {
    note = `Страница ответила ${fingerprint.status}; WAF/CMS могли быть скрыты.`;
  }

  return createCard("Информация о технологиях", rows, note);
}

function securityTxtValue(securityTxt) {
  if (!securityTxt || typeof securityTxt !== "object") {
    return createMuted("н/д");
  }
  if (securityTxt.present) return createBadge("ok", "есть");
  if (securityTxt.blocked) return createBadge("warn", "403");
  if (securityTxt.error) return createMuted("Не удалось проверить");
  if (securityTxt.status === 404) return createBadge("bad", "нет");
  return createMuted("н/д");
}

function createFilesCard(files, securityTxt) {
  const rows = [
    { label: "security.txt", value: securityTxtValue(securityTxt) },
  ];

  if (!files || typeof files !== "object") {
    const card = createCard(
      "Открытые файлы",
      rows,
      "Не удалось проверить: данные HEAD-проб не получены.",
    );
    card.classList.add("detail--files");
    return card;
  }

  const exposed = getExposedFiles(files);
  if (exposed.length === 0) {
    const blocked = Array.isArray(files.blocked) ? files.blocked.length : 0;
    const note =
      blocked > 0
        ? `Открытых файлов не найдено; ${blocked} путей заблокировано (403/WAF).`
        : "Открытых файлов не найдено.";
    const card = createCard("Открытые файлы", rows, note);
    card.classList.add("detail--files");
    return card;
  }

  const hasCritical = exposed.some((path) => CRITICAL_FILE_PATHS.has(path));
  const card = createCard(
    "Открытые файлы",
    rows,
    hasCritical
      ? "Найдены файлы, доступные без авторизации. Это критично."
      : "Найден /.DS_Store: он раскрывает структуру каталогов, но это низкий риск.",
  );
  card.classList.add("detail--files");

  const list = document.createElement("ul");
  list.className = "detail__file-list";
  list.setAttribute("role", "list");

  for (const path of exposed) {
    const critical = CRITICAL_FILE_PATHS.has(path);
    const item = document.createElement("li");
    item.className = "detail__file-item";

    const pathNode = document.createElement("span");
    pathNode.className = "detail__file-path";
    pathNode.textContent = path;

    item.append(
      pathNode,
      critical
        ? createBadge("bad", "Критично")
        : createBadge("muted", "Низкий риск"),
    );
    list.append(item);
  }

  card.append(list);
  return card;
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
    createMailCard(report.dns),
    createCookieCard(report.headers),
    createTechCard(report.fingerprint),
    createFilesCard(report.files, report.securityTxt),
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
  // WAF/CMS — информационные находки Step 1; они показываются в карточке
  // технологий, а не в списке «Что исправить».
  const displayFindings = findings.filter(
    (finding) =>
      finding &&
      finding.id !== "waf-detected" &&
      finding.id !== "cms-detected",
  );

  const ports = Array.isArray(report.ports) ? report.ports : [];
  const ssl = report.ssl && typeof report.ssl === "object" ? report.ssl : { hasSSL: false };
  const headers =
    report.headers && typeof report.headers === "object" ? report.headers : { error: true };
  const dns = report.dns && typeof report.dns === "object" ? report.dns : null;
  const files =
    report.files && typeof report.files === "object" ? report.files : null;
  const securityTxt =
    report.securityTxt && typeof report.securityTxt === "object"
      ? report.securityTxt
      : null;
  const fingerprint =
    report.fingerprint && typeof report.fingerprint === "object"
      ? report.fingerprint
      : null;

  const score = Number.isFinite(report.score) ? report.score : 0;

  const normalized = {
    ...report,
    findings: displayFindings,
    ports,
    ssl,
    headers,
    dns,
    files,
    securityTxt,
    fingerprint,
  };
  const { block: scoreBlock, gauge } = createScore(normalized, score);

  body.replaceChildren();
  body.append(
    scoreBlock,
    createFindings(displayFindings),
    createDetails(normalized),
  );

  container.hidden = false;

  currentGauge = gauge;
  currentScore = score;
  animateGauge(gauge, score);
}

window.addEventListener("beforeprint", () => {
  // Печать может быть повторной: заголовок нужен для имени PDF каждый раз.
  if (reportTitle) document.title = reportTitle;

  // И кольцо должно попасть на бумагу в конечном положении,
  // даже если печать нажали в середине анимации.
  if (currentGauge) currentGauge.style.setProperty("--value", String(currentScore));
});

window.addEventListener("afterprint", () => {
  document.title = PAGE_TITLE;
});
