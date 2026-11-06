/* Рендер отчёта: оценка → что чинить → детали проверки.
   Только DOM API и textContent, без innerHTML и инлайн-разметки. */

import {
  sanitizeText,
  getCriticalPaths,
  getExposedFiles,
  filesNote,
  tlsNotice,
  caaState,
  secureContextState,
  reportTitleFor,
  plural,
} from "./report-model.js";

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

const TECH_LABELS = {
  cloudflare: "Cloudflare",
  sucuri: "Sucuri",
  akamai: "Akamai",
  wordpress: "WordPress",
  drupal: "Drupal",
  joomla: "Joomla",
  bitrix: "Bitrix",
};

// Подсказки для сложных терминов. title показывает их при наведении, а
// пунктирное подчёркивание в CSS подсказывает, что термин можно «потрогать».
const HINTS = {
  server: "Заголовок Server сообщает имя и версию веб-сервера.",
  csp: "CSP ограничивает, откуда страница может загружать скрипты и стили.",
  xframe: "X-Frame-Options запрещает встраивать сайт в чужой фрейм.",
  hsts: "HSTS заставляет браузер открывать сайт только по HTTPS.",
  xcontent: "X-Content-Type-Options запрещает браузеру угадывать тип файла.",
  referrer: "Referrer-Policy решает, какие адреса передавать внешним сайтам.",
  permissions:
    "Permissions-Policy ограничивает доступ к камере, микрофону и геолокации.",
  coop: "COOP изолирует страницу от чужих окон браузера.",
  cors: "CORS определяет, какие сайты могут читать ответы этого сайта.",
  spf: "SPF перечисляет серверы, которым разрешено отправлять письма от имени домена.",
  dmarc:
    "DMARC говорит почтовым сервисам, что делать с письмами, не прошедшими проверку SPF/DKIM.",
  caa: "CAA указывает, какие удостоверяющие центры могут выпускать сертификаты для домена.",
  tls: "TLS шифрует соединение, а сертификат подтверждает, что сайт настоящий.",
  cookieSecure: "Secure запрещает браузеру передавать cookie по HTTP.",
  cookieHttpOnly:
    "HttpOnly скрывает cookie от JavaScript — это защищает сессию при XSS.",
  cookieSameSite:
    "SameSite ограничивает отправку cookie в запросах с чужих сайтов.",
  securityTxt:
    "security.txt — файл с контактом для сообщений об уязвимостях.",
};

// HSTS и Secure имеют смысл только при подтверждённом HTTPS с валидным
// сертификатом. При невалидном сертификате scoring их не штрафует, значит
// и карточка не должна рисовать красное «нет» — иначе пользователь идёт
// чинить HSTS, хотя проблема в сертификате.
const SECURE_CONTEXT_NOTES = {
  "no-https": "н/д (нет HTTPS)",
  "invalid-cert": "н/д (сертификат невалиден)",
  unverified: "н/д (сертификат не прочитан)",
  unknown: "н/д (TLS не проверен)",
};

// Категории фильтра повторяют severity находок, поэтому кнопки и карточки
// не могут разойтись: и те и другие читают одно поле.
const FILTERS = [
  { key: "all", label: "Все" },
  { key: "high", label: "Критичные" },
  { key: "medium", label: "Важные" },
  { key: "low", label: "Замечания" },
];

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
  // Имя приходит из ответа сервера: нестроковое значение не должно давать
  // пустой бейдж, поэтому приводим его к строке.
  const text =
    typeof value === "string" ? value : value === null || value === undefined ? "" : String(value);
  if (text.length === 0) return "";

  const key = text.toLowerCase();
  if (TECH_LABELS[key]) return TECH_LABELS[key];
  return text.charAt(0).toUpperCase() + text.slice(1);
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

// «2/3» без текста читалось скринридером как «2 слэш 3», а title
// недоступен с клавиатуры: добавляем визуально скрытое пояснение.
function cookieFlagBadge(summary, missingKey, missingTone, label) {
  const total = summary.total;
  const missing = Number.isFinite(summary[missingKey])
    ? summary[missingKey]
    : total;
  const present = Math.max(0, total - missing);
  const tone = missing === 0 ? "ok" : missing >= total ? missingTone : "warn";
  const badge = createBadge(tone, `${present}/${total}`);
  badge.setAttribute("title", `${present} из ${total} cookie`);

  const hidden = document.createElement("span");
  hidden.className = "u-visually-hidden";
  hidden.textContent = ` ${present} из ${total} cookie с флагом ${label}`;
  badge.append(hidden);

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

  const countFor = (key) =>
    key === "all"
      ? findings.length
      : findings.filter((finding) => finding.severity === key).length;

  const filters = document.createElement("div");
  filters.className = "findings__filters";
  filters.setAttribute("role", "group");
  filters.setAttribute("aria-label", "Фильтр находок по важности");

  const list = document.createElement("ul");
  list.className = "findings__list";
  list.id = "findings-list";
  // list-style: none убирает список из дерева доступности в Safari —
  // возвращаем роль явно.
  list.setAttribute("role", "list");

  const empty = document.createElement("p");
  empty.className = "findings__empty";
  empty.hidden = true;

  const entries = [];
  const buttons = [];

  for (const finding of findings) {
    const severity = SEVERITY[finding.severity] ?? SEVERITY.low;
    const severityKey = SEVERITY[finding.severity] ? finding.severity : "low";

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

    // Пустой desc оставлял бы <p> с margin — визуальную дыру в карточке.
    const descText = typeof finding.desc === "string" ? finding.desc : "";
    let desc = null;
    if (descText.trim() !== "") {
      desc = document.createElement("p");
      desc.className = "finding__desc";
      desc.textContent = descText;
    }

    const fix = document.createElement("p");
    fix.className = "finding__fix";

    const fixLabel = document.createElement("span");
    fixLabel.className = "finding__fix-label";
    fixLabel.textContent = "Как исправить:";

    fix.append(fixLabel, document.createTextNode(` ${finding.recommendation}`));

    item.append(head);
    if (desc) item.append(desc);
    item.append(fix);
    list.append(item);

    entries.push({ item, severity: severityKey });
  }

  const applyFilter = (key) => {
    const active = FILTERS.find((filter) => filter.key === key) ?? FILTERS[0];
    let visible = 0;

    for (const entry of entries) {
      const show = key === "all" || entry.severity === key;
      entry.item.hidden = !show;
      if (show) visible += 1;
    }

    for (const button of buttons) {
      button.setAttribute(
        "aria-pressed",
        String(button.dataset.filter === key),
      );
    }

    empty.hidden = visible > 0;
    empty.textContent =
      visible === 0
        ? `В категории «${active.label}» замечаний нет.`
        : "";
  };

  for (const filter of FILTERS) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "findings__filter";
    button.dataset.filter = filter.key;
    button.textContent = `${filter.label} (${countFor(filter.key)})`;
    button.setAttribute("aria-pressed", String(filter.key === "all"));
    button.setAttribute("aria-controls", list.id);
    button.addEventListener("click", () => applyFilter(filter.key));

    filters.append(button);
    buttons.push(button);
  }

  section.append(filters, list, empty);
  return section;
}

function createRow(label, value, hint) {
  const row = document.createElement("div");
  row.className = "detail__row";

  const term = document.createElement("dt");
  term.className = "detail__label";
  term.textContent = label;

  if (hint) {
    term.classList.add("detail__label--hint");
    // title — нативный и доступный способ показать пояснение при наведении;
    // он не нарушает CSP и не требует JS.
    term.setAttribute("title", hint);
  }

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
      list.append(createRow(row.label, row.value, row.hint));
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

function createTlsCard(ssl, ports) {
  // «SSL не настроен: сайт отвечает по HTTP» — неправда, если сайт вообще
  // не ответил: такой текст отправлял пользователя чинить HTTPS у
  // недоступного хоста.
  const notice = tlsNotice(ssl, ports);
  if (notice) return createCard("TLS", [], notice);

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

  const rows = [{ label: "Сертификат", value: validBadge, hint: HINTS.tls }];

  if (!ssl.valid && ssl.verifyError) {
    rows.push({
      label: "Причина",
      value: sanitizeText(ssl.verifyError) || "н/д",
    });
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

  // Издатель — недоверенная строка: ограничиваем длину и убираем bidi/C0.
  const issuer = sanitizeText(ssl.issuer);
  if (issuer) rows.push({ label: "Издатель", value: issuer });

  const tlsVersion = sanitizeText(ssl.tlsVersion, 32);
  if (tlsVersion) rows.push({ label: "Версия TLS", value: tlsVersion });

  if (ssl.supportsOldTls) {
    rows.push({
      label: "Старые протоколы",
      value: createBadge("warn", "TLS 1.0/1.1"),
    });
  }

  return createCard("TLS", rows);
}

function createHeadersCard(headers, ssl) {
  if (headers.error) {
    return createCard(
      "Заголовки",
      [],
      "Сервер не ответил на HTTP-запрос — заголовки не проверены.",
    );
  }

  const context = secureContextState(ssl);

  // Состояние заголовка: ok / weak (есть, но выключен) / missing.
  // Scoring считает так же, поэтому «есть» и «небезопасно» не расходятся.
  const stateFlag = (state, present) => {
    if (present) return createBadge("ok", "Настроен");
    if (state === "weak") return createBadge("warn", "Не защищает");
    if (state === undefined && present === undefined) return createMuted("н/д");
    return createBadge("bad", "Не настроен");
  };
  const optionalFlag = (value, state) =>
    value === undefined && state === undefined
      ? createMuted("н/д")
      : stateFlag(state, Boolean(value));

  const cors =
    headers.corsWildcard === true
      ? createBadge("bad", "*")
      : headers.corsWildcard === false
        ? createBadge("ok", "ограничен")
        : createMuted("н/д");

  // Без HTTPS HSTS неприменим: scoring его не штрафует, значит и карточка
  // не должна рисовать красное «нет». Невалидный сертификат — тот же случай.
  const hstsValue =
    context === "ok"
      ? stateFlag(headers.hstsState, headers.hsts)
      : createMuted(SECURE_CONTEXT_NOTES[context] ?? "н/д");

  const rows = [
    {
      label: "Server",
      value: sanitizeText(headers.server) || "не указан",
      hint: HINTS.server,
    },
    { label: "Протокол", value: headers.protocol || "—" },
    { label: "CSP", value: stateFlag(headers.cspState, headers.csp), hint: HINTS.csp },
    {
      label: "X-Frame-Options",
      value: stateFlag(headers.xframeState, headers.xframe),
      hint: HINTS.xframe,
    },
    { label: "HSTS", value: hstsValue, hint: HINTS.hsts },
    {
      label: "X-Content-Type-Options",
      value: stateFlag(headers.xcontentState, headers.xcontent),
      hint: HINTS.xcontent,
    },
    {
      label: "Referrer-Policy",
      value: optionalFlag(headers.referrerPolicy, headers.referrerPolicyState),
      hint: HINTS.referrer,
    },
    {
      label: "Permissions-Policy",
      value: optionalFlag(
        headers.permissionsPolicy,
        headers.permissionsPolicyState,
      ),
      hint: HINTS.permissions,
    },
    { label: "COOP", value: optionalFlag(headers.coop, headers.coopState), hint: HINTS.coop },
    { label: "CORS", value: cors, hint: HINTS.cors },
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
  let spfValue;
  if (dnsSectionUnavailable(spf)) {
    spfValue = createMuted("Не удалось проверить");
  } else if (!spf.present) {
    spfValue = createBadge("bad", "Не настроен");
  } else if (spf.multiple) {
    spfValue = createBadge("bad", "Конфликт записей");
  } else if (spf.weak) {
    spfValue = createBadge("warn", "Слишком мягкий");
  } else {
    spfValue = createBadge("ok", "Настроен");
  }

  const dmarc = dns.dmarc;
  let dmarcValue;
  if (dnsSectionUnavailable(dmarc)) {
    dmarcValue = createMuted("Не удалось проверить");
  } else if (dmarc.multiple) {
    dmarcValue = createBadge("bad", "Конфликт записей");
  } else if (!dmarc.present) {
    dmarcValue = createBadge("bad", "Не настроен");
  } else {
    const policy =
      typeof dmarc.policy === "string" ? dmarc.policy.toLowerCase() : null;
    if (policy === "reject") {
      dmarcValue = createBadge("ok", "Строгий (Блокировка)");
    } else if (policy === "quarantine") {
      dmarcValue = createBadge("ok", "Карантин (В спам)");
    } else if (policy === "none") {
      dmarcValue = createBadge("warn", "Мониторинг");
    } else {
      dmarcValue = createBadge("warn", "Некорректный");
    }
  }

  const caa = dns.caa;
  const caaStateValue = caaState(caa);
  const caaValue =
    caaStateValue === "ok"
      ? createBadge("ok", "Настроен")
      : caaStateValue === "weak"
        ? // Запись только с iodef выпуск сертификатов не ограничивает:
          // зелёное «есть» противоречило бы находке «CAA не ограничивает».
          createBadge("warn", "Не ограничивает")
        : caaStateValue === "missing"
          ? createBadge("warn", "Не настроен")
          : createMuted("Не удалось проверить");

  const rows = [
    { label: "SPF", value: spfValue, hint: HINTS.spf },
    { label: "DMARC", value: dmarcValue, hint: HINTS.dmarc },
    { label: "CAA", value: caaValue, hint: HINTS.caa },
  ];

  // CAA оценивается тем же правилом, что и бейдж: ENOTFOUND для apex — сбой,
  // а не «записи нет», поэтому в счётчик недоступных он тоже входит.
  const unavailable = [
    dnsSectionUnavailable(dns.spf),
    dnsSectionUnavailable(dns.dmarc),
    caaStateValue === "unknown",
  ].filter(Boolean).length;

  return createCard(
    "Почтовая безопасность",
    rows,
    unavailable > 0
      ? "Часть DNS-проверок не ответила — значения отмечены как «Не удалось проверить»."
      : "",
  );
}

function createCookieCard(headers, ssl) {
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

  // Secure имеет смысл только на HTTPS. Scoring без HTTPS его не штрафует —
  // значит, и карточка не должна показывать красное «0/1».
  const context = secureContextState(ssl);

  const secureValue =
    context === "ok"
      ? cookieFlagBadge(summary, "missingSecure", "bad", "Secure")
      : createMuted(SECURE_CONTEXT_NOTES[context] ?? "н/д");

  const rows = [
    { label: "Secure", value: secureValue, hint: HINTS.cookieSecure },
    {
      label: "HttpOnly",
      value: cookieFlagBadge(summary, "missingHttpOnly", "bad", "HttpOnly"),
      hint: HINTS.cookieHttpOnly,
    },
    {
      label: "SameSite",
      value: cookieFlagBadge(summary, "missingSameSite", "warn", "SameSite"),
      hint: HINTS.cookieSameSite,
    },
  ];

  let note = `Всего cookie: ${summary.total}.`;
  if (context === "ok" && summary.insecureNone > 0) {
    note += " Часть cookie с SameSite=None без Secure — браузеры их отвергают.";
  }

  return createCard("Флаги Cookie", rows, note);
}

function securityTxtValue(securityTxt) {
  if (!securityTxt || typeof securityTxt !== "object") {
    return createMuted("н/д");
  }
  if (securityTxt.present) return createBadge("ok", "есть");
  if (securityTxt.blocked) return createBadge("warn", "403 (заблокировано)");
  if (securityTxt.error) return createMuted("не удалось проверить");
  if (securityTxt.status === 404) return createBadge("bad", "нет (404)");
  if (securityTxt.status === 200) return createBadge("warn", "некорректный");
  return createMuted(
    Number.isInteger(securityTxt.status) ? `н/д (${securityTxt.status})` : "н/д",
  );
}

function createTechCard(fingerprint, securityTxt) {
  const securityRow = {
    label: "security.txt",
    value: securityTxtValue(securityTxt),
    hint: HINTS.securityTxt,
  };

  if (!fingerprint || typeof fingerprint !== "object") {
    return createCard(
      "Технологии",
      [securityRow],
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

  // «Не обнаружен» — это результат проверки. При не-200 странице CMS не
  // искали (заглушка ошибки или WAF), поэтому честнее «не проверялся».
  const checked = fingerprint.status === 200;

  const rows = [
    {
      label: "WAF",
      value: wafName
        ? createBadge("ok", formatTechName(wafName))
        : createMuted(checked ? "не обнаружен" : "не проверялся"),
    },
    {
      label: "CMS",
      value: cmsName
        ? createBadge("muted", formatTechName(cmsName))
        : createMuted(checked ? "не обнаружена" : "не проверялась"),
    },
    securityRow,
  ];

  let note = "";
  if (fingerprint.error) {
    note = "Не удалось проверить полностью: страница не ответила.";
  } else if (
    Number.isInteger(fingerprint.status) &&
    fingerprint.status !== 200
  ) {
    note = `Страница ответила ${fingerprint.status}; WAF/CMS не проверялись — заглушка ошибки не доказывает их отсутствие.`;
  }

  return createCard("Технологии", rows, note);
}

function createFilesCard(files) {
  const card = createCard("Открытые файлы", [], filesNote(files));
  card.classList.add("detail--files");

  if (!files || typeof files !== "object") return card;

  const exposed = getExposedFiles(files);
  if (exposed.length === 0) return card;

  const criticalPaths = getCriticalPaths(files);

  const list = document.createElement("ul");
  list.className = "detail__file-list";
  list.setAttribute("role", "list");

  for (const path of exposed) {
    const critical = criticalPaths.has(path);
    const item = document.createElement("li");
    item.className = critical
      ? "detail__file-item detail__file-item--critical"
      : "detail__file-item detail__file-item--low";

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
    createTlsCard(report.ssl, report.ports),
    createHeadersCard(report.headers, report.ssl),
    createMailCard(report.dns),
    createCookieCard(report.headers, report.ssl),
    createTechCard(report.fingerprint, report.securityTxt),
    createFilesCard(report.files),
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

  // host "—" — заглушка нормализации, а не домен: печатать её в заголовок
  // документа (и в имя PDF через beforeprint) нельзя.
  const host = typeof report.host === "string" ? report.host : "";
  const shortHost = sanitizeText(host, 60);

  reportTitle = reportTitleFor(shortHost, localDate);
  document.title = reportTitle || PAGE_TITLE;

  const dateText = now.toLocaleString("ru-RU", {
    dateStyle: "short",
    timeStyle: "short",
  });

  setText('[data-js="report-host"]', shortHost || "—");
  setText('[data-js="report-date"]', dateText);
  setText('[data-js="report-date-footer"]', dateText);

  const findings = Array.isArray(report.findings) ? report.findings : [];
  // WAF/CMS — информационные находки; они показываются в карточке
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

// Возвращает исходный заголовок вкладки. После неудачного скана старый
// «CyberCheck_<host>_<date>» вводил бы в заблуждение и попадал в имя PDF.
export function resetReportTitle() {
  reportTitle = "";
  document.title = PAGE_TITLE;
}

window.addEventListener("beforeprint", () => {
  // Печать может быть повторной: заголовок нужен для имени PDF каждый раз.
  document.title = reportTitle || PAGE_TITLE;

  // И кольцо должно попасть на бумагу в конечном положении,
  // даже если печать нажали в середине анимации.
  if (currentGauge) currentGauge.style.setProperty("--value", String(currentScore));
});

window.addEventListener("afterprint", () => {
  // Отчёт остался на экране — вкладка должна называться по нему. Сброс в
  // PAGE_TITLE делают только там, где отчёт убран (resetReportTitle).
  document.title = reportTitle || PAGE_TITLE;
});
