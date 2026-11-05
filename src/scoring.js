// Risk Score v2.1.0.
//
// Положительные веса ниже в сумме дают ровно 100. Поддержка TLS 1.0/1.1 —
// отдельный штраф −10, поэтому в WEIGHTS её нет. Потолки применяются после
// суммирования и могут опустить итог ниже суммы весов.
//
// Новые данные Step 1 (dns/files/securityTxt/fingerprint и расширенные поля
// headers) читаются осторожно: если проверка не выполнялась (поле undefined)
// или DNS/сеть вернули ошибку, баллы не отнимаются и скан не падает.

const OWASP = {
  crypto: "A02:2021 Cryptographic Failures",
  misconfig: "A05:2021 Security Misconfiguration",
  injection: "A03:2021 Injection",
  auth: "A07:2021 Identification and Authentication Failures",
  vulnerable: "A06:2021 Vulnerable and Outdated Components",
};

// Сумма значений этого объекта — ровно 100.
const WEIGHTS = {
  // TLS / сертификат
  ssl: 12,
  sslDays: 3,
  // Заголовки
  hsts: 8,
  csp: 10,
  xframe: 6,
  xcontent: 6,
  server: 3,
  // Порты
  riskyPorts: 10,
  port8080: 2,
  // DNS / email
  spf: 4,
  dmarc: 3,
  caa: 2,
  // Cookie
  cookieSecure: 3,
  cookieHttpOnly: 2,
  cookieSameSite: 1,
  // Дополнительные заголовки
  referrer: 2,
  permissions: 2,
  coop: 2,
  cors: 3,
  // Открытые файлы
  env: 7,
  git: 4,
  backup: 2,
  dsStore: 1,
  // security.txt
  securityTxt: 2,
};

const OLD_TLS_PENALTY = 10;

const FILE_CHECKS = [
  {
    path: "/.env",
    id: "exposed-env",
    title: "Открыт /.env",
    desc: "Файл /.env доступен по HTTP — возможна утечка секретов, ключей и строк подключения.",
    severity: "high",
    weight: WEIGHTS.env,
    cap: 40,
    recommendation:
      "Закройте доступ к /.env на веб-сервере и смените все секреты, которые могли попасть в файл.",
    owasp: OWASP.injection,
  },
  {
    path: "/.git/config",
    id: "exposed-git",
    title: "Открыт /.git/config",
    desc: "Служебный каталог Git доступен из интернета — можно получить URL репозитория и настройки проекта.",
    severity: "high",
    weight: WEIGHTS.git,
    cap: 50,
    recommendation:
      "Запретите отдачу /.git через конфиг сервера и проверьте, не утекли ли исходники.",
    owasp: OWASP.injection,
  },
  {
    path: "/backup.zip",
    id: "exposed-backup",
    title: "Открыт /backup.zip",
    desc: "Архив бэкапа доступен без авторизации — в нём могут быть исходники, дампы или конфиги.",
    severity: "high",
    weight: WEIGHTS.backup,
    cap: 50,
    recommendation:
      "Удалите публичный бэкап, храните архивы вне web-root и ограничьте доступ по IP.",
    owasp: OWASP.injection,
  },
  {
    path: "/.DS_Store",
    id: "exposed-dsstore",
    title: "Открыт /.DS_Store",
    desc: "Файл метаданных macOS доступен из интернета — он раскрывает имена файлов и структуру каталогов.",
    severity: "low",
    weight: WEIGHTS.dsStore,
    cap: null,
    recommendation:
      "Удалите .DS_Store из web-root и добавьте его в .gitignore/исключения деплоя.",
    owasp: OWASP.injection,
  },
];

// ENODATA — «записи нет» и для apex, и для _dmarc. ENOTFOUND у apex-домена,
// у которого уже разрешились A/AAAA, означает рассинхрон/split-horizon DNS,
// а не доказательство отсутствия TXT/CAA, поэтому баллы за это не снимаются.
const APEX_MISSING_ERRORS = new Set(["ENODATA"]);
const SUBDOMAIN_MISSING_ERRORS = new Set(["ENODATA", "ENOTFOUND"]);

function isMissingDnsError(error, missingErrors = SUBDOMAIN_MISSING_ERRORS) {
  return !error || missingErrors.has(error);
}

// Ошибка резолвера (таймаут, SERVFAIL, abort) — не доказательство отсутствия
// записи: баллы не отнимаем, находку не создаём.
function isDnsUnavailable(section, missingErrors) {
  return (
    Boolean(section && section.error) &&
    !isMissingDnsError(section.error, missingErrors)
  );
}

function cookieSummaryFrom(headers) {
  if (
    headers.cookieSummary &&
    typeof headers.cookieSummary === "object" &&
    Number.isFinite(headers.cookieSummary.total)
  ) {
    return headers.cookieSummary;
  }

  if (!Array.isArray(headers.cookies)) return null;

  const total = headers.cookies.length;
  let secure = 0;
  let httpOnly = 0;
  let sameSite = 0;
  let insecureNone = 0;

  for (const cookie of headers.cookies) {
    if (!cookie || typeof cookie !== "object") continue;
    if (cookie.secure) secure += 1;
    if (cookie.httpOnly) httpOnly += 1;
    if (cookie.sameSite) sameSite += 1;
    if (cookie.sameSiteValue === "none" && !cookie.secure) insecureNone += 1;
  }

  return {
    total,
    secure,
    httpOnly,
    sameSite,
    insecureNone,
    missingSecure: total - secure,
    missingHttpOnly: total - httpOnly,
    missingSameSite: total - sameSite,
  };
}

function exposedPaths(files) {
  const result = new Set();

  if (Array.isArray(files.exposed)) {
    for (const path of files.exposed) {
      if (typeof path === "string") result.add(path);
    }
  }

  // files.critical — основной контракт Step 1; поддерживаем и строки, и
  // объекты { path, severity }, чтобы скоринг не зависел от формы отчёта.
  if (Array.isArray(files.critical)) {
    for (const item of files.critical) {
      let path = null;
      if (typeof item === "string") path = item;
      else if (item && typeof item.path === "string") path = item.path;
      if (path) result.add(path);
    }
  }

  // Совместимость: если exposed не передан, но есть results — берём только 200.
  if (result.size === 0 && Array.isArray(files.results)) {
    for (const item of files.results) {
      if (item && item.status === 200 && typeof item.path === "string") {
        result.add(item.path);
      }
    }
  }

  return result;
}

function calculateScore(report) {
  // Чистая функция не должна бросать на мусорном входе: неизвестный отчёт
  // (null, массив, строка) считается пустым объектом.
  const input = report && typeof report === "object" ? report : {};

  const findings = [];
  let score = 0;

  const ssl = input.ssl && typeof input.ssl === "object" ? input.ssl : {};
  const h =
    input.headers && typeof input.headers === "object"
      ? input.headers
      : { error: true };
  const ports = (Array.isArray(input.ports) ? input.ports : []).filter(
    (p) => p && typeof p === "object",
  );

  const hasSSL = !!ssl.hasSSL && !!ssl.valid;
  const daysLeft = typeof ssl.daysLeft === "number" ? ssl.daysLeft : null;
  const riskyPorts = ports.filter(
    (p) => p.status === "open" && [22, 3306].includes(p.port),
  );
  const has3306 = ports.some((p) => p.port === 3306 && p.status === "open");

  const add = (finding) => {
    findings.push({ owasp: OWASP.misconfig, ...finding });
  };

  // --- TLS / сертификат -----------------------------------------------------
  if (hasSSL) {
    score += WEIGHTS.ssl;
  } else if (ssl.tlsConfirmed === true) {
    // Заголовки пришли по HTTPS, но сертификат прочитать не удалось: это не
    // «SSL не настроен» и не ошибка проверки в обычном смысле. Баллы за TLS
    // не начисляются (валидность неизвестна), но и потолок 60 не ставится:
    // сайт реально работает по HTTPS.
    add({
      id: "ssl-unverified",
      title: "Сертификат не проверен",
      desc: "Сервер ответил по HTTPS, но сертификат прочитать не удалось: срок действия и цепочка не проверены.",
      severity: "medium",
      weight: WEIGHTS.ssl,
      recommendation:
        "Проверьте сертификат вручную (срок, цепочку, соответствие домену).",
      owasp: OWASP.crypto,
    });
  } else if (ssl.error === "NO_WEB_PORT") {
    // Ни один веб-порт не открыт: TLS не проверялся. Утверждать «SSL нет» и
    // ставить потолок 30 здесь нельзя — это ложный вывод о недоступном хосте.
    add({
      id: "tls-not-checked",
      title: "TLS не проверялся",
      desc: "У цели не открыт ни один веб-порт (80/443/8080), поэтому TLS-соединение не устанавливалось. Это не значит, что HTTPS не настроен.",
      severity: "medium",
      weight: 0,
      recommendation:
        "Проверьте, что сайт отвечает по 80/443, и повторите скан.",
      owasp: OWASP.crypto,
    });
  } else if (ssl.error) {
    add({
      id: "ssl-error",
      title: "Ошибка проверки SSL",
      desc: "Не удалось установить TLS-соединение. Возможно, сервер недоступен или блокирует запросы.",
      severity: "medium",
      weight: 0,
      recommendation: "Повторите скан позже.",
      owasp: OWASP.crypto,
    });
  } else if (!ssl.hasSSL) {
    add({
      id: "no-ssl",
      title: "Нет SSL",
      desc: "Сайт работает по HTTP — трафик не шифруется.",
      severity: "high",
      weight: WEIGHTS.ssl,
      recommendation: "Настройте HTTPS (Let's Encrypt, Cloudflare).",
      owasp: OWASP.crypto,
    });
  } else {
    add({
      id: "bad-ssl",
      title: "Невалидный SSL",
      desc: "Браузеры показывают предупреждение о сертификате.",
      severity: "high",
      weight: WEIGHTS.ssl,
      recommendation: "Обновите сертификат или проверьте цепочку.",
      owasp: OWASP.crypto,
    });
  }

  if (hasSSL && daysLeft !== null && daysLeft > 30) {
    score += WEIGHTS.sslDays;
  } else if (hasSSL && daysLeft !== null && daysLeft <= 30) {
    add({
      id: "ssl-expiring",
      title: "SSL истекает скоро",
      desc: `Сертификат истекает через ${daysLeft} дн.`,
      severity: "low",
      weight: WEIGHTS.sslDays,
      recommendation: "Настройте автопродление сертификата.",
      owasp: OWASP.crypto,
    });
  }

  if (ssl.hasSSL && ssl.supportsOldTls) {
    score -= OLD_TLS_PENALTY;
    add({
      id: "old-tls",
      title: "Устаревший TLS",
      desc: "Сервер поддерживает TLS 1.0 или 1.1, которые уязвимы к атакам.",
      severity: "medium",
      weight: OLD_TLS_PENALTY,
      recommendation:
        "Отключите TLS 1.0 и 1.1 на сервере, оставьте только 1.2 и 1.3.",
      owasp: OWASP.crypto,
    });
  }

  // --- HTTP-заголовки, cookie, CORS ----------------------------------------
  if (h.error) {
    add({
      id: "headers-unavailable",
      title: "Не удалось проверить заголовки",
      desc: "Сервер не ответил на HTTP-запрос. Часть проверок не выполнена.",
      severity: "medium",
      weight: 0,
      recommendation: "Повторите скан позже.",
      owasp: OWASP.misconfig,
    });
  } else {
    // Заголовок с небезопасным значением (HSTS: max-age=0, COOP: unsafe-none,
    // Referrer-Policy: unsafe-url, XCTO: foo) — это «weak»: защита выключена,
    // поэтому баллов он не даёт, но и формулировка «нет заголовка» неверна.
    const headerFinding = (state, weight, options) => {
      const weak = state === "weak";
      add({
        id: weak ? options.weakId : options.id,
        title: weak ? options.weakTitle : options.title,
        desc: weak ? options.weakDesc : options.desc,
        severity: options.severity,
        weight,
        recommendation: options.recommendation,
        owasp: OWASP.misconfig,
      });
    };

    if (h.hsts && hasSSL) {
      score += WEIGHTS.hsts;
    } else if (hasSSL) {
      headerFinding(h.hstsState, WEIGHTS.hsts, {
        id: "no-hsts",
        weakId: "weak-hsts",
        title: "Нет HSTS",
        weakTitle: "HSTS не защищает",
        desc: "Не включён Strict-Transport-Security — риск downgrade-атаки после первого визита.",
        weakDesc:
          "Strict-Transport-Security есть, но max-age=0 или отсутствует: браузер не запоминает HTTPS.",
        severity: "medium",
        recommendation: "Добавьте Strict-Transport-Security: max-age=31536000.",
      });
    }

    if (h.csp) {
      score += WEIGHTS.csp;
    } else {
      headerFinding(h.cspState, WEIGHTS.csp, {
        id: "no-csp",
        weakId: "weak-csp",
        title: "Нет CSP",
        weakTitle: "CSP не ограничивает источники",
        desc: "Отсутствие Content-Security-Policy снижает защиту от XSS.",
        weakDesc:
          "Content-Security-Policy есть, но script-src/default-src не ограничены (wildcard или unsafe-inline).",
        severity: "high",
        recommendation: "Добавьте CSP с ограничением script-src.",
      });
    }

    if (h.xframe) {
      score += WEIGHTS.xframe;
    } else {
      headerFinding(h.xframeState, WEIGHTS.xframe, {
        id: "no-xframe",
        weakId: "weak-xframe",
        title: "Нет X-Frame-Options",
        weakTitle: "X-Frame-Options не защищает",
        desc: "Страницу можно встроить во фрейм — риск кликджекинга.",
        weakDesc:
          "X-Frame-Options есть, но значение не DENY/SAMEORIGIN — встраивание не запрещено.",
        severity: "medium",
        recommendation: "Добавьте X-Frame-Options: DENY.",
      });
    }

    if (h.xcontent) {
      score += WEIGHTS.xcontent;
    } else {
      headerFinding(h.xcontentState, WEIGHTS.xcontent, {
        id: "no-xcontent",
        weakId: "weak-xcontent",
        title: "Нет X-Content-Type-Options",
        weakTitle: "X-Content-Type-Options не включён",
        desc: "Браузер может интерпретировать файлы неверно.",
        weakDesc:
          "X-Content-Type-Options есть, но значение не nosniff — MIME-sniffing не отключён.",
        severity: "medium",
        recommendation: "Добавьте X-Content-Type-Options: nosniff.",
      });
    }

    if (/(?:^|[\s/])\d+(?:\.\d+)*/.test(typeof h.server === "string" ? h.server : "")) {
      add({
        id: "server-exposed",
        title: "Раскрыт Server",
        desc: "В заголовке Server есть номер версии — это упрощает подбор эксплойтов.",
        severity: "low",
        weight: WEIGHTS.server,
        recommendation:
          "Уберите версию из заголовка Server или скройте его в конфиге nginx/apache.",
        owasp: OWASP.misconfig,
      });
    } else {
      score += WEIGHTS.server;
    }

    // Дополнительные заголовки: undefined значит «не проверялось» — не
    // штрафуем старые/частичные отчёты, false значит «проверено и отсутствует».
    const headerCheck = (value, state, weight, options) => {
      if (value === undefined) return weight;
      if (value) return weight;
      headerFinding(state, weight, options);
      return 0;
    };

    score += headerCheck(h.referrerPolicy, h.referrerPolicyState, WEIGHTS.referrer, {
      id: "no-referrer-policy",
      weakId: "weak-referrer-policy",
      title: "Нет Referrer-Policy",
      weakTitle: "Referrer-Policy не защищает",
      desc: "Браузер может передавать полный URL во внешние ресурсы через Referer.",
      weakDesc:
        "Referrer-Policy задаёт unsafe-url или неизвестное значение — полный URL утекает во внешние ресурсы.",
      severity: "low",
      recommendation: "Добавьте Referrer-Policy: strict-origin-when-cross-origin.",
    });

    score += headerCheck(h.permissionsPolicy, h.permissionsPolicyState, WEIGHTS.permissions, {
      id: "no-permissions-policy",
      weakId: "no-permissions-policy",
      title: "Нет Permissions-Policy",
      weakTitle: "Нет Permissions-Policy",
      desc: "Браузерные API (камера, микрофон, геолокация) не ограничены заголовком.",
      weakDesc:
        "Браузерные API (камера, микрофон, геолокация) не ограничены заголовком.",
      severity: "low",
      recommendation: "Добавьте Permissions-Policy и отключите ненужные API.",
    });

    score += headerCheck(h.coop, h.coopState, WEIGHTS.coop, {
      id: "no-coop",
      weakId: "weak-coop",
      title: "Нет Cross-Origin-Opener-Policy",
      weakTitle: "COOP не изолирует страницу",
      desc: "Страница не изолирована от cross-origin opener — возможны атаки через window.opener.",
      weakDesc:
        "Cross-Origin-Opener-Policy есть, но значение (например, unsafe-none) не изолирует opener.",
      severity: "medium",
      recommendation: "Добавьте Cross-Origin-Opener-Policy: same-origin.",
    });

    if (h.corsWildcard) {
      add({
        id: "cors-wildcard",
        title: "CORS разрешён для всех",
        desc: "Access-Control-Allow-Origin: * позволяет любому origin читать ответы API.",
        severity: "high",
        weight: WEIGHTS.cors,
        recommendation:
          "Замените * на явный список origin и не включайте credentials вместе с *.",
        owasp: OWASP.misconfig,
      });
    } else {
      score += WEIGHTS.cors;
    }

    const cookieSummary = cookieSummaryFrom(h);
    if (!cookieSummary || cookieSummary.total === 0) {
      score +=
        WEIGHTS.cookieSecure + WEIGHTS.cookieHttpOnly + WEIGHTS.cookieSameSite;
    } else {
      // Secure имеет смысл только на подтверждённом HTTPS. На чистом HTTP
      // этот флаг неприменим (как и в UI), а при ssl.error/невалидном
      // сертификате отсутствие Secure — следствие сломанного TLS, за которое
      // уже есть отдельная находка.
      if (cookieSummary.missingSecure === 0) {
        score += WEIGHTS.cookieSecure;
      } else if (hasSSL) {
        add({
          id: "cookie-no-secure",
          title: "Cookie без Secure",
          desc: "Часть cookie может передаваться по HTTP — риск перехвата сессии.",
          severity: "high",
          weight: WEIGHTS.cookieSecure,
          recommendation: "Добавьте флаг Secure всем cookie на HTTPS-сайте.",
          owasp: OWASP.crypto,
        });
      } else if (
        ssl.error ||
        ssl.tlsConfirmed === true ||
        (ssl.hasSSL && !ssl.valid)
      ) {
        // Отдельный штраф не начисляем: причина уже в ssl-error/ssl-unverified/
        // bad-ssl. Флаг Secure без подтверждённого сертификата не проверить.
      } else {
        score += WEIGHTS.cookieSecure;
      }

      // SameSite=None без Secure браузеры отвергают: cookie просто не
      // доедет, поэтому это отдельная находка, а не «флаг есть».
      if (cookieSummary.insecureNone > 0) {
        add({
          id: "cookie-samesite-none-insecure",
          title: "SameSite=None без Secure",
          desc: "Cookie с SameSite=None не имеет флага Secure — современные браузеры такое cookie отвергают.",
          severity: "medium",
          weight: 0,
          recommendation: "Добавьте Secure к cookie с SameSite=None.",
          owasp: OWASP.misconfig,
        });
      }

      if (cookieSummary.missingHttpOnly === 0) {
        score += WEIGHTS.cookieHttpOnly;
      } else {
        add({
          id: "cookie-no-httponly",
          title: "Cookie без HttpOnly",
          desc: "JavaScript может читать cookie — XSS сразу приводит к краже сессии.",
          severity: "medium",
          weight: WEIGHTS.cookieHttpOnly,
          recommendation: "Добавьте HttpOnly всем сессионным cookie.",
          owasp: OWASP.misconfig,
        });
      }

      if (cookieSummary.missingSameSite === 0) {
        score += WEIGHTS.cookieSameSite;
      } else {
        add({
          id: "cookie-no-samesite",
          title: "Cookie без SameSite",
          desc: "Cookie отправляется в cross-site запросах — риск CSRF.",
          severity: "low",
          weight: WEIGHTS.cookieSameSite,
          recommendation: "Укажите SameSite=Lax или Strict для cookie.",
          owasp: OWASP.misconfig,
        });
      }
    }
  }

  // --- Порты ---------------------------------------------------------------
  if (riskyPorts.length === 0) {
    score += WEIGHTS.riskyPorts;
  } else {
    riskyPorts.forEach((p) =>
      add({
        id: `port-${p.port}`,
        title: `Открыт опасный порт ${p.port}`,
        desc: `Порт ${p.port} доступен из интернета.`,
        severity: "high",
        weight: WEIGHTS.riskyPorts,
        recommendation: `Закройте ${p.port} файрволом или ACL.`,
        owasp: OWASP.misconfig,
      }),
    );
  }

  if (!ports.some((p) => p.port === 8080 && p.status === "open")) {
    score += WEIGHTS.port8080;
  } else {
    add({
      id: "port-8080",
      title: "Открыт порт 8080",
      desc: "Может использоваться для админки.",
      severity: "medium",
      weight: WEIGHTS.port8080,
      recommendation: "Закройте 8080 или ограничьте по IP.",
      owasp: OWASP.misconfig,
    });
  }

  // --- DNS / email ---------------------------------------------------------
  const dns = input.dns;
  if (!dns || dns.applicable === false) {
    // Для IP/localhost проверки неприменимы, для старого отчёта их просто нет.
    score += WEIGHTS.spf + WEIGHTS.dmarc + WEIGHTS.caa;
  } else {
    const spf = dns.spf;
    if (!spf) {
      score += WEIGHTS.spf;
    } else if (spf.multiple) {
      add({
        id: "spf-multiple",
        title: "Несколько SPF-записей",
        desc: "В TXT-записях домена больше одного v=spf1. По RFC 7208 это permerror: проверка SPF не проходит.",
        severity: "medium",
        weight: WEIGHTS.spf,
        recommendation: "Оставьте ровно одну TXT-запись v=spf1 и перенесите в неё все include.",
        owasp: OWASP.auth,
      });
    } else if (spf.present && spf.weak) {
      add({
        id: "spf-weak",
        title: "Слабый SPF",
        desc: "SPF разрешает отправку писем от имени домена всем (+all/?all) или не содержит механизмов.",
        severity: "medium",
        weight: WEIGHTS.spf,
        recommendation: "Замените +all на -all и перечислите только доверенных отправителей.",
        owasp: OWASP.auth,
      });
    } else if (spf.present) {
      score += WEIGHTS.spf;
    } else if (!isDnsUnavailable(spf, APEX_MISSING_ERRORS)) {
      add({
        id: "spf-missing",
        title: "Нет SPF",
        desc: "В TXT-записях домена нет v=spf1 — письма можно подделывать от имени домена.",
        severity: "medium",
        weight: WEIGHTS.spf,
        recommendation: "Добавьте TXT-запись v=spf1 с разрешёнными отправителями.",
        owasp: OWASP.auth,
      });
    } else {
      score += WEIGHTS.spf;
    }

    const dmarc = dns.dmarc;
    if (!dmarc) {
      score += WEIGHTS.dmarc;
    } else if (dmarc.multiple) {
      add({
        id: "dmarc-multiple",
        title: "Несколько DMARC-записей",
        desc: "В _dmarc опубликовано больше одной v=DMARC1. По RFC 7489 такие записи не применяются: политика не действует.",
        severity: "medium",
        weight: WEIGHTS.dmarc,
        recommendation: "Оставьте ровно одну _dmarc-запись с политикой p=quarantine или p=reject.",
        owasp: OWASP.auth,
      });
    } else if (dmarc.present) {
      const policy =
        typeof dmarc.policy === "string" ? dmarc.policy.toLowerCase() : null;
      if (policy === "reject" || policy === "quarantine") {
        score += WEIGHTS.dmarc;
      } else if (policy === "none") {
        add({
          id: "dmarc-weak",
          title: "DMARC p=none",
          desc: "Политика DMARC только наблюдает и не блокирует поддельные письма.",
          severity: "medium",
          weight: WEIGHTS.dmarc,
          recommendation: "Переведите DMARC на p=quarantine или p=reject.",
          owasp: OWASP.auth,
        });
      } else {
        add({
          id: "dmarc-invalid",
          title: "Некорректный DMARC",
          desc: "DMARC-запись есть, но политика p не распознана или отсутствует.",
          severity: "medium",
          weight: WEIGHTS.dmarc,
          recommendation: "Укажите p=none, p=quarantine или p=reject в _dmarc-записи.",
          owasp: OWASP.auth,
        });
      }
    } else if (!isDnsUnavailable(dmarc)) {
      add({
        id: "dmarc-missing",
        title: "Нет DMARC",
        desc: "Нет TXT-записи _dmarc — домен не защищён от подделки писем.",
        severity: "medium",
        weight: WEIGHTS.dmarc,
        recommendation: "Добавьте _dmarc с политикой p=quarantine или p=reject.",
        owasp: OWASP.auth,
      });
    } else {
      score += WEIGHTS.dmarc;
    }

    const caa = dns.caa;
    // iodef-запись сообщает, куда слать отчёты, но не ограничивает выпуск
    // сертификатов: ограничением считаем только issue/issuewild.
    const caaRestrictive =
      !caa ||
      (caa.restrictive === undefined ? Boolean(caa.present) : caa.restrictive);

    if (caaRestrictive) {
      score += WEIGHTS.caa;
    } else if (!isDnsUnavailable(caa, APEX_MISSING_ERRORS)) {
      // Два разных случая: записи нет вовсе и запись есть, но не ограничивает
      // выпуск (только iodef). Один текст «Нет CAA» на оба — ложь во втором
      // случае и расходится с карточкой UI.
      const hasRecords = Boolean(caa && caa.present === true);

      add({
        id: hasRecords ? "caa-not-restrictive" : "caa-missing",
        title: hasRecords ? "CAA не ограничивает выпуск" : "Нет CAA",
        desc: hasRecords
          ? "Опубликованы только служебные CAA-записи (например, iodef): они не указывают, какие удостоверяющие центры могут выпускать сертификаты."
          : "CAA-записи не ограничивают, какие удостоверяющие центры могут выпускать сертификаты.",
        severity: "low",
        weight: WEIGHTS.caa,
        recommendation: hasRecords
          ? "Добавьте CAA-запись issue с вашим удостоверяющим центром (iodef её не заменяет)."
          : "Добавьте CAA-запись issue с вашим удостоверяющим центром.",
        owasp: OWASP.misconfig,
      });
    } else {
      score += WEIGHTS.caa;
    }
  }

  // --- Открытые файлы ------------------------------------------------------
  const files = input.files;
  let filesCap = 100;

  if (!files) {
    score +=
      WEIGHTS.env + WEIGHTS.git + WEIGHTS.backup + WEIGHTS.dsStore;
  } else {
    const exposed = exposedPaths(files);

    // HEAD-проба, которая упала (WAF/таймаут), ничего не доказывает:
    // за такой путь баллы не начисляем, но и находку не создаём.
    const failedProbes = new Set();
    if (Array.isArray(files.results)) {
      for (const item of files.results) {
        if (item && item.error && typeof item.path === "string") {
          failedProbes.add(item.path);
        }
      }
    }

    for (const check of FILE_CHECKS) {
      if (exposed.has(check.path)) {
        add({
          id: check.id,
          title: check.title,
          desc: check.desc,
          severity: check.severity,
          weight: check.weight,
          recommendation: check.recommendation,
          owasp: check.owasp,
        });
        if (Number.isFinite(check.cap)) {
          filesCap = Math.min(filesCap, check.cap);
        }
      } else if (failedProbes.has(check.path)) {
        // Неизвестно, открыт ли путь: оставляем статус «не проверено».
      } else {
        score += check.weight;
      }
    }
  }

  // --- security.txt --------------------------------------------------------
  const securityTxt = input.securityTxt;
  if (!securityTxt || securityTxt.present || securityTxt.status !== 404) {
    score += WEIGHTS.securityTxt;
  } else {
    add({
      id: "security-txt-missing",
      title: "Нет security.txt",
      desc: "По /.well-known/security.txt не опубликованы контакты для сообщения об уязвимостях.",
      severity: "low",
      weight: WEIGHTS.securityTxt,
      recommendation: "Опубликуйте security.txt с контактом и сроком ответа.",
      owasp: OWASP.misconfig,
    });
  }

  // --- Fingerprint (информационно, без баллов) -----------------------------
  const fingerprint = input.fingerprint;
  if (fingerprint && fingerprint.waf && fingerprint.waf.name) {
    add({
      id: "waf-detected",
      title: "Обнаружен WAF",
      desc: `WAF: ${fingerprint.waf.name}. Это защитный слой, а не недостаток.`,
      severity: "low",
      weight: 0,
      recommendation:
        "Проверьте, что правила WAF обновляются и не блокируют легитимный трафик.",
      owasp: OWASP.misconfig,
    });
  }
  if (fingerprint && fingerprint.cms && fingerprint.cms.name) {
    add({
      id: "cms-detected",
      title: "Обнаружена CMS",
      desc: `CMS: ${fingerprint.cms.name}. Версия и плагины не проверялись.`,
      severity: "low",
      weight: 0,
      recommendation:
        "Держите CMS, плагины и темы обновлёнными; уберите лишние компоненты.",
      owasp: OWASP.vulnerable,
    });
  }

  // --- Потолки -------------------------------------------------------------
  let cap = 100;

  if (h.error) cap = Math.min(cap, 60);
  // Тот же принцип: ошибка TLS режет оценку до 60 только когда HTTPS не
  // подтверждён. Если заголовки пришли по HTTPS, потолок 60 — ложный.
  if (ssl.error && ssl.tlsConfirmed !== true) cap = Math.min(cap, 60);
  if (!ssl.hasSSL && !ssl.error && ssl.tlsConfirmed !== true) {
    cap = Math.min(cap, 30);
  } else if (ssl.hasSSL && !ssl.valid) {
    cap = Math.min(cap, 40);
  }
  if (has3306) cap = Math.min(cap, 70);
  if (ssl.supportsOldTls) cap = Math.min(cap, 85);
  if (hasSSL && daysLeft !== null && daysLeft <= 7) cap = Math.min(cap, 90);
  if (h.corsWildcard) cap = Math.min(cap, 60);
  cap = Math.min(cap, filesCap);
  if (findings.some((f) => f.severity !== "low")) cap = Math.min(cap, 90);

  score = Math.min(score, cap);
  score = Math.max(0, Math.min(100, score));

  let grade = "F";
  if (score >= 95) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else if (score >= 20) grade = "E";

  // Порядок в отчёте: сначала severity (high → medium → low), внутри уровня —
  // по весу. Только по весу low-находка могла стоять выше medium.
  const SEVERITY_RANK = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => {
    const rank =
      (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3);
    if (rank !== 0) return rank;
    return b.weight - a.weight;
  });

  return { score, grade, findings };
}

module.exports = { calculateScore, WEIGHTS };
