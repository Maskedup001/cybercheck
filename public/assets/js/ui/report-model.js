/* Чистые функции отчёта: без DOM, без сети. Их использует рендер, и их же
   проверяют тесты — поэтому тексты карточек и «критичность» путей живут
   в одном месте, а не дублируются в scoring и в UI. */

const MAX_TEXT = 120;

// DNS-код, который означает «записи нет», а не «не удалось проверить».
// Для CAA набор строже, чем для остальных секций: apex-домен, который уже
// разрешился, не может внезапно получить ENOTFOUND, поэтому такой ответ —
// сбой резолвера, а не отсутствие записи. Ровно так же его трактует scoring
// (APEX_MISSING_ERRORS).
const CAA_MISSING_ERRORS = new Set(["ENODATA"]);

// Русское склонение по числу: 1 путь, 2 пути, 5 путей, 11 путей, 21 путь.
export function plural(count, forms) {
  const abs = Math.abs(count) % 100;
  const last = abs % 10;

  if (abs > 10 && abs < 20) return forms[2];
  if (last > 1 && last < 5) return forms[1];
  if (last === 1) return forms[0];
  return forms[2];
}

// Убирает управляющие символы и bidi-переопределения: XSS при textContent
// невозможен, но визуально подменить текст карточки/PDF недоверенный Server
// или issuer сертификата могли бы.
export function sanitizeText(value, maxLength = MAX_TEXT) {
  if (typeof value !== "string") return "";

  const cleaned = value
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .replace(/\s+/g, " ")
    .trim();

  return cleaned.slice(0, maxLength);
}

// Критические пути берутся из files.critical — единственного источника,
// который определяет сервер. Своего списка путей в UI нет.
export function getCriticalPaths(files) {
  const paths = new Set();
  if (!files || typeof files !== "object") return paths;
  if (!Array.isArray(files.critical)) return paths;

  for (const item of files.critical) {
    let path = null;
    if (typeof item === "string") path = item;
    else if (item && typeof item.path === "string") path = item.path;
    if (path) paths.add(path);
  }

  return paths;
}

// Все пути, которые сервер считает открытыми. Старый контракт без exposed
// восстанавливается из results (только 200).
export function getExposedFiles(files) {
  const paths = new Set();
  if (!files || typeof files !== "object") return [];

  if (Array.isArray(files.exposed)) {
    for (const path of files.exposed) {
      if (typeof path === "string") paths.add(path);
    }
  }

  for (const path of getCriticalPaths(files)) paths.add(path);

  if (paths.size === 0 && Array.isArray(files.results)) {
    for (const item of files.results) {
      if (item && item.status === 200 && typeof item.path === "string") {
        paths.add(item.path);
      }
    }
  }

  return Array.from(paths);
}

// Сколько HEAD-проб реально ответили, сколько упало и сколько заблокировано.
export function getProbeStats(files) {
  const results = Array.isArray(files && files.results) ? files.results : [];
  let failed = 0;
  let blocked = 0;
  let exposed = 0;

  for (const item of results) {
    if (!item || typeof item !== "object") continue;
    if (item.error) failed += 1;
    else if (item.status === 403) blocked += 1;
    else if (item.status === 200) exposed += 1;
  }

  return { total: results.length, failed, blocked, exposed };
}

// Текст под карточкой «Открытые файлы». «Не найдено» допустимо только когда
// все пробы действительно ответили: иначе непроверенное выдаётся за
// проверенное отрицание.
export function filesNote(files) {
  if (!files || typeof files !== "object") {
    return "Не удалось проверить: данные HEAD-проб не получены.";
  }

  const exposed = getExposedFiles(files);
  const criticalPaths = getCriticalPaths(files);
  const { total, failed, blocked } = getProbeStats(files);

  if (exposed.length > 0) {
    const critical = exposed.filter((path) => criticalPaths.has(path));

    if (critical.length > 0) {
      return `Найдены файлы, доступные без авторизации: ${critical.join(", ")}. Это критично.`;
    }

    return `Найдены файлы, доступные без авторизации: ${exposed.join(", ")}. Критических путей среди них нет.`;
  }

  if (total > 0 && failed >= total) {
    const pathsForm = plural(total, ["пути", "путей", "путей"]);
    return `Не удалось проверить ни один из ${total} ${pathsForm} (WAF или таймаут). Что файлов нет — не подтверждено.`;
  }

  const parts = ["Открытых файлов не найдено."];
  if (failed > 0) parts.push(`Не удалось проверить ${failed} из ${total}.`);
  if (blocked > 0) {
    const verb = plural(blocked, [
      "заблокирован",
      "заблокированы",
      "заблокировано",
    ]);
    const paths = plural(blocked, ["путь", "пути", "путей"]);
    parts.push(`${verb} ${blocked} ${paths} (403/WAF).`);
  }

  return parts.join(" ");
}

// Пояснение к карточке TLS, когда проверить его было нечем.
export function tlsNotice(ssl, ports) {
  if (!ssl || typeof ssl !== "object") return null;

  const list = Array.isArray(ports) ? ports : [];

  if (ssl.error === "NO_WEB_PORT") {
    return "TLS не проверялся: у сайта не открыт ни один веб-порт (80, 443, 8080).";
  }

  // HTTPS подтверждён ответом сервера, но сертификат прочитать не удалось:
  // «SSL не настроен» здесь так же неверно, как и «TLS не проверялся».
  if (ssl.tlsConfirmed === true) {
    return "HTTPS работает (подтверждено ответом сервера), но сертификат не удалось прочитать. Срок и цепочку проверьте вручную.";
  }

  if (!ssl.hasSSL && !ssl.error && list.length === 0) {
    return "TLS не проверялся: у сайта не открыт ни один веб-порт (80, 443, 8080).";
  }

  return null;
}

// Состояние CAA для карточки: present сам по себе ничего не значит, если
// записи только служебные (iodef) и выпуск сертификатов не ограничивают.
export function caaState(caa) {
  if (!caa || typeof caa !== "object") return "unknown";
  if (caa.error && !CAA_MISSING_ERRORS.has(caa.error)) return "unknown";
  if (!caa.present) return "missing";

  // Старый контракт без restrictive считаем ограничивающим — так же, как
  // scoring: иначе UI и оценка разойдутся на старых отчётах.
  return caa.restrictive === false ? "weak" : "ok";
}

// Контекст, в котором HSTS и флаг Secure вообще имеют смысл: только
// подтверждённый HTTPS с валидным сертификатом. При невалидном сертификате
// их отсутствие — следствие уже наказанной ошибки TLS, а не отдельная
// проблема, поэтому карточка показывает «н/д», а не красное «нет».
export function secureContextState(ssl) {
  if (!ssl || typeof ssl !== "object") return "unknown";
  // HTTPS подтверждён заголовками, но сертификат не прочитан: это не «TLS не
  // проверен» — карточка TLS в этом же отчёте говорит, что HTTPS работает.
  if (ssl.tlsConfirmed === true) return "unverified";
  if (ssl.error) return "unknown";
  if (ssl.hasSSL !== true) return "no-https";
  if (ssl.valid === false) return "invalid-cert";
  return "ok";
}

// Имя отчёта: используется и в заголовке вкладки, и в имени PDF. host "—" —
// заглушка нормализации, а не домен.
export function reportTitleFor(host, date) {
  const safeHost = sanitizeText(host, 60);
  if (!safeHost || safeHost === "—") return "";
  return `CyberCheck_${safeHost}_${date}`;
}

// Текст для кнопки «Скопировать отчёт»: 3–5 самых важных находок с
// рекомендациями. Информационные WAF/CMS не включаем — это не проблема,
// которую нужно исправлять. Формат рассчитан на вставку в чат или тикет.
export function buildShareText(report) {
  if (!report || typeof report !== "object") return "";

  const host = sanitizeText(report.host, 60);
  const score = Number.isFinite(report.score) ? Math.round(report.score) : 0;
  const grade = typeof report.grade === "string" ? report.grade : "?";
  const findings = (Array.isArray(report.findings) ? report.findings : []).filter(
    (finding) =>
      finding &&
      typeof finding === "object" &&
      finding.id !== "waf-detected" &&
      finding.id !== "cms-detected",
  );

  const severityLabels = {
    high: "Критично",
    medium: "Важно",
    low: "Замечание",
  };

  const lines = [
    `CyberCheck — отчёт для ${host || "сайта"}`,
    `Оценка: ${score}/100 (${grade})`,
    "",
  ];

  if (findings.length === 0) {
    lines.push("Замечаний нет — базовая гигиена в порядке.");
  } else {
    lines.push("Что исправить в первую очередь:");
    findings.slice(0, 5).forEach((finding, index) => {
      const title = sanitizeText(finding.title, MAX_TEXT) || "Замечание";
      const severity =
        severityLabels[finding.severity] ?? severityLabels.low;
      const recommendation = sanitizeText(finding.recommendation, 200);
      const fix = recommendation ? ` — ${recommendation}` : "";

      lines.push(`${index + 1}. [${severity}] ${title}${fix}`);
    });
  }

  lines.push(
    "",
    "Отчёт сформирован автоматически и не заменяет полноценный аудит.",
  );

  return lines.join("\n");
}
