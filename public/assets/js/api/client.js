const API_URL = "/api";
const TIMEOUT_MS = 65_000;

const SEVERITIES = ["high", "medium", "low"];
// Оценка — только A–F: произвольная строка из ответа не должна попадать ни
// в текст, ни в поиск по объекту (например, "__proto__").
const GRADES = ["A", "B", "C", "D", "E", "F"];

/**
 * Рендер отчёта читает поля находки напрямую: элемент без title или desc
 * уронил бы его уже после успешного скана, и пользователь увидел бы
 * «Ошибка: …» вместо отчёта. Приводим форму до передачи в рендер.
 */
export function normalizeFinding(raw) {
  const finding = raw && typeof raw === "object" ? raw : {};

  return {
    id: typeof finding.id === "string" ? finding.id : "",
    title: typeof finding.title === "string" ? finding.title : "Замечание",
    desc: typeof finding.desc === "string" ? finding.desc : "",
    severity: SEVERITIES.includes(finding.severity) ? finding.severity : "low",
    weight: Number.isFinite(finding.weight) ? finding.weight : 0,
    owasp: typeof finding.owasp === "string" ? finding.owasp : "",
    recommendation:
      typeof finding.recommendation === "string"
        ? finding.recommendation
        : "Проверьте настройку вручную.",
  };
}

export async function scanTarget({ url, consent, consentToken }) {
  // <-- Добавили consentToken
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    // Только сетевой вызов: TypeError от fetch означает «запрос не ушёл»
    // (нет сети, DNS, обрыв, CORS). Ловить TypeError вокруг всей функции
    // нельзя — тогда любая ошибка нормализации выглядела бы как «нет связи».
    let res;
    try {
      res = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, consent, consentToken }), // <-- Передаем токен
        signal: controller.signal,
      });
    } catch (error) {
      if (error && error.name === "AbortError") {
        throw new Error(
          "Превышено время ожидания (65 сек). Попробуйте другой адрес.",
        );
      }
      if (error && error.name === "TypeError") {
        // Браузерный текст («Failed to fetch») английский и ничего не
        // подсказывает, поэтому заменяем его своим.
        throw new Error(
          "Не удалось связаться с сервером. Проверьте соединение и повторите.",
        );
      }
      throw error;
    }

    // Таймаут может сработать уже во время чтения тела ответа. Если
    // проглотить AbortError, пользователь увидит «некорректный ответ»
    // вместо честного «превышено время ожидания».
    const data = await res.json().catch((error) => {
      if (error && error.name === "AbortError") {
        throw new Error(
          "Превышено время ожидания (65 сек). Попробуйте другой адрес.",
        );
      }
      return null;
    });

    if (!res.ok) throw new Error(data?.error || `Сервер ответил ${res.status}`);
    if (!data) throw new Error("Сервер вернул некорректный ответ");

    // Защита от неполного или некорректного JSON
    const normalized = {
      host: typeof data.host === "string" ? data.host : "—",
      // Карточка портов рисует «открыт/опасный», поэтому закрытый порт в
      // списке показывался бы открытым. Старый контракт без status — open.
      ports: Array.isArray(data.ports)
        ? data.ports.filter(
            (p) =>
              p &&
              Number.isInteger(p.port) &&
              (p.status === undefined || p.status === "open"),
          )
        : [],
      ssl:
        data.ssl && typeof data.ssl === "object" ? data.ssl : { hasSSL: false },
      headers:
        data.headers && typeof data.headers === "object"
          ? data.headers
          : { error: true },
      dns: data.dns && typeof data.dns === "object" ? data.dns : null,
      files: data.files && typeof data.files === "object" ? data.files : null,
      securityTxt:
        data.securityTxt && typeof data.securityTxt === "object"
          ? data.securityTxt
          : null,
      fingerprint:
        data.fingerprint && typeof data.fingerprint === "object"
          ? data.fingerprint
          : null,
      // Number.isFinite(NaN) === false, а typeof NaN === "number":
      // Math.max(0, NaN) дал бы NaN в UI.
      score: Number.isFinite(data.score)
        ? Math.min(100, Math.max(0, data.score))
        : 0,
      grade: GRADES.includes(data.grade) ? data.grade : "?",
      findings: Array.isArray(data.findings)
        ? data.findings.map(normalizeFinding)
        : [],
    };
    return normalized;
  } finally {
    clearTimeout(timeoutId);
  }
}
