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
function normalizeFinding(raw) {
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

export async function scanTarget({ url, consent }) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, consent, consentTimestamp: Date.now() }),
      signal: controller.signal,
    });

    const data = await res.json().catch(() => null);

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
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "Превышено время ожидания (65 сек). Попробуйте другой адрес.",
      );
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
