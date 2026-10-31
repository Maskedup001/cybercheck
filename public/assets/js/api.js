const API_URL = "/api";
const TIMEOUT_MS = 45_000;

const SEVERITIES = ["high", "medium", "low"];

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
      ports: Array.isArray(data.ports)
        ? data.ports.filter((p) => Number.isInteger(p?.port))
        : [],
      ssl:
        data.ssl && typeof data.ssl === "object" ? data.ssl : { hasSSL: false },
      headers:
        data.headers && typeof data.headers === "object"
          ? data.headers
          : { error: true },
      score: typeof data.score === "number" ? data.score : 0,
      grade: typeof data.grade === "string" ? data.grade : "?",
      findings: Array.isArray(data.findings)
        ? data.findings.map(normalizeFinding)
        : [],
    };
    return normalized;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "Превышено время ожидания (45 сек). Попробуйте другой адрес.",
      );
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
