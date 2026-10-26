const API_URL = "/api";
const TIMEOUT_MS = 30_000;

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

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error(
        "Превышено время ожидания (30 сек). Попробуйте другой адрес.",
      );
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
