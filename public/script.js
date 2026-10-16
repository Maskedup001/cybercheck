const API_URL = "http://localhost:3000/api";

async function scan() {
  const url = document.getElementById("url").value.trim();
  const consent = document.getElementById("consent").checked;
  const resultEl = document.getElementById("result");
  const btn = document.getElementById("scanBtn");

  if (!url) {
    resultEl.textContent = "Введи адрес сайта";
    return;
  }

  if (!consent) {
    resultEl.textContent = "Подтверди согласие на проверку";
    return;
  }

  btn.disabled = true;
  resultEl.textContent = "Сканирую... (максимум 30 секунд)";

  // Таймаут 30 сек — прерываем запрос, если сервер не ответил
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30_000);

  try {
    const res = await fetch(`${API_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        consent,
        // Timestamp нужен бэку для проверки свежести согласия
        consentTimestamp: Date.now(),
      }),
      signal: controller.signal,
    });

    const data = await res.json();

    if (data.error) {
      resultEl.textContent = `Ошибка: ${data.error}`;
    } else {
      render(data);
    }
  } catch (e) {
    if (e.name === "AbortError") {
      resultEl.textContent =
        "Превышено время ожидания (30 сек). Попробуй другой адрес.";
    } else {
      resultEl.textContent = "Ошибка: не удалось подключиться к серверу";
    }
  } finally {
    clearTimeout(timeoutId);
    btn.disabled = false;
  }
}

// Формирует текстовый отчёт из ответа бэкенда
function render(d) {
  let out = `Хост: ${d.host}\n`;

  out += "\n=== ПОРТЫ ===\n";
  if (d.ports.length === 0) {
    out += "  Открытых портов не найдено\n";
  } else {
    d.ports.forEach((p) => (out += `  Порт ${p.port}: открыт\n`));
  }

  out += "\n=== SSL ===\n";
  if (d.ssl.hasSSL) {
    out += `  Сертификат: ${d.ssl.valid ? "валиден" : "невалиден"}\n`;
    out += `  Истекает: ${d.ssl.validTo || "н/д"}\n`;
    out += `  Осталось дней: ${d.ssl.daysLeft ?? "н/д"}\n`;
    out += `  Издатель: ${d.ssl.issuer || "неизвестен"}\n`;
  } else {
    out += "  SSL отсутствует — данные передаются открыто\n";
  }

  out += "\n=== ЗАГОЛОВКИ БЕЗОПАСНОСТИ ===\n";
  const h = d.headers;
  if (h.error) {
    out += "  Не удалось получить\n";
  } else {
    out += `  Протокол: ${h.protocol}\n`;
    out += `  Server: ${h.server}\n`;
    out += `  Content-Security-Policy: ${h.csp ? "есть" : "НЕТ"}\n`;
    out += `  X-Frame-Options: ${h.xframe ? "есть" : "НЕТ"}\n`;
    out += `  Strict-Transport-Security: ${h.hsts ? "есть" : "НЕТ"}\n`;
    out += `  X-Content-Type-Options: ${h.xcontent ? "есть" : "НЕТ"}\n`;
  }

  document.getElementById("result").textContent = out;
}

// Обработчик кнопки — вынесен из HTML для строгого CSP
document.getElementById('scanBtn').addEventListener('click', scan);