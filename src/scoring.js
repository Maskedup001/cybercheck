function calculateScore(report) {
  const findings = [];
  let score = 0;

  const ssl = report.ssl || {};
  const h = report.headers || { error: true };
  const ports = report.ports || [];

  const hasSSL = !!ssl.hasSSL && !!ssl.valid;
  const daysLeft = typeof ssl.daysLeft === "number" ? ssl.daysLeft : null;
  const riskyPorts = ports.filter((p) => [22, 3306].includes(p.port));
  const has3306 = ports.some((p) => p.port === 3306);
  const push = (f) => findings.push(f);

  if (hasSSL) score += 20;
  else if (!ssl.hasSSL)
    push({
      id: "no-ssl",
      title: "Нет SSL",
      desc: "Сайт работает по HTTP — трафик не шифруется.",
      severity: "high",
      weight: 20,
      recommendation: "Настройте HTTPS (Let's Encrypt, Cloudflare).",
    });
  else
    push({
      id: "bad-ssl",
      title: "Невалидный SSL",
      desc: "Браузеры показывают предупреждение о сертификате.",
      severity: "high",
      weight: 20,
      recommendation: "Обновите сертификат или проверьте цепочку.",
    });

  if (ssl.hasSSL && ssl.supportsOldTls) {
    score -= 10;
    push({
      id: "old-tls",
      title: "Устаревший TLS",
      desc: "Сервер поддерживает TLS 1.0 или 1.1, которые уязвимы к атакам.",
      severity: "medium",
      weight: 10,
      recommendation:
        "Отключите TLS 1.0 и 1.1 на сервере, оставьте только 1.2 и 1.3.",
    });
  }

  if (hasSSL && daysLeft !== null && daysLeft > 30) score += 5;
  else if (hasSSL && daysLeft !== null && daysLeft <= 30)
    push({
      id: "ssl-expiring",
      title: "SSL истекает скоро",
      desc: `Сертификат истекает через ${daysLeft} дн.`,
      severity: "medium",
      weight: 5,
      recommendation: "Настройте автопродление сертификата.",
    });

  if (h.error) {
    push({
      id: "headers-unavailable",
      title: "Не удалось проверить заголовки",
      desc: "Сервер не ответил на HTTP-запрос. Часть проверок не выполнена.",
      severity: "medium",
      weight: 0,
      recommendation: "Повторите скан позже.",
    });
  } else {
    if (h.hsts && hasSSL) score += 15;
    else if (hasSSL)
      push({
        id: "no-hsts",
        title: "Нет HSTS",
        desc: "Не включён Strict-Transport-Security — риск downgrade-атаки после первого визита.",
        severity: "medium",
        weight: 15,
        recommendation: "Добавьте Strict-Transport-Security: max-age=31536000.",
      });

    if (h.csp) score += 15;
    else
      push({
        id: "no-csp",
        title: "Нет CSP",
        desc: "Отсутствие Content-Security-Policy снижает защиту от XSS.",
        severity: "high",
        weight: 15,
        recommendation: "Добавьте CSP с ограничением script-src.",
      });

    if (h.xframe) score += 10;
    else
      push({
        id: "no-xframe",
        title: "Нет X-Frame-Options",
        desc: "Страницу можно встроить во фрейм — риск кликджекинга.",
        severity: "medium",
        weight: 10,
        recommendation: "Добавьте X-Frame-Options: DENY.",
      });

    if (h.xcontent) score += 10;
    else
      push({
        id: "no-xcontent",
        title: "Нет X-Content-Type-Options",
        desc: "Браузер может интерпретировать файлы неверно.",
        severity: "medium",
        weight: 10,
        recommendation: "Добавьте X-Content-Type-Options: nosniff.",
      });

    // ИСПРАВЛЕНИЕ: не считаем раскрытием строку "не указан"
    if (h.server && h.server !== "не указан")
      push({
        id: "server-exposed",
        title: "Раскрыт Server",
        desc: "Заголовок раскрывает ПО и версию.",
        severity: "low",
        weight: 5,
        recommendation: "Скройте Server через конфиг nginx/apache.",
      });
    else score += 5;
  }

  if (riskyPorts.length === 0) score += 15;
  else
    riskyPorts.forEach((p) =>
      push({
        id: `port-${p.port}`,
        title: `Открыт опасный порт ${p.port}`,
        desc: `Порт ${p.port} доступен из интернета.`,
        severity: "high",
        weight: 15,
        recommendation: `Закройте ${p.port} файрволом или ACL.`,
      }),
    );

  if (!ports.some((p) => p.port === 8080)) score += 5;
  else
    push({
      id: "port-8080",
      title: "Открыт порт 8080",
      desc: "Может использоваться для админки.",
      severity: "medium",
      weight: 5,
      recommendation: "Закройте 8080 или ограничьте по IP.",
    });

  if (h.error) score = Math.min(score, 60);
  if (!ssl.hasSSL) score = Math.min(score, 30);
  else if (!ssl.valid) score = Math.min(score, 40);
  if (has3306) score = Math.min(score, 70);
  if (ssl.supportsOldTls) score = Math.min(score, 85);

  score = Math.max(0, Math.min(100, score));

  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else if (score >= 20) grade = "E";

  findings.sort((a, b) => b.weight - a.weight);
  return { score, grade, findings };
}

module.exports = { calculateScore };
