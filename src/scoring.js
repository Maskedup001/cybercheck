function calculateScore(report) {
  let score = 100;
  const findings = [];

  report.ports.forEach((p) => {
    if ([22, 3306].includes(p.port)) {
      score -= 20;
      findings.push({
        title: "Открыт опасный порт",
        desc: `Порт ${p.port} доступен из интернета.`,
        severity: "high",
      });
    }
    if (p.port === 8080) {
      score -= 10;
      findings.push({
        title: "Открыт альтернативный порт",
        desc: "Порт 8080 может использоваться для админок.",
        severity: "medium",
      });
    }
  });

  if (!report.ssl.hasSSL) {
    score -= 30;
    findings.push({
      title: "Нет SSL",
      desc: "Данные передаются открыто. Установите HTTPS.",
      severity: "high",
    });
  } else if (!report.ssl.valid) {
    score -= 20;
    findings.push({
      title: "Невалидный SSL",
      desc: "Браузеры блокируют ваш сайт.",
      severity: "high",
    });
  }

  if (!report.headers.error) {
    if (!report.headers.hsts) {
      score -= 10;
      findings.push({
        title: "Нет HSTS",
        desc: "Нет защиты от перехвата.",
        severity: "medium",
      });
    }
    if (!report.headers.csp) {
      score -= 10;
      findings.push({
        title: "Нет CSP",
        desc: "Сайт уязвим для XSS.",
        severity: "high",
      });
    }
    if (!report.headers.xframe) {
      score -= 5;
      findings.push({
        title: "Нет X-Frame-Options",
        desc: "Уязвим к кликджекингу.",
        severity: "medium",
      });
    }
  }

  score = Math.max(0, score);
  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else if (score >= 20) grade = "E";

  return { score, grade, findings };
}

module.exports = { calculateScore };
