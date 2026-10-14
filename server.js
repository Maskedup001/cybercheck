const express = require('express');
const cors = require('cors');
const { checkPort, checkSSL, checkHeaders } = require('./checks');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Ограничение: не больше 1 скана в 10 секунд с одного IP
const lastScan = new Map();
const COOLDOWN_MS = 10_000;

function checkCooldown(ip) {
  const now = Date.now();
  const last = lastScan.get(ip) || 0;
  if (now - last < COOLDOWN_MS) {
    return Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
  }
  lastScan.set(ip, now);
  return 0;
}

// Блокировка внутренних IP (SSRF protection)
function isPrivateHost(host) {
  if (!host) return true;

  // В демо-режиме localhost разрешён
  const DEMO_MODE = process.env.DEMO_MODE === 'true';

  // localhost и его вариации
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    return !DEMO_MODE; // в демо — разрешено, в продакшене — нет
  }

  // Приватные IPv4-диапазоны
  const privateRanges = [
    /^10\./,                                            // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[01])\./,                    // 172.16.0.0/12
    /^192\.168\./,                                      // 192.168.0.0/16
    /^169\.254\./,                                      // link-local
    /^127\./,                                           // loopback
    /^0\./,                                             // 0.0.0.0/8
    /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./    // CGNAT
  ];

  return privateRanges.some((regex) => regex.test(host));
}

// Основной эндпоинт
app.post('/api/scan', async (req, res) => {
  const ip = req.ip;

  const wait = checkCooldown(ip);
  if (wait > 0) {
    return res.status(429).json({
      error: `Подожди ${wait} сек. перед следующим сканом`
    });
  }

  const { url, consent, consentTimestamp } = req.body;

  // Логирование запроса
  console.log(`[${new Date().toISOString()}] Запрос на сканирование: ${url || 'пусто'} | IP: ${ip}`);

  if (!consent) {
    return res.status(400).json({
      error: 'Подтверди, что у тебя есть право на проверку'
    });
  }

  // Проверка свежести согласия (не старше 5 минут)
  const CONSENT_MAX_AGE = 5 * 60 * 1000;
  if (!consentTimestamp || Date.now() - consentTimestamp > CONSENT_MAX_AGE) {
    return res.status(400).json({
      error: 'Подтверждение устарело, обнови страницу'
    });
  }

  if (!url) {
    return res.status(400).json({ error: 'URL не указан' });
  }

  // Чистим URL от http:// и путей
  let host = url
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .trim()
    .toLowerCase();

  // Разрешаем: обычные домены (example.com) + localhost + IP-адреса
  const hostRegex = /^(localhost|([a-z0-9-]+\.)+[a-z]{2,}|(\d{1,3}\.){3}\d{1,3})$/;
  if (!hostRegex.test(host)) {
    return res.status(400).json({ error: 'Некорректный адрес' });
  }

  // Блокируем внутренние адреса
  if (isPrivateHost(host)) {
    return res.status(400).json({
      error: 'Сканирование внутренних адресов запрещено'
    });
  }

  try {
    const ports = await Promise.all(
      [80, 443, 22, 3306, 8080].map((p) => checkPort(host, p))
    );

    const openPorts = ports.filter((p) => p.status === 'open');

    // Ищем веб-порт: 443 → 80 → 8080 → 3000
    const webPort = [443, 80, 8080, 3000].find((p) =>
      openPorts.some((op) => op.port === p)
    );

    // Если веб-порт не найден — возвращаем заглушку
    if (!webPort) {
      return res.json({
        host,
        ports: openPorts,
        ssl: { hasSSL: false },
        headers: { error: true }
      });
    }

    const ssl = await checkSSL(host, webPort);
    const headers = await checkHeaders(host, webPort);

    res.json({
      host,
      ports: openPorts,
      ssl,
      headers
    });
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сканирования' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сканер запущен: http://localhost:${PORT}`);
  if (process.env.DEMO_MODE === 'true') {
    console.log('DEMO_MODE включён: localhost разрешён для сканирования');
  }
});