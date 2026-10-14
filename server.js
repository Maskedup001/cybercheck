const express = require('express');
const cors = require('cors');
const { checkPort, checkSSL, checkHeaders } = require('./checks');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Cooldown: не больше 1 скана в 10 сек с одного IP (защита от DDoS)
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

// Блокировка внутренних IP (SSRF protection).
// В DEMO_MODE=true localhost разрешён — для демонстрации
function isPrivateHost(host) {
  if (!host) return true;

  const DEMO_MODE = process.env.DEMO_MODE === 'true';

  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    return !DEMO_MODE;
  }

  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^127\./,
    /^0\./,
    /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./
  ];

  return privateRanges.some((regex) => regex.test(host));
}

// Основной эндпоинт сканирования
app.post('/api/scan', async (req, res) => {
  const ip = req.ip;

  const wait = checkCooldown(ip);
  if (wait > 0) {
    return res.status(429).json({
      error: `Подожди ${wait} сек. перед следующим сканом`
    });
  }

  const { url, consent, consentTimestamp } = req.body;

  // Логируем запросы — для отладки и аудита
  console.log(`[${new Date().toISOString()}] Сканирование: ${url || 'пусто'} | IP: ${ip}`);

  if (!consent) {
    return res.status(400).json({
      error: 'Подтверди, что у тебя есть право на проверку'
    });
  }

  // Согласие действует 5 минут — чтобы нельзя было поставить галочку один раз и повторять
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

  // Разрешаем домены, localhost и IP-адреса
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

    // Ищем веб-порт по приоритету: 443 → 80 → 8080 → 3000
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
    console.log('[DEMO_MODE] localhost разрешён для сканирования');
  }
});