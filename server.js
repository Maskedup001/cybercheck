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

// Основной эндпоинт
app.post('/api/scan', async (req, res) => {
  const ip = req.ip;

  const wait = checkCooldown(ip);
  if (wait > 0) {
    return res.status(429).json({
      error: `Подожди ${wait} сек. перед следующим сканом`
    });
  }

  const { url, consent } = req.body;

  // Логирование запроса
  console.log(`[${new Date().toISOString()}] Запрос на сканирование: ${url || 'пусто'} | IP: ${ip}`);

  if (!consent) {
    return res.status(400).json({
      error: 'Подтверди, что у тебя есть право на проверку'
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

  try {
    const ports = await Promise.all(
      [80, 443, 22, 3306, 8080].map((p) => checkPort(host, p))
    );

    const openPorts = ports.filter((p) => p.status === 'open');

    // Ищем веб-порт: 443 → 80 → 8080 → 3000
    const webPort = [443, 80, 8080, 3000].find((p) =>
      openPorts.some((op) => op.port === p)
    );

    // Если веб-порт не найден — возвращаем заглушку без проверок SSL и заголовков
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
});