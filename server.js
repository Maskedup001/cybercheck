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

  // Простая валидация домена
  const hostRegex = /^[a-z0-9.-]+\.[a-z]{2,}$/;
  if (!hostRegex.test(host)) {
    return res.status(400).json({ error: 'Некорректный адрес' });
  }

  try {
    const ports = await Promise.all(
      [80, 443, 22, 3306, 8080].map((p) => checkPort(host, p))
    );
    const ssl = await checkSSL(host);
    const headers = await checkHeaders(host);

    res.json({
      host,
      ports: ports.filter((p) => p.status === 'open'),
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