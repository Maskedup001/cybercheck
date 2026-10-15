const path = require('path');
const express = require('express');
const cors = require('cors');
const { checkPort, checkSSL, checkHeaders } = require('./checks');
const { resolvePublicIps } = require('./net-guard');

// DEMO_MODE включает сканирование localhost — только для локальной демонстрации
const DEMO_MODE = process.env.DEMO_MODE === 'true';

// Защита от случайного включения DEMO_MODE в продакшене
if (DEMO_MODE && process.env.NODE_ENV === 'production') {
  console.error('ОШИБКА: DEMO_MODE запрещён в production');
  process.exit(1);
}

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Cooldown: не больше 1 скана в 10 секунд с одного IP.
// Защита от превращения сканера в DDoS-инструмент.
const lastScan = new Map();
const COOLDOWN_MS = 10_000;

// Очистка старых записей раз в 5 минут, чтобы карта не росла бесконечно
setInterval(() => {
  const now = Date.now();
  for (const [ip, time] of lastScan.entries()) {
    if (now - time > 60_000) lastScan.delete(ip);
  }
}, 5 * 60_000).unref();

// Возвращает число секунд ожидания, если cooldown ещё активен, иначе 0.
function checkCooldown(ip) {
  const now = Date.now();
  const last = lastScan.get(ip) || 0;
  if (now - last < COOLDOWN_MS) {
    return Math.ceil((COOLDOWN_MS - (now - last)) / 1000);
  }
  lastScan.set(ip, now);
  return 0;
}

// Основной эндпоинт сканирования
app.post('/api/scan', async (req, res) => {
  const ip = req.ip;

  // Проверка cooldown до всех остальных проверок
  const wait = checkCooldown(ip);
  if (wait > 0) {
    return res.status(429).json({
      error: `Подожди ${wait} сек. перед следующим сканом`
    });
  }

  const { url, consent, consentTimestamp } = req.body;

  // Логирование запроса (URL + IP клиента)
  console.log(`[${new Date().toISOString()}] Сканирование: ${url || 'пусто'} | IP: ${ip}`);

  // Проверка согласия на сканирование
  if (!consent) {
    return res.status(400).json({
      error: 'Подтверди, что у тебя есть право на проверку'
    });
  }

  // Согласие действует 5 минут — чтобы нельзя было поставить галочку один раз и сканировать часами
  const CONSENT_MAX_AGE = 5 * 60 * 1000;
  if (!consentTimestamp || Date.now() - consentTimestamp > CONSENT_MAX_AGE) {
    return res.status(400).json({
      error: 'Подтверждение устарело, обнови страницу'
    });
  }

  if (!url) {
    return res.status(400).json({ error: 'URL не указан' });
  }

  // Чистим URL: убираем схему (http://) и путь (/page)
  const hostname = url
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .trim()
    .toLowerCase();

  // Валидация формата: localhost, домен, или IPv4-адрес
  const hostRegex = /^(localhost|([a-z0-9-]+\.)+[a-z]{2,}|(\d{1,3}\.){3}\d{1,3})$/;
  if (!hostRegex.test(hostname)) {
    return res.status(400).json({ error: 'Некорректный адрес' });
  }

  // ===== SSRF-ЗАЩИТА =====
  // Резолвим DNS и проверяем, что все полученные IP публичные.
  // Сканируем по IP (не по hostname) — это защита от DNS rebinding,
  // когда между проверкой и подключением домен может сменить адрес.
  let connectIp;

  if (DEMO_MODE && (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1')) {
    // Демо-режим: localhost разрешён для показа на тестовом стенде
    connectIp = hostname;
  } else {
    let resolvedIps;
    try {
      resolvedIps = await resolvePublicIps(hostname);
    } catch (e) {
      return res.status(400).json({ error: 'Не удалось разрешить адрес' });
    }

    if (resolvedIps.length === 0) {
      return res.status(400).json({
        error: 'Сканирование внутренних адресов запрещено'
      });
    }

    connectIp = resolvedIps[0];
  }
  // ========================

  try {
    // Проверяем все порты параллельно
    const ports = await Promise.all(
      [80, 443, 22, 3306, 8080].map((p) => checkPort(connectIp, p))
    );

    const openPorts = ports.filter((p) => p.status === 'open');

    // Ищем веб-порт по приоритету: 443 → 80 → 8080
    const webPort = [443, 80, 8080].find((p) =>
      openPorts.some((op) => op.port === p)
    );

    // Если веб-порт не найден — SSL и заголовки проверить негде
    if (!webPort) {
      return res.json({
        host: hostname,
        ports: openPorts,
        ssl: { hasSSL: false },
        headers: { error: true }
      });
    }

    const ssl = await checkSSL(connectIp, webPort, hostname);
    const headers = await checkHeaders(connectIp, webPort, hostname);

    res.json({
      host: hostname,
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
  if (DEMO_MODE) {
    console.log('[DEMO_MODE] localhost разрешён для сканирования');
  }
});