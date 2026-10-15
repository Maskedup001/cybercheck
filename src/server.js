const path = require('path');
const express = require('express');
const cors = require('cors');
const { checkPort, checkSSL, checkHeaders } = require('./checks');
const { resolvePublicIps } = require('./net-guard');

// DEMO_MODE — разрешает сканирование localhost (только для демо)
const DEMO_MODE = process.env.DEMO_MODE === 'true';

// Запрет DEMO_MODE в production
if (DEMO_MODE && process.env.NODE_ENV === 'production') {
  console.error('ОШИБКА: DEMO_MODE запрещён в production');
  process.exit(1);
}

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Cooldown: не больше 1 скана в 10 сек с одного IP
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

  console.log(`[${new Date().toISOString()}] Сканирование: ${url || 'пусто'} | IP: ${ip}`);

  if (!consent) {
    return res.status(400).json({
      error: 'Подтверди, что у тебя есть право на проверку'
    });
  }

  // Согласие действует 5 минут
  const CONSENT_MAX_AGE = 5 * 60 * 1000;
  if (!consentTimestamp || Date.now() - consentTimestamp > CONSENT_MAX_AGE) {
    return res.status(400).json({
      error: 'Подтверждение устарело, обнови страницу'
    });
  }

  if (!url) {
    return res.status(400).json({ error: 'URL не указан' });
  }

  // Чистим URL
  const hostname = url
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .trim()
    .toLowerCase();

  const hostRegex = /^(localhost|([a-z0-9-]+\.)+[a-z]{2,}|(\d{1,3}\.){3}\d{1,3})$/;
  if (!hostRegex.test(hostname)) {
    return res.status(400).json({ error: 'Некорректный адрес' });
  }

  // ============ SSRF-ЗАЩИТА ============
  let connectIp;

  if (DEMO_MODE && (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1')) {
    // Демо-режим: разрешаем localhost
    connectIp = hostname;
  } else {
    // Резолвим DNS и проверяем ВСЕ полученные IP на публичность
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
  // ====================================

  try {
    const ports = await Promise.all(
      [80, 443, 22, 3306, 8080].map((p) => checkPort(connectIp, p))
    );

    const openPorts = ports.filter((p) => p.status === 'open');

    // Ищем веб-порт: 443 → 80 → 8080
    const webPort = [443, 80, 8080].find((p) =>
      openPorts.some((op) => op.port === p)
    );

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