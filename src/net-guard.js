const dns = require('node:dns').promises;
const net = require('node:net');

// Проверяет, является ли IP-адрес публичным.
// Возвращает false для: private (10/8, 172.16/12, 192.168/16),
// loopback (127/8, ::1), link-local (169.254/16, fe80::/10),
// CGNAT (100.64/10), multicast, reserved, ULA (fc00::/7).
// Возвращает true только для адресов, которые реально маршрутизируются в интернете.
function isPublicIp(ip) {
  if (!ip) return false;

  // IPv4-mapped IPv6 (::ffff:x.x.x.x) — разворачиваем в IPv4 и проверяем заново
  const v4Match = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4Match) return isPublicIp(v4Match[1]);

  // ===== IPv4 =====
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);

    if (a === 0) return false;                          // 0.0.0.0/8 — "this network"
    if (a === 10) return false;                         // 10.0.0.0/8 — приватная сеть
    if (a === 100 && b >= 64 && b <= 127) return false; // 100.64.0.0/10 — CGNAT провайдеров
    if (a === 127) return false;                        // 127.0.0.0/8 — loopback
    if (a === 169 && b === 254) return false;           // 169.254.0.0/16 — link-local (в т.ч. cloud metadata 169.254.169.254)
    if (a === 172 && b >= 16 && b <= 31) return false;  // 172.16.0.0/12 — приватная сеть
    if (a === 192 && b === 0 && c === 0) return false;  // 192.0.0.0/24 — IETF protocol assignments
    if (a === 192 && b === 0 && c === 2) return false;  // 192.0.2.0/24 — TEST-NET-1 (документация)
    if (a === 192 && b === 88 && c === 99) return false;// 192.88.99.0/24 — deprecated 6to4 relay
    if (a === 192 && b === 168) return false;           // 192.168.0.0/16 — домашняя сеть
    if (a === 198 && (b === 18 || b === 19)) return false; // 198.18.0.0/15 — benchmarking
    if (a === 198 && b === 51 && c === 100) return false;  // 198.51.100.0/24 — TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return false;   // 203.0.113.0/24 — TEST-NET-3
    if (a >= 224 && a <= 239) return false;             // 224.0.0.0/4 — multicast
    if (a >= 240) return false;                         // 240.0.0.0/4 — reserved + broadcast

    return true;
  }

  // ===== IPv6 =====
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();

    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return false; // loopback
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return false;  // unspecified
    if (lower.startsWith('fc') || lower.startsWith('fd')) return false; // fc00::/7 — ULA (аналог приватных)
    if (/^fe[89ab]/.test(lower)) return false;                          // fe80::/10 — link-local
    if (lower.startsWith('ff')) return false;                           // ff00::/8 — multicast

    return true;
  }

  return false;
}

// Резолвит hostname в список IP-адресов и проверяет, что ВСЕ они публичные.
// Если хотя бы один IP приватный — возвращает пустой массив (полный отказ).
// Это защита от DNS rebinding: домен может вернуть и публичный, и приватный адрес.
async function resolvePublicIps(hostname) {
  // Если уже передан IP-литерал — просто проверяем его
  if (net.isIP(hostname)) {
    return isPublicIp(hostname) ? [hostname] : [];
  }

  // Резолвим домен во все IP (all: true) в порядке приоритета DNS (verbatim: true)
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  const ips = records.map((r) => r.address);

  if (ips.length === 0) return [];
  if (!ips.every(isPublicIp)) return [];

  return ips;
}

module.exports = { isPublicIp, resolvePublicIps };