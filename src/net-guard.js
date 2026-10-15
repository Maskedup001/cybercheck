const dns = require('node:dns').promises;
const net = require('node:net');

/**
 * Проверяет, является ли IP публичным (не внутренним).
 * Блокирует: private, loopback, link-local, CGNAT, multicast, reserved, ULA.
 */
function isPublicIp(ip) {
  if (!ip) return false;

  // IPv4-mapped IPv6 (::ffff:x.x.x.x)
  const v4Match = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4Match) {
    return isPublicIp(v4Match[1]);
  }

  // IPv4
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b, c] = parts;

    if (a === 0) return false;                          // 0.0.0.0/8
    if (a === 10) return false;                         // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return false; // 100.64.0.0/10 CGNAT
    if (a === 127) return false;                        // loopback
    if (a === 169 && b === 254) return false;           // link-local
    if (a === 172 && b >= 16 && b <= 31) return false;  // 172.16.0.0/12
    if (a === 192 && b === 0 && c === 0) return false;  // 192.0.0.0/24
    if (a === 192 && b === 0 && c === 2) return false;  // TEST-NET-1
    if (a === 192 && b === 88 && c === 99) return false;
    if (a === 192 && b === 168) return false;           // 192.168.0.0/16
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    if (a >= 224 && a <= 239) return false;             // multicast
    if (a >= 240) return false;                         // reserved + broadcast

    return true;
  }

  // IPv6
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();

    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return false;
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return false;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return false; // ULA
    if (/^fe[89ab]/.test(lower)) return false;                          // link-local
    if (lower.startsWith('ff')) return false;                           // multicast

    return true;
  }

  return false;
}

/**
 * Резолвит hostname в IP-адреса и проверяет, что все они публичные.
 * Возвращает массив публичных IP или пустой массив, если хотя бы один приватный.
 */
async function resolvePublicIps(hostname) {
  if (net.isIP(hostname)) {
    return isPublicIp(hostname) ? [hostname] : [];
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  const ips = records.map((r) => r.address);

  if (ips.length === 0) return [];
  if (!ips.every(isPublicIp)) return [];

  return ips;
}

module.exports = { isPublicIp, resolvePublicIps };