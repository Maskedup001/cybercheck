const dns = require("node:dns").promises;
const net = require("node:net");
const ipaddr = require("ipaddr.js");

// Проверяет, является ли IP-адрес публичным.
function isPublicIp(ip) {
  if (!ip) return false;

  let addr;
  try {
    addr = ipaddr.parse(ip);
  } catch {
    return false; // fail closed (если не смогли распарсить — блокируем)
  }

  // 1. Разворачиваем IPv4-mapped IPv6 любой формы (::ffff:7f00:1 -> 127.0.0.1)
  if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress()) {
    addr = addr.toIPv4Address();
  }

  // 2. Проверяем NAT64 (64:ff9b::/96)
  if (addr.kind() === "ipv6" && addr.match(ipaddr.parse("64:ff9b::"), 96)) {
    const ipv4 = new ipaddr.IPv4([
      addr.parts[6] >> 8, addr.parts[6] & 0xff,
      addr.parts[7] >> 8, addr.parts[7] & 0xff
    ]);
    return isPublicIp(ipv4.toString());
  }

  // 3. Проверяем диапазон. range() вернёт 'unicast' только для реальных публичных адресов.
  // Всё остальное (private, loopback, linkLocal, uniqueLocal, carrierGradeNat) отсекается.
  return addr.range() === "unicast";
}

// Резолвит hostname в список IP-адресов и проверяет, что ВСЕ они публичные.
async function resolvePublicIps(hostname) {
  if (net.isIP(hostname)) {
    return isPublicIp(hostname) ? [hostname] : [];
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  const ips = records.map((r) => r.address);

  if (ips.length === 0) return [];
  if (!ips.every(isPublicIp)) return [];

  // IPv4 вперёд — меньше проблем с VPN и старыми сетями
  const sorted = ips.sort((a, b) => {
    const aIsV4 = net.isIPv4(a) ? 1 : 0;
    const bIsV4 = net.isIPv4(b) ? 1 : 0;
    return bIsV4 - aIsV4;
  });

  return sorted;
}

module.exports = { isPublicIp, resolvePublicIps };