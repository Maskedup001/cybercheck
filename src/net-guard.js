const dns = require("node:dns").promises;
const net = require("node:net");
const ipaddr = require("ipaddr.js");

const DEFAULT_DNS_TIMEOUT_MS = 5000;

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
      addr.parts[6] >> 8,
      addr.parts[6] & 0xff,
      addr.parts[7] >> 8,
      addr.parts[7] & 0xff,
    ]);
    return isPublicIp(ipv4.toString());
  }

  // 3. Блокируем IPv4-compatible (::/96) - устаревший класс
  if (addr.kind() === "ipv6" && addr.match(ipaddr.parse("::"), 96)) {
    return false;
  }

  // 4. Проверяем диапазон. range() вернёт 'unicast' только для реальных публичных адресов.
  // Всё остальное (private, loopback, linkLocal, uniqueLocal, carrierGradeNat) отсекается.
  return addr.range() === "unicast";
}

// Ограничивает DNS-запрос по времени. Важно: используется c-ares
// (dns.resolve4/resolve6), а не dns.lookup: getaddrinfo выполняется в
// libuv-threadpool из 4 потоков, и четыре медленных имени блокировали бы
// остальные резолвы всего процесса.
function withTimeout(promise, ms) {
  if (!Number.isFinite(ms) || ms < 0) return promise;

  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error("DNS_TIMEOUT");
      err.code = "ETIMEOUT";
      reject(err);
    }, ms);
  });

  return Promise.race([promise, timeout]).finally(() => {
    clearTimeout(timer);
  });
}

function isMissingRecordError(error) {
  const code = error && typeof error === "object" ? error.code : null;
  return code === "ENODATA" || code === "ENOTFOUND";
}

// Один DNS-запрос: результат или ошибка, без исключений наружу.
async function queryAddresses(run, timeoutMs) {
  try {
    const value = await withTimeout(Promise.resolve().then(run), timeoutMs);
    const ips = Array.isArray(value)
      ? value.filter((item) => typeof item === "string" && item.length > 0)
      : [];
    return { ips, error: null };
  } catch (error) {
    return { ips: [], error };
  }
}

// Резолвит A и AAAA параллельно. Возвращает объединённый список без повторов.
// Если обе записи отсутствуют — пустой массив; если обе попытки упали по
// реальной причине — пробрасываем ошибку, чтобы сервер вернул DNS-ошибку,
// а не «приватный адрес».
async function resolveAddresses(hostname, resolver, timeoutMs) {
  const [ipv4, ipv6] = await Promise.all([
    queryAddresses(() => resolver.resolve4(hostname), timeoutMs),
    queryAddresses(() => resolver.resolve6(hostname), timeoutMs),
  ]);

  const ips = [...ipv4.ips, ...ipv6.ips];

  if (ips.length === 0) {
    const error = ipv4.error || ipv6.error;
    if (error && !isMissingRecordError(error)) throw error;
    return [];
  }

  return Array.from(new Set(ips));
}

// Резолвит hostname в список IP-адресов и проверяет, что ВСЕ они публичные.
// options.resolver — точка инъекции для тестов; options.timeoutMs — бюджет.
async function resolvePublicIps(hostname, options = {}) {
  if (net.isIP(hostname)) {
    return isPublicIp(hostname) ? [hostname] : [];
  }

  const resolver = options.resolver || dns;
  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? Math.max(0, options.timeoutMs)
    : DEFAULT_DNS_TIMEOUT_MS;

  const ips = await resolveAddresses(hostname, resolver, timeoutMs);

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
