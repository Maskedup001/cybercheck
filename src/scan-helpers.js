// Чистые вспомогательные функции HTTP-слоя: их можно тестировать без сети
// и без запуска сервера.

const net = require("node:net");
const ipaddr = require("ipaddr.js");

// Схема должна стоять в начале адреса. Поиск "://" в любом месте ломал
// валидный ввод вида "example.com/?next=https://x": он уходил в new URL без
// схемы и получал 400.
const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

// Разбирает ввод пользователя в URL. Возвращает null, если адрес невалиден
// или схема не http(s).
function parseTarget(raw) {
  if (typeof raw !== "string") return null;

  const value = raw.trim();
  if (value.length === 0) return null;

  let parsed;
  try {
    parsed = new URL(SCHEME_RE.test(value) ? value : `http://${value}`);
  } catch {
    return null;
  }

  if (!["http:", "https:"].includes(parsed.protocol)) return null;
  return parsed;
}

// Ключ rate-limit: канонический IPv4 или /64 для IPv6.
// Без канонизации "2001:db8::1" и "2001:0db8:0:0::1" давали разные ключи
// для одной и той же сети, а IPv4-mapped схлопывался в "::/64".
function rateKey(ip) {
  if (typeof ip !== "string") return "unknown";

  const value = ip.trim();
  if (value.length === 0) return "unknown";

  let addr;
  try {
    addr = ipaddr.parse(value);
  } catch {
    return "unknown"; // невалидный IP не создаёт свой бакет
  }

  if (addr.kind() === "ipv6" && addr.isIPv4MappedAddress()) {
    addr = addr.toIPv4Address();
  }

  if (addr.kind() === "ipv4") return addr.toString();

  // IPv6: первые 4 hextet — это /64. Приводим к нижнему регистру без
  // ведущих нулей, чтобы текстовые варианты одного адреса совпадали.
  const prefix = addr.parts
    .slice(0, 4)
    .map((part) => part.toString(16))
    .join(":");

  return `${prefix}::/64`;
}

// Остаток бюджета скана: этапы не должны выходить за общий дедлайн.
function clampTimeout(ms, deadline, now = Date.now()) {
  const budget = deadline - now;
  if (!Number.isFinite(budget)) return Math.max(0, ms);
  return Math.max(0, Math.min(ms, budget));
}

// Итоговое состояние TLS: источник истины — фактически полученные заголовки,
// а не checkSSL. На 443 checkHeaders пробует HTTPS даже при упавшем
// checkSSL, и протокол ответа точно описывает, как соединение установилось.
function effectiveHasTls({ headers, port, portTls }) {
  if (!headers || headers.error) return false;
  if (headers.protocol === "HTTPS") return true;
  if (headers.protocol === "HTTP") return false;
  return port !== 80 && Boolean(portTls);
}

// Запрос HTML-файла мимо pageHtml (например, /%69ndex.html или /./index.html)
// не должен отдавать шаблон с незаполненным __BASE_URL__ из статики.
function isHtmlRequestPath(rawPath) {
  if (typeof rawPath !== "string" || rawPath.length === 0) return false;

  let decoded = rawPath;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    // Битая percent-последовательность: проверяем как есть.
  }

  return /\.html?$/i.test(decoded);
}

module.exports = {
  parseTarget,
  rateKey,
  clampTimeout,
  effectiveHasTls,
  isHtmlRequestPath,
};
