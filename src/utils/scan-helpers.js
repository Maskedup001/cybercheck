// Чистые вспомогательные функции HTTP-слоя: их можно тестировать без сети
// и без запуска сервера.

const net = require("node:net");
const ipaddr = require("ipaddr.js");
const { calculateScore } = require("../scoring");
const { CRITICAL_FILE_PATHS } = require("../core/file-paths");

// Схема должна стоять в начале адреса. Поиск "://" в любом месте ломал
// валидный ввод вида "example.com/?next=https://x": он уходил в new URL без
// схемы и получал 400.
const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

// Порядок, в котором перебираются веб-порты: сначала HTTPS, потом HTTP,
// потом альтернативный HTTP.
const WEB_PORT_ORDER = [443, 80, 8080];

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

// URL.hostname для IPv6 приходит в квадратных скобках ([::1]), а net.isIP,
// DNS-проверки и отчёт ждут «голый» адрес. Скобки нужны только в Host/SNI,
// поэтому нормализация живёт здесь, а не в каждом потребителе.
function normalizeHostname(raw) {
  if (typeof raw !== "string") return "";

  return raw
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[([^\]]+)\]$/, "$1");
}

// Host для HTTP-запроса: у IPv6 обязательны скобки, у нестандартного порта —
// суффикс :port. Одна функция на все пробы, чтобы заголовки не разъехались.
function hostHeaderFor(hostname, port) {
  const host = net.isIP(hostname) === 6 ? `[${hostname}]` : hostname;
  return port === 80 || port === 443 ? host : `${host}:${port}`;
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

// Сколько миллисекунд осталось до абсолютного дедлайна. Infinity означает
// «дедлайна нет» — так функции проверок можно вызывать по одной, без скана.
function budgetLeft(deadline, now = Date.now()) {
  if (!Number.isFinite(deadline)) return Infinity;
  return Math.max(0, deadline - now);
}

// Остаток бюджета, но не больше запрошенного таймаута. 0 значит «времени
// не осталось»: вызывающий обязан не начинать работу, а не ждать 0 мс.
function timeoutFor(ms, deadline, now = Date.now()) {
  const requested = Number.isFinite(ms) && ms > 0 ? ms : 0;
  const left = budgetLeft(deadline, now);
  if (left === Infinity) return requested;
  return Math.max(0, Math.min(requested, left));
}

// Хватает ли остатка на действие длительностью neededMs.
function hasBudget(deadline, neededMs, now = Date.now()) {
  return budgetLeft(deadline, now) >= Math.max(0, neededMs);
}

// Личный дедлайн этапа: он не может выйти ни за свой таймаут, ни за общий
// дедлайн скана. Все попытки внутри этапа (ретраи, проверка старых TLS)
// делят этот бюджет, поэтому «timeout этапа» — это действительно этап,
// а не одна попытка.
function stageDeadline(timeoutMs, deadline, now = Date.now()) {
  const requested = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 1;
  const local = now + requested;
  return Number.isFinite(deadline) ? Math.min(deadline, local) : local;
}

// Остаток бюджета скана: этапы не должны выходить за общий дедлайн.
function clampTimeout(ms, deadline, now = Date.now()) {
  return timeoutFor(ms, deadline, now);
}

// Итоговое состояние TLS: источник истины — фактически полученные заголовки,
// а не checkSSL. На 443 checkHeaders пробует HTTPS даже при упавшем
// checkSSL, и протокол ответа точно описывает, как соединение установилось.
function effectiveHasTls({ headers, port, portTls }) {
  if (!headers || headers.error) {
    // Заголовки не сняты, но TLS-порт уже подтверждён хендшейком: пробы
    // должны идти по HTTPS, а не падать на 80/8080.
    return port !== 80 && Boolean(portTls);
  }
  if (headers.protocol === "HTTPS") return true;
  if (headers.protocol === "HTTP") return false;
  return port !== 80 && Boolean(portTls);
}

// Состояние 443, при котором TLS нельзя считать проверенным: таймаут/DROP
// (filtered) или локальный отказ/исчерпанный бюджет (closed). В обоих случаях
// порт не измерен, поэтому «SSL не настроен» — ложное утверждение.
function tlsUnknownPort(portResults) {
  if (!Array.isArray(portResults)) return false;
  const port443 = portResults.find((item) => item && item.port === 443);
  return Boolean(port443) && (port443.status === "filtered" || port443.status === "closed");
}

// Веб-порты, которые реально открыты, в порядке приоритета. Отдельная
// функция, потому что это решение оркестратора: его надо тестировать без
// сети и без Express. Порядок можно подменить (options в server.js): это
// тестовый шов, чтобы поднять зависшую цель на случайном порту, не занимая
// фиксированный 8080.
function selectWebPorts(openPorts, order = WEB_PORT_ORDER) {
  const open = new Set(
    (Array.isArray(openPorts) ? openPorts : [])
      .filter((item) => item && item.status === "open")
      .map((item) => item.port),
  );

  return order.filter((port) => open.has(port));
}

// Критические пути отдаются контрактом files.critical. Здесь же решается,
// что считать критичным: .DS_Store остаётся в exposed, но не в critical —
// это low-риск, а severity "high" — словарь находок.
function withCriticalFiles(files) {
  if (!files || typeof files !== "object") return files;

  const exposed = Array.isArray(files.exposed) ? files.exposed : [];

  return {
    ...files,
    critical: exposed
      .filter(
        (path) => typeof path === "string" && CRITICAL_FILE_PATHS.has(path),
      )
      .map((path) => ({ path, severity: "high" })),
  };
}

// Сборка ответа API: скоринг идёт по тем же данным, что видит клиент.
// extra — результаты DNS/файлов/security.txt/фингерпринта, без них карточки
// показывали бы проверки, которые не влияют на оценку.
function buildReport(host, ports, ssl, headers, extra = {}) {
  // Всё, что не является отдельным блоком отчёта (признак клоакинга,
  // подтверждённый редирект HTTP→HTTPS), уходит в скоринг как есть. Раньше
  // cloaking терялся здесь, и находка о разном ответе сканеру и браузеру
  // никогда не появлялась.
  const {
    dns = null,
    files = null,
    securityTxt = null,
    fingerprint = null,
    ...scoringInput
  } = extra;

  const filesReport = withCriticalFiles(files);
  const { score, grade, findings } = calculateScore({
    host,
    ports,
    ssl,
    headers,
    dns,
    files: filesReport,
    securityTxt,
    fingerprint,
    ...scoringInput,
  });

  return {
    host,
    ports,
    // Полный набор состояний портов нужен UI и тестам; в API это
    // дополнительное поле, старые клиенты его игнорируют.
    portChecks: Array.isArray(scoringInput.portChecks)
      ? scoringInput.portChecks
      : null,
    ssl,
    headers,
    dns,
    files: filesReport,
    securityTxt,
    fingerprint,
    score,
    grade,
    findings,
  };
}

// Запрос HTML-файла мимо pageHtml (например, /%69ndex.html или /./index.html)
// не должен отдавать шаблон с незаполненным __BASE_URL__ из статики.
function isHtmlRequestPath(rawPath) {
  if (typeof rawPath !== "string" || rawPath.length === 0) return false;

  // На Windows существуют NTFS Alternate Data Streams (ADS) и обратные слэши.
  // Файл index.html::$DATA отдается как index.html. Такие пути нельзя
  // отдавать через статику, чтобы не обойти проверку.
  if (rawPath.includes(":") || rawPath.includes("\\")) return true;

  let decoded = rawPath;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    // Оставляем строку как есть, если декодирование не удалось
  }

  if (decoded.includes(":") || decoded.includes("\u0000")) return true;

  return /\.html?$/i.test(decoded);
}

// Инвариант SSRF, общий для всех сетевых проверок: соединяться можно только
// с литеральным IP. Имя хоста (или пустая строка) увели бы сокет в
// собственный DNS-резолв Node и обошли бы проверку адреса.
function isLiteralIp(value) {
  return typeof value === "string" && net.isIP(value) !== 0;
}

module.exports = {
  parseTarget,
  normalizeHostname,
  hostHeaderFor,
  rateKey,
  budgetLeft,
  timeoutFor,
  hasBudget,
  stageDeadline,
  clampTimeout,
  effectiveHasTls,
  tlsUnknownPort,
  selectWebPorts,
  WEB_PORT_ORDER,
  withCriticalFiles,
  buildReport,
  isHtmlRequestPath,
  isLiteralIp,
};
