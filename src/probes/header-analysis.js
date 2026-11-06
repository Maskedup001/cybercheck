// Разбор Set-Cookie и эвристики для WAF/CMS.
// Все функции чистые: без сети, I/O и глобального состояния.

const SAME_SITE_VALUES = new Set(["lax", "strict", "none"]);
const CLOUDFLARE_COOKIES = ["cf_clearance", "__cf_bm", "__cfduid"];

// Значения заголовков, которые действительно включают защиту. Присутствие
// заголовка с небезопасным значением (HSTS: max-age=0, COOP: unsafe-none,
// Referrer-Policy: unsafe-url, XCTO: foo) защитой не считается — иначе сайт
// получал бы баллы за явно отключённую настройку.
const SAFE_REFERRER_POLICIES = new Set([
  "no-referrer",
  "no-referrer-when-downgrade",
  "same-origin",
  "origin",
  "strict-origin",
  "origin-when-cross-origin",
  "strict-origin-when-cross-origin",
]);
const SAFE_COOP = new Set(["same-origin", "same-origin-allow-popups"]);
const SAFE_XFRAME = new Set(["deny", "sameorigin"]);

// Максимальная длина недоверенного заголовка в отчёте (Server, issuer).
const MAX_HEADER_TEXT = 120;

// Убирает управляющие символы и bidi-переопределения: они позволяют визуально
// подменить текст карточки или PDF, хотя XSS при textContent невозможен.
function sanitizeHeaderText(value) {
  if (typeof value !== "string") return null;
  const cleaned = value
    // C0/C1, DEL
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    // bidi-марки/переопределения и zero-width
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (cleaned === "") return null;
  return cleaned.slice(0, MAX_HEADER_TEXT);
}

// Первое значение из списка: "deny, sameorigin" → "deny".
function firstToken(value) {
  if (typeof value !== "string") return "";
  return value.split(",")[0].trim().toLowerCase();
}

// max-age из Strict-Transport-Security. null, если параметра нет.
function hstsMaxAge(value) {
  const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?/i.exec(String(value));
  return match ? Number(match[1]) : null;
}

// Источники, которые не ограничивают, откуда берётся скрипт: wildcard,
// inline/eval и схемы без хоста (data:, blob:, http:, https: — последние
// разрешают любой сайт по этой схеме). `https://*` — тот же wildcard,
// только записанный иначе.
const PERMISSIVE_CSP_SOURCES = new Set([
  "*",
  "'unsafe-inline'",
  "'unsafe-eval'",
  "data:",
  "blob:",
  "http:",
  "https:",
]);
const ANY_HOST_SCHEME_RE = /^(?:https?:)?\/\/\*$/i;

function isPermissiveCspSource(source) {
  return PERMISSIVE_CSP_SOURCES.has(source) || ANY_HOST_SCHEME_RE.test(source);
}

// nonce/hash отключает 'unsafe-inline' по CSP3: браузер игнорирует его,
// если в директиве есть nonce или hash. Поэтому такая политика — рабочая,
// а не «слабая из-за unsafe-inline».
const NONCE_OR_HASH_RE = /^'(?:nonce|sha256|sha384|sha512)-/i;

// Какая директива реально управляет скриптами. script-src-elem перекрывает
// script-src, а script-src перекрывает default-src; проверять «любую
// хорошую» директиву нельзя: default-src 'self' + script-src * означает
// «скрипты откуда угодно».
const SCRIPT_DIRECTIVES = ["script-src-elem", "script-src", "default-src"];

// Первая (по CSP применяется первая) директива с таким именем.
function directiveSources(directives, name) {
  for (const directive of directives) {
    const parts = directive.split(/\s+/).filter(Boolean);
    if (parts.length === 0) continue;
    if (parts[0].toLowerCase() !== name) continue;
    return parts.slice(1).map((source) => source.toLowerCase());
  }
  return null;
}

// CSP считается рабочей, если эффективная директива ограничивает источники
// скриптов и не разрешает inline/eval. `script-src 'self' 'unsafe-inline'`
// защитой не считается: inline-скрипт — основной вектор XSS. Исключение —
// nonce/hash рядом с 'unsafe-inline': браузер его игнорирует.
function cspIsRestrictive(value) {
  if (typeof value !== "string" || value.trim() === "") return false;

  const directives = value
    .split(";")
    .map((directive) => directive.trim())
    .filter(Boolean);

  let sources = null;
  for (const name of SCRIPT_DIRECTIVES) {
    sources = directiveSources(directives, name);
    if (sources !== null) break;
  }
  if (sources === null || sources.length === 0) return false;

  // 'none' работает только в одиночку: по CSP3 рядом с другими источниками он
  // игнорируется, поэтому `script-src 'none' https:` разрешает любой https.
  const meaningful = sources.filter((source) => source !== "'none'");
  if (meaningful.length === 0) return true;

  const hasNonceOrHash = meaningful.some((source) =>
    NONCE_OR_HASH_RE.test(source),
  );
  const restrictsInline =
    hasNonceOrHash || !meaningful.includes("'unsafe-inline'");
  if (!restrictsInline) return false;

  // Список источников — объединение: одного `https:` или `data:` достаточно,
  // чтобы загрузить скрипт с любого сайта/из data-URL, даже если рядом стоит
  // 'self'. Поэтому «строгая» политика не должна содержать ни одного
  // permissive-источника. Исключение — 'unsafe-inline' рядом с nonce/hash:
  // браузер его игнорирует (CSP3).
  const hasPermissive = meaningful.some((source) => {
    if (source === "'unsafe-inline'" && hasNonceOrHash) return false;
    return isPermissiveCspSource(source);
  });

  return !hasPermissive;
}

// Permissions-Policy защищает, только если значение реально ограничивает
// API. `camera=*` и директива без значения разрешают всё, `camera=()` —
// запрещает, `camera=(self)` — сужает до своего origin.
function permissionsPolicyIsRestrictive(value) {
  if (typeof value !== "string" || value.trim() === "") return false;

  const directives = value
    .split(",")
    .map((directive) => directive.trim())
    .filter(Boolean);
  if (directives.length === 0) return false;

  return directives.some((directive) => {
    const separator = directive.indexOf("=");
    if (separator === -1) return false; // без allowlist — как "*"
    const allowlist = directive.slice(separator + 1).trim();
    if (!allowlist.startsWith("(") || !allowlist.endsWith(")")) return false;

    const inner = allowlist.slice(1, -1).trim();
    // Пустой allowlist camera=() запрещает API всем — это ограничение.
    if (inner === "") return true;

    // camera=(*) формально в скобках, но разрешает API любому origin.
    return !inner
      .split(/\s+/)
      .some((token) => token === "*" || token === '"*"');
  });
}

// Возвращает непустое значение заголовка или null.
// Node отдаёт set-cookie массивом, остальные заголовки — строкой;
// на всякий случай поддерживаем оба варианта.
function headerValue(headers, name) {
  if (!headers || typeof headers !== "object") return null;
  const raw = headers[name];
  if (raw === undefined || raw === null) return null;

  const text = Array.isArray(raw) ? raw.join(", ") : String(raw);
  const trimmed = text.trim();
  return trimmed === "" ? null : trimmed;
}

// Имена cookie в нижнем регистре — для сравнения без учёта регистра.
function cookieNameSet(cookies) {
  const names = new Set();
  if (!Array.isArray(cookies)) return names;

  for (const cookie of cookies) {
    if (cookie && typeof cookie.name === "string") {
      names.add(cookie.name.toLowerCase());
    }
  }
  return names;
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Ищет <meta ... name="generator" ... content="WordPress">.
// Порядок атрибутов может быть любым; версия после названия допускается.
function hasGeneratorMeta(html, value) {
  const escaped = escapeRegExp(value);
  const nameFirst = new RegExp(
    `<meta\\b[^>]*\\bname\\s*=\\s*["']?generator["']?[^>]*\\bcontent\\s*=\\s*["']?${escaped}\\b`,
    "i",
  );
  const contentFirst = new RegExp(
    `<meta\\b[^>]*\\bcontent\\s*=\\s*["']?${escaped}\\b[^>]*\\bname\\s*=\\s*["']?generator["']?`,
    "i",
  );
  return nameFirst.test(html) || contentFirst.test(html);
}

// Разбирает Set-Cookie. Значение cookie никогда не попадает в результат:
// нужны только имя и флаги. Одна запись массива — один cookie.
function parseSetCookie(value) {
  let entries;
  if (Array.isArray(value)) {
    entries = [];
    for (const item of value) {
      if (typeof item !== "string") continue;
      entries.push(...item.split(/\r?\n/));
    }
  } else if (typeof value === "string") {
    entries = value.split(/\r?\n/);
  } else {
    return [];
  }

  const cookies = [];
  for (const entry of entries) {
    const raw = entry.trim();
    if (!raw) continue;

    // Простой split по ";" допустим для этого шага. Значение (в том числе
    // кавычки и ";" внутри него) не разбираем и наружу не отдаём.
    const parts = raw.split(";");
    const pair = parts[0];
    const equals = pair.indexOf("=");
    // Запись без "=" — не cookie, а мусор от прокси/WAF: имя не определено,
    // и любой токен в такой строке мог бы оказаться значением. Молча
    // пропускаем, чтобы «значения cookie не отдаются» оставалось правдой.
    if (equals === -1) continue;

    const name = pair.slice(0, equals).trim();
    if (!name) continue;

    const cookie = {
      name,
      secure: false,
      httpOnly: false,
      sameSite: false,
      sameSiteValue: null,
    };

    for (let i = 1; i < parts.length; i += 1) {
      const attribute = parts[i].trim();
      if (!attribute) continue;

      const attributeEquals = attribute.indexOf("=");
      const key = (
        attributeEquals === -1
          ? attribute
          : attribute.slice(0, attributeEquals)
      )
        .trim()
        .toLowerCase();

      if (key === "secure") {
        cookie.secure = true;
        continue;
      }
      if (key === "httponly") {
        cookie.httpOnly = true;
        continue;
      }
      if (key === "samesite") {
        let attributeValue =
          attributeEquals === -1
            ? ""
            : attribute.slice(attributeEquals + 1).trim();
        // Допускаем кавычки: SameSite="Lax".
        if (
          attributeValue.length >= 2 &&
          (attributeValue[0] === '"' || attributeValue[0] === "'") &&
          attributeValue.endsWith(attributeValue[0])
        ) {
          attributeValue = attributeValue.slice(1, -1).trim();
        }
        const normalized = attributeValue.toLowerCase();
        // Только lax/strict/none. SameSite без значения или SameSite=Foo
        // браузеры не применяют — это не защита, и считать её флагом нельзя.
        if (SAME_SITE_VALUES.has(normalized)) {
          cookie.sameSite = true;
          cookie.sameSiteValue = normalized;
        }
      }
    }

    cookies.push(cookie);
  }

  return cookies;
}

// Сводка по флагам: сколько cookie имеют каждый флаг и сколько его лишены.
// insecureNone — SameSite=None без Secure: браузеры такое cookie отвергают.
function summarizeCookies(cookies) {
  const list = Array.isArray(cookies) ? cookies : [];
  let secure = 0;
  let httpOnly = 0;
  let sameSite = 0;
  let insecureNone = 0;

  for (const cookie of list) {
    if (!cookie || typeof cookie !== "object") continue;
    if (cookie.secure) secure += 1;
    if (cookie.httpOnly) httpOnly += 1;
    if (cookie.sameSite) sameSite += 1;
    if (cookie.sameSiteValue === "none" && !cookie.secure) insecureNone += 1;
  }

  const total = list.length;
  return {
    total,
    secure,
    httpOnly,
    sameSite,
    insecureNone,
    missingSecure: total - secure,
    missingHttpOnly: total - httpOnly,
    missingSameSite: total - sameSite,
  };
}

// Наличие security-заголовков, проверка их значений и точное значение ACAO "*".
// Каждый заголовок получает состояние:
//   missing — заголовка нет;
//   weak    — заголовок есть, но значение не включает защиту;
//   ok      — защита действительно включена.
// Булевы поля (csp/hsts/...) означают «защита работает»: так их читают
// scoring и UI, поэтому HSTS: max-age=0 больше не даёт баллов.
function analyzeSecurityHeaders(headers) {
  const accessControlAllowOrigin = headerValue(
    headers,
    "access-control-allow-origin",
  );

  const hstsValue = headerValue(headers, "strict-transport-security");
  let hstsState = "missing";
  if (hstsValue !== null) {
    const maxAge = hstsMaxAge(hstsValue);
    hstsState = maxAge !== null && maxAge > 0 ? "ok" : "weak";
  }

  const cspValue = headerValue(headers, "content-security-policy");
  let cspState = "missing";
  if (cspValue !== null) {
    cspState = cspIsRestrictive(cspValue) ? "ok" : "weak";
  }

  const xframeValue = headerValue(headers, "x-frame-options");
  let xframeState = "missing";
  if (xframeValue !== null) {
    xframeState = SAFE_XFRAME.has(firstToken(xframeValue)) ? "ok" : "weak";
  }

  const xcontentValue = headerValue(headers, "x-content-type-options");
  let xcontentState = "missing";
  if (xcontentValue !== null) {
    xcontentState = firstToken(xcontentValue) === "nosniff" ? "ok" : "weak";
  }

  const referrerValue = headerValue(headers, "referrer-policy");
  let referrerPolicyState = "missing";
  if (referrerValue !== null) {
    referrerPolicyState = SAFE_REFERRER_POLICIES.has(firstToken(referrerValue))
      ? "ok"
      : "weak";
  }

  const coopValue = headerValue(headers, "cross-origin-opener-policy");
  let coopState = "missing";
  if (coopValue !== null) {
    coopState = SAFE_COOP.has(firstToken(coopValue)) ? "ok" : "weak";
  }

  // Permissions-Policy: пустой заголовок бесполезен, но и непустой не
  // всегда защищает — `camera=*` разрешает API всем.
  const permissionsValue = headerValue(headers, "permissions-policy");
  let permissionsPolicyState = "missing";
  if (permissionsValue !== null) {
    permissionsPolicyState = permissionsPolicyIsRestrictive(permissionsValue)
      ? "ok"
      : "weak";
  }

  // ACAO — недоверенная строка, как Server: управляющие и bidi-символы
  // вырезаем до отдачи в API. corsWildcard считается по исходному значению,
  // поэтому "*" остаётся "*".
  const corsWildcard = accessControlAllowOrigin === "*";

  return {
    hsts: hstsState === "ok",
    hstsState,
    csp: cspState === "ok",
    cspState,
    xframe: xframeState === "ok",
    xframeState,
    xcontent: xcontentState === "ok",
    xcontentState,
    referrerPolicy: referrerPolicyState === "ok",
    referrerPolicyState,
    permissionsPolicy: permissionsPolicyState === "ok",
    permissionsPolicyState,
    coop: coopState === "ok",
    coopState,
    corsWildcard,
    accessControlAllowOrigin: sanitizeHeaderText(accessControlAllowOrigin),
  };
}

// Определяет WAF по заголовкам и cookie. В evidence попадают только имена.
function detectWaf(headers, cookies) {
  const cookieNames = cookieNameSet(cookies);
  const server = (headerValue(headers, "server") || "").toLowerCase();

  const cloudflare = [];
  if (server.includes("cloudflare")) cloudflare.push("server");
  for (const name of ["cf-ray", "cf-cache-status", "cf-request-id"]) {
    if (headerValue(headers, name) !== null) cloudflare.push(name);
  }
  for (const name of CLOUDFLARE_COOKIES) {
    if (cookieNames.has(name)) cloudflare.push(`cookie:${name}`);
  }
  if (cloudflare.length > 0) {
    return { name: "cloudflare", evidence: cloudflare };
  }

  const sucuri = [];
  if (headerValue(headers, "x-sucuri-id") !== null) {
    sucuri.push("x-sucuri-id");
  }
  if (server.includes("sucuri")) sucuri.push("server");
  if (sucuri.length > 0) {
    return { name: "sucuri", evidence: sucuri };
  }

  const akamai = [];
  if (headerValue(headers, "x-akamai-transformed") !== null) {
    akamai.push("x-akamai-transformed");
  }
  if (server.includes("akamai")) akamai.push("server");
  if (akamai.length > 0) {
    return { name: "akamai", evidence: akamai };
  }

  return { name: null, evidence: [] };
}

// Определяет CMS по cookie, body и отдельным заголовкам.
// Порядок проверок задаёт приоритет при совпадении нескольких признаков.
function detectCms(body, headers, cookies) {
  const html = typeof body === "string" ? body : "";
  const htmlLower = html.toLowerCase();
  const cookieNames = Array.from(cookieNameSet(cookies));

  const wordpress = [];
  if (cookieNames.some((name) => name.startsWith("wordpress_logged_in_"))) {
    wordpress.push("cookie:wordpress_logged_in_");
  } else if (cookieNames.some((name) => name.startsWith("wordpress_"))) {
    wordpress.push("cookie:wordpress_");
  }
  if (cookieNames.some((name) => name.startsWith("wp-settings-time-"))) {
    wordpress.push("cookie:wp-settings-time-");
  } else if (cookieNames.some((name) => name.startsWith("wp-settings-"))) {
    wordpress.push("cookie:wp-settings-");
  }
  if (htmlLower.includes("/wp-content/")) wordpress.push("body:wp-content");
  if (htmlLower.includes("wp-json")) wordpress.push("body:wp-json");
  if (hasGeneratorMeta(html, "wordpress")) {
    wordpress.push("body:meta-generator");
  }
  if (wordpress.length > 0) {
    return { name: "wordpress", evidence: wordpress };
  }

  const drupal = [];
  if (cookieNames.some((name) => name.startsWith("drupal"))) {
    drupal.push("cookie:drupal");
  }
  if (cookieNames.some((name) => name.startsWith("ssess"))) {
    drupal.push("cookie:ssess");
  }
  if (htmlLower.includes("sites/default/files")) {
    drupal.push("body:sites-default-files");
  }
  if (hasGeneratorMeta(html, "drupal")) drupal.push("body:meta-generator");
  const generator = headerValue(headers, "x-generator");
  if (generator && generator.toLowerCase().includes("drupal")) {
    drupal.push("header:x-generator");
  }
  if (drupal.length > 0) {
    return { name: "drupal", evidence: drupal };
  }

  const joomla = [];
  if (cookieNames.some((name) => name.startsWith("joomla"))) {
    joomla.push("cookie:joomla");
  }
  if (htmlLower.includes("/media/system/js/")) {
    joomla.push("body:media-system-js");
  }
  if (hasGeneratorMeta(html, "joomla")) joomla.push("body:meta-generator");
  if (joomla.length > 0) {
    return { name: "joomla", evidence: joomla };
  }

  const bitrix = [];
  if (cookieNames.some((name) => name.startsWith("bitrix"))) {
    bitrix.push("cookie:bitrix");
  }
  if (htmlLower.includes("/bitrix/")) bitrix.push("body:bitrix");
  if (bitrix.length > 0) {
    return { name: "bitrix", evidence: bitrix };
  }

  return { name: null, evidence: [] };
}

module.exports = {
  parseSetCookie,
  summarizeCookies,
  analyzeSecurityHeaders,
  detectWaf,
  detectCms,
  sanitizeHeaderText,
};
