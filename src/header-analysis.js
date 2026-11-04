// Разбор Set-Cookie и эвристики для WAF/CMS.
// Все функции чистые: без сети, I/O и глобального состояния.

const SAME_SITE_VALUES = new Set(["lax", "strict", "none"]);
const CLOUDFLARE_COOKIES = ["cf_clearance", "__cf_bm", "__cfduid"];

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

// Ищет <meta ... content="Drupal"> без требования конкретного name.
function hasMetaContent(html, value) {
  const pattern = new RegExp(
    `<meta\\b[^>]*\\bcontent\\s*=\\s*["']?${escapeRegExp(value)}\\b`,
    "i",
  );
  return pattern.test(html);
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
    const name = (equals === -1 ? pair : pair.slice(0, equals)).trim();
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
        cookie.sameSite = true;
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
        cookie.sameSiteValue = SAME_SITE_VALUES.has(normalized)
          ? normalized
          : null;
      }
    }

    cookies.push(cookie);
  }

  return cookies;
}

// Сводка по флагам: сколько cookie имеют каждый флаг и сколько его лишены.
function summarizeCookies(cookies) {
  const list = Array.isArray(cookies) ? cookies : [];
  let secure = 0;
  let httpOnly = 0;
  let sameSite = 0;

  for (const cookie of list) {
    if (!cookie || typeof cookie !== "object") continue;
    if (cookie.secure) secure += 1;
    if (cookie.httpOnly) httpOnly += 1;
    if (cookie.sameSite) sameSite += 1;
  }

  const total = list.length;
  return {
    total,
    secure,
    httpOnly,
    sameSite,
    missingSecure: total - secure,
    missingHttpOnly: total - httpOnly,
    missingSameSite: total - sameSite,
  };
}

// Наличие security-заголовков и точное значение ACAO "*".
// Значения не интерпретируются, только trim и проверка на пустоту.
function analyzeSecurityHeaders(headers) {
  const accessControlAllowOrigin = headerValue(
    headers,
    "access-control-allow-origin",
  );

  return {
    referrerPolicy: headerValue(headers, "referrer-policy") !== null,
    permissionsPolicy: headerValue(headers, "permissions-policy") !== null,
    coop: headerValue(headers, "cross-origin-opener-policy") !== null,
    corsWildcard: accessControlAllowOrigin === "*",
    accessControlAllowOrigin,
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
  if (hasMetaContent(html, "drupal")) drupal.push("body:meta-generator");
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
  if (hasMetaContent(html, "joomla")) joomla.push("body:meta-generator");
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
};
