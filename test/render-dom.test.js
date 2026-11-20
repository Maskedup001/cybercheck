const test = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

// Вызовы HTML-синков, которые стенд увидел во время рендера. В норме список
// пуст: отчёт собирается только из createElement/textContent.
const sinkCalls = [];

// Минимальный DOM-узел: хранит атрибуты и детей, а все писатели HTML
// записывает в sinkCalls. Этого достаточно, чтобы render-result.js
// отработал целиком, не упрощая сам рендер.
class FakeNode {
  constructor(tag) {
    this.tagName = tag;
    this.nodeType = 1;
    this.children = [];
    this.attrs = {};
    this.dataset = {};
    this.className = "";
    this.hidden = false;
    this.id = "";
    this.type = "";
    this.listeners = [];
    this._text = "";
    this.style = {
      setProperty: (name, value) => {
        this.attrs[`style:${name}`] = String(value);
      },
    };
    this.classList = {
      add() {},
      remove() {},
      toggle() {},
      contains: () => false,
    };
  }

  set innerHTML(value) {
    sinkCalls.push(["innerHTML", String(value)]);
  }

  set outerHTML(value) {
    sinkCalls.push(["outerHTML", String(value)]);
  }

  set srcdoc(value) {
    sinkCalls.push(["srcdoc", String(value)]);
  }

  insertAdjacentHTML(position, value) {
    sinkCalls.push(["insertAdjacentHTML", String(value)]);
  }

  setAttribute(name, value) {
    this.attrs[name] = String(value);
    if (/^on/i.test(name)) sinkCalls.push([`attr:${name}`, String(value)]);
    if (
      /^(href|src|srcdoc)$/i.test(name) &&
      /^\s*javascript:/i.test(String(value))
    ) {
      sinkCalls.push([`url:${name}`, String(value)]);
    }
  }

  removeAttribute(name) {
    delete this.attrs[name];
  }

  hasAttribute(name) {
    return Object.hasOwn(this.attrs, name);
  }

  append(...nodes) {
    this.children.push(...nodes);
  }

  appendChild(node) {
    this.children.push(node);
    return node;
  }

  replaceChildren(...nodes) {
    this.children = nodes;
    this._text = "";
  }

  addEventListener(type, handler) {
    this.listeners.push({ type, handler });
  }

  focus() {}

  querySelector() {
    return null;
  }

  get textContent() {
    if (this._text) return this._text;
    return this.children
      .map((child) =>
        child && child.nodeType === 3 ? child.data : child.textContent,
      )
      .join("");
  }

  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }

  get lastElementChild() {
    return (
      [...this.children].reverse().find((child) => child && child.nodeType !== 3) ||
      null
    );
  }
}

test("renderResult: XSS-payload из отчёта остаётся текстом, HTML-синков нет", async () => {
  const payload = `<img src=x onerror=alert(1)>`;
  const stubNodes = new Map();
  const saved = { document: globalThis.document, window: globalThis.window };

  globalThis.document = {
    title: "CyberCheck",
    createElement: (tag) => new FakeNode(tag),
    createElementNS: (_namespace, tag) => new FakeNode(tag),
    createTextNode: (data) => ({ nodeType: 3, data: String(data) }),
    querySelector: (selector) => {
      if (!stubNodes.has(selector)) stubNodes.set(selector, new FakeNode("span"));
      return stubNodes.get(selector);
    },
  };
  globalThis.window = {
    addEventListener() {},
    requestAnimationFrame: () => 0,
    cancelAnimationFrame() {},
    // Сокращённое движение: gauge ставит конечное значение без анимации,
    // поэтому в тесте не остаётся висящих кадров.
    matchMedia: () => ({ matches: true }),
  };

  try {
    const { renderResult } = await import(
      pathToFileURL(
        path.join(__dirname, "../public/assets/js/ui/render-result.js"),
      ).href
    );

    const finding = {
      id: "xss",
      title: payload,
      desc: payload,
      severity: "high",
      weight: 1,
      // Префикс A03 проходит фильтр тега OWASP; сам payload попадает
      // в title-атрибут бейджа и должен остаться просто строкой.
      owasp: `A03:2021 ${payload}`,
      recommendation: payload,
    };

    const report = {
      host: payload,
      score: 40,
      grade: "D",
      ports: [{ port: 443, status: "open" }],
      headers: {
        error: false,
        server: payload,
        protocol: payload,
        csp: payload,
        cspState: "ok",
        xframe: payload,
        xframeState: "ok",
        hsts: payload,
        hstsState: "ok",
        xcontent: payload,
        xcontentState: "ok",
        referrerPolicy: payload,
        referrerPolicyState: "ok",
        permissionsPolicy: payload,
        permissionsPolicyState: "ok",
        coop: payload,
        coopState: "ok",
        corsWildcard: true,
        cookieSummary: {
          total: 1,
          secure: 1,
          httpOnly: 1,
          sameSite: 1,
          insecureNone: 0,
          missingSecure: 0,
          missingHttpOnly: 0,
          missingSameSite: 0,
        },
      },
      ssl: {
        hasSSL: true,
        valid: true,
        validToISO: "2030-01-01T00:00:00Z",
        issuer: payload,
        tlsVersion: payload,
        daysLeft: 10,
      },
      dns: {
        applicable: true,
        spf: { present: true },
        dmarc: { present: true, policy: "reject" },
        caa: { present: true, restrictive: true },
      },
      files: { exposed: [payload], critical: [{ path: payload }] },
      securityTxt: { present: true },
      fingerprint: {
        status: 200,
        waf: { name: payload },
        cms: { name: payload },
      },
      findings: [finding],
    };

    const container = new FakeNode("section");
    const body = new FakeNode("div");

    renderResult(container, body, report);

    assert.deepStrictEqual(sinkCalls, [], "рендер не должен трогать HTML-синки");
    assert.strictEqual(container.hidden, false, "renderResult должен показать отчёт");
    assert.ok(
      body.textContent.includes(payload),
      "payload должен попасть в текст как есть",
    );
    assert.ok(
      !JSON.stringify(body.attrs).includes("javascript:"),
      "javascript:-URL не должен стать атрибутом контейнера",
    );

    // Проверяем не только контейнер: любой узел дерева мог получить
    // href/src с javascript:-URL.
    const attributeDumps = [];
    const walk = (node) => {
      if (!node || node.nodeType === 3) return;
      attributeDumps.push(node.attrs);
      for (const child of node.children || []) walk(child);
    };
    walk(body);

    assert.ok(
      !JSON.stringify(attributeDumps).includes("javascript:"),
      "javascript:-URL не должен попасть ни в один атрибут",
    );
  } finally {
    if (saved.document === undefined) delete globalThis.document;
    else globalThis.document = saved.document;
    if (saved.window === undefined) delete globalThis.window;
    else globalThis.window = saved.window;
  }
});

async function renderReport(report) {
  const saved = { document: globalThis.document, window: globalThis.window };

  globalThis.document = {
    title: "CyberCheck",
    createElement: (tag) => new FakeNode(tag),
    createElementNS: (_namespace, tag) => new FakeNode(tag),
    createTextNode: (data) => ({ nodeType: 3, data: String(data) }),
    querySelector: () => new FakeNode("span"),
  };
  globalThis.window = {
    addEventListener() {},
    requestAnimationFrame: () => 0,
    cancelAnimationFrame() {},
    matchMedia: () => ({ matches: true }),
  };

  try {
    const { renderResult } = await import(
      pathToFileURL(
        path.join(__dirname, "../public/assets/js/ui/render-result.js"),
      ).href
    );

    const container = new FakeNode("section");
    const body = new FakeNode("div");
    renderResult(container, body, report);
    return { body, container };
  } finally {
    if (saved.document === undefined) delete globalThis.document;
    else globalThis.document = saved.document;
    if (saved.window === undefined) delete globalThis.window;
    else globalThis.window = saved.window;
  }
}

function allNodes(node, acc = []) {
  if (!node || node.nodeType === 3) return acc;
  acc.push(node);
  for (const child of node.children || []) allNodes(child, acc);
  return acc;
}

const baseReport = {
  host: "example.com",
  score: 100,
  grade: "A",
  ports: [],
  ssl: { hasSSL: false, error: "NO_WEB_PORT" },
  headers: { error: true },
  dns: { applicable: false },
  files: null,
  securityTxt: null,
  fingerprint: null,
  findings: [],
};

test("renderResult: критичная находка не даёт зелёный вердикт «Хорошая защита»", async () => {
  const { body } = await renderReport({
    ...baseReport,
    score: 90,
    grade: "B",
    ports: [{ port: 443, status: "open" }],
    ssl: { hasSSL: true, valid: true, daysLeft: 100 },
    headers: { error: false, status: 200 },
    findings: [
      {
        id: "exposed-env",
        title: "Открыт .env",
        severity: "high",
        weight: 7,
        recommendation: "Закройте .env.",
      },
    ],
  });

  assert.match(body.textContent, /Есть критичные замечания/);
  assert.ok(
    !body.textContent.includes("Хорошая защита"),
    "зелёный вердикт при критичной находке недопустим",
  );
  assert.ok(
    allNodes(body).some((node) => String(node.className).includes("score--warn")),
    "тон оценки должен стать предупреждающим",
  );
});

test("renderResult: устаревший TLS не подписан как «невалидный сертификат»", async () => {
  const { body } = await renderReport({
    ...baseReport,
    ports: [{ port: 443, status: "open" }],
    ssl: {
      hasSSL: true,
      valid: false,
      verifyError: null,
      tlsVersion: "TLSv1.0",
      daysLeft: 100,
      validToISO: "2030-01-01T00:00:00Z",
    },
    headers: { error: false, status: 200 },
  });

  assert.match(body.textContent, /устаревший TLS/);
  assert.match(body.textContent, /Протокол TLSv1\.0 ниже TLS 1\.2/);
  assert.ok(!body.textContent.includes("невалиден"));
});

test("renderResult: пустые порты при NO_WEB_PORT — «не проверены», файлы не дублируются", async () => {
  const { body } = await renderReport({
    ...baseReport,
    files: { exposed: ["/.env"], critical: [{ path: "/.env" }], results: [] },
  });

  assert.match(
    body.textContent,
    /Порты не проверены: пробы не ответили/,
  );

  const occurrences = body.textContent.split("/.env").length - 1;
  assert.strictEqual(occurrences, 1, "путь не должен дублироваться в подписи");
});

test("renderResult: HTTP 404 — заголовки оцениваются, 403 — «не проверено»", async () => {
  const okHeaders = {
    error: false,
    status: 404,
    protocol: "HTTPS",
    hsts: true,
    hstsState: "ok",
    csp: true,
    cspState: "ok",
    xframe: true,
    xframeState: "ok",
    xcontent: true,
    xcontentState: "ok",
    referrerPolicy: true,
    referrerPolicyState: "ok",
    permissionsPolicy: true,
    permissionsPolicyState: "ok",
    coop: true,
    coopState: "ok",
    corsWildcard: false,
    cookieSummary: { total: 0 },
  };

  const notFound = await renderReport({
    ...baseReport,
    ports: [{ port: 443, status: "open" }],
    ssl: { hasSSL: true, valid: true, daysLeft: 100 },
    headers: okHeaders,
  });
  assert.ok(!notFound.body.textContent.includes("Проверка не выполнялась"));

  const challenge = await renderReport({
    ...baseReport,
    ports: [{ port: 443, status: "open" }],
    ssl: { hasSSL: true, valid: true, daysLeft: 100 },
    headers: { ...okHeaders, status: 403 },
  });
  assert.match(challenge.body.textContent, /Проверка не выполнялась: корневой ответ HTTP 403/);
});

test("renderResult: HTTP 301 — карточка заголовков говорит «не проверено»", async () => {
  const saved = { document: globalThis.document, window: globalThis.window };

  globalThis.document = {
    title: "CyberCheck",
    createElement: (tag) => new FakeNode(tag),
    createElementNS: (_namespace, tag) => new FakeNode(tag),
    createTextNode: (data) => ({ nodeType: 3, data: String(data) }),
    querySelector: () => new FakeNode("span"),
  };
  globalThis.window = {
    addEventListener() {},
    requestAnimationFrame: () => 0,
    cancelAnimationFrame() {},
    matchMedia: () => ({ matches: true }),
  };

  try {
    const { renderResult } = await import(
      pathToFileURL(
        path.join(__dirname, "../public/assets/js/ui/render-result.js"),
      ).href
    );

    const report = {
      host: "example.com",
      score: 14,
      grade: "F",
      ports: [{ port: 80, status: "open" }],
      headers: {
        error: false,
        status: 301,
        location: "https://example.com/",
        protocol: "HTTP",
        server: "nginx",
      },
      ssl: { hasSSL: false, tlsChecked: false },
      dns: {
        applicable: true,
        spf: { present: true },
        dmarc: { present: true, policy: "reject" },
        caa: { present: true, restrictive: true },
      },
      files: { exposed: [], blocked: [], results: [] },
      securityTxt: { present: true },
      fingerprint: null,
      findings: [],
    };

    const container = new FakeNode("section");
    const body = new FakeNode("div");
    renderResult(container, body, report);

    assert.ok(
      body.textContent.includes(
        "Проверка не выполнялась: корневой ответ HTTP 301",
      ),
      "карточка заголовков должна объяснять, почему проверки нет",
    );
    assert.ok(
      !body.textContent.includes("CSP"),
      "при ответе 301 карточка не должна перечислять заголовки как проверенные",
    );
  } finally {
    if (saved.document === undefined) delete globalThis.document;
    else globalThis.document = saved.document;
    if (saved.window === undefined) delete globalThis.window;
    else globalThis.window = saved.window;
  }
});
