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
