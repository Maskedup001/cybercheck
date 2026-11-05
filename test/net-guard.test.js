const test = require("node:test");
const assert = require("node:assert");
const { isPublicIp, resolvePublicIps } = require("../src/net-guard");

const blocked = [
  "0.0.0.0",
  "10.0.0.1",
  "100.64.0.1",
  "127.0.0.1",
  "169.254.169.254",
  "172.16.0.1",
  "192.168.1.1",
  "198.18.0.1",
  "224.0.0.1",
  "::1",
  "::",
  "fc00::1",
  "fe80::1",
  "::ffff:127.0.0.1",
  "::ffff:10.0.0.1",
	"::ffff:7f00:1",        // hex-форма 127.0.0.1
  "::127.0.0.1",          // IPv4-compatible
  "64:ff9b::7f00:1",       // NAT64 -> 127.0.0.1
	"::7f00:1",
  "::a9fe:a9fe"
];

const allowed = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"];

test("Блокирует приватные и служебные адреса", () => {
  for (const ip of blocked) {
    assert.strictEqual(
      isPublicIp(ip),
      false,
      `ОШИБКА: должен блокировать ${ip}`,
    );
  }
});

test("Разрешает публичные адреса", () => {
  for (const ip of allowed) {
    assert.strictEqual(isPublicIp(ip), true, `ОШИБКА: должен разрешать ${ip}`);
  }
});

test("Fail-closed: невалидный ввод блокируется", () => {
  const invalid = ["", "not-an-ip", "999.999.999.999", null, undefined];
  for (const ip of invalid) {
    assert.strictEqual(
      isPublicIp(ip),
      false,
      `ОШИБКА: должен блокировать ${ip}`,
    );
  }
});

// --- Резолв через c-ares (resolve4/resolve6), с инъекцией -------------

function fakeResolver({ a = [], aaaa = [], aError = null, aaaaError = null } = {}) {
  return {
    calls: [],
    async resolve4(name) {
      this.calls.push({ type: "A", name });
      if (aError) throw aError;
      return a;
    },
    async resolve6(name) {
      this.calls.push({ type: "AAAA", name });
      if (aaaaError) throw aaaaError;
      return aaaa;
    },
  };
}

function dnsError(code) {
  const err = new Error(`query failed: ${code}`);
  err.code = code;
  return err;
}

test("resolvePublicIps: литеральный IP не требует DNS", async () => {
  const resolver = fakeResolver();

  assert.deepStrictEqual(
    await resolvePublicIps("8.8.8.8", { resolver }),
    ["8.8.8.8"],
  );
  assert.deepStrictEqual(await resolvePublicIps("10.0.0.1", { resolver }), []);
  assert.deepStrictEqual(resolver.calls, []);
});

test("resolvePublicIps: объединяет A/AAAA и ставит IPv4 вперёд", async () => {
  const resolver = fakeResolver({
    a: ["93.184.216.34", "1.1.1.1"],
    aaaa: ["2606:4700::1111"],
  });

  const ips = await resolvePublicIps("example.com", { resolver });

  assert.deepStrictEqual(ips, ["93.184.216.34", "1.1.1.1", "2606:4700::1111"]);
  assert.deepStrictEqual(
    resolver.calls.map((call) => call.type),
    ["A", "AAAA"],
  );
});

test("resolvePublicIps: приватный адрес в наборе блокирует весь домен", async () => {
  const resolver = fakeResolver({ a: ["93.184.216.34", "127.0.0.1"] });

  assert.deepStrictEqual(await resolvePublicIps("example.com", { resolver }), []);
});

test("resolvePublicIps: обе записи отсутствуют → пустой список", async () => {
  const resolver = fakeResolver({
    aError: dnsError("ENODATA"),
    aaaaError: dnsError("ENOTFOUND"),
  });

  assert.deepStrictEqual(await resolvePublicIps("example.com", { resolver }), []);
});

test("resolvePublicIps: реальная ошибка DNS пробрасывается", async () => {
  const resolver = fakeResolver({
    aError: dnsError("ESERVFAIL"),
    aaaaError: dnsError("ESERVFAIL"),
  });

  await assert.rejects(
    () => resolvePublicIps("example.com", { resolver }),
    /query failed/,
  );
});

test("resolvePublicIps: зависший резолвер обрывается по таймауту", async () => {
  const never = () => new Promise(() => {});
  const resolver = { resolve4: never, resolve6: never };

  await assert.rejects(
    () => resolvePublicIps("example.com", { resolver, timeoutMs: 20 }),
    (err) => err.code === "ETIMEOUT",
  );
});
