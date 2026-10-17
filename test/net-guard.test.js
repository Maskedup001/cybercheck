const test = require("node:test");
const assert = require("node:assert");
const { isPublicIp } = require("../src/net-guard");

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
