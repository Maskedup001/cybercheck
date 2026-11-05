const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const path = require("node:path");

test("TRUST_PROXY=0 не роняет сервер", async (t) => {
  const child = spawn(process.execPath, [path.join(__dirname, "../src/server.js")], {
    env: {
      ...process.env,
      TRUST_PROXY: "0",
      PUBLIC_ORIGIN: "http://localhost:3000",
      PORT: "0", // не конфликтуем с портом 3000
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  t.after(() => child.kill());

  let stdout = "";
  let stderr = "";

  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  // Ждём именно строку запуска: раньше тест всегда висел 5 секунд, даже
  // когда сервер поднимался за двести миллисекунд.
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new Error(`Сервер не запустился за 10 с: stdout=${stdout}, stderr=${stderr}`),
      );
    }, 10_000);

    const finish = (error) => {
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.includes("Сканер запущен")) finish();
    });

    child.on("exit", (code) => {
      if (code === 1) {
        finish(new Error(`Сервер упал с кодом 1: ${stderr}`));
      }
    });
  });

  assert.match(stdout, /Сканер запущен/);
  assert.strictEqual(stderr.includes("ОШИБКА"), false, stderr);
});
