const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const path = require("node:path");

test("TRUST_PROXY=0 не роняет сервер", async () => {
  return new Promise((resolve, reject) => {
    const serverPath = path.join(__dirname, "../src/server.js");
    const child = spawn(process.execPath, [serverPath], {
      env: {
        ...process.env,
        TRUST_PROXY: "0",
        PUBLIC_ORIGIN: "http://localhost:3000",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let resolved = false;

    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });

    const timer = setTimeout(() => {
      if (resolved) return;
      resolved = true;
      if (stderr.includes("ОШИБКА")) {
        reject(new Error(`Сервер выдал ошибку: ${stderr}`));
      } else if (!stdout.includes("Сканер запущен")) {
        reject(
          new Error(`Сервер не запустился: stdout=${stdout}, stderr=${stderr}`),
        );
      } else {
        child.kill();
        resolve();
      }
    }, 1500);

    child.on("exit", (code) => {
      if (resolved) return;
      clearTimeout(timer);
      if (code === 1) {
        resolved = true;
        reject(new Error(`Сервер упал с кодом 1: ${stderr}`));
      }
    });
  });
});
