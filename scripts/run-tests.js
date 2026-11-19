// Запуск тестов в одном процессе.
//
// `node --test` для каждого файла поднимает дочерний процесс. В средах, где
// создание процессов запрещено (контейнеры с урезанными capabilities, CI-
// песочницы, Windows AppContainer), это даёт `spawn EPERM` и весь набор падает,
// хотя сами тесты рабочие. Здесь файлы просто подключаются по очереди: node:test
// регистрирует тесты и запускает их после загрузки, код тестов тот же самый.
//
// Изоляция между файлами в таком режиме слабее — если нужен классический
// прогон с отдельным процессом на файл, используйте `npm run test:isolated`.

const fs = require("node:fs");
const path = require("node:path");

// Тестовое окружение выставляется до загрузки тестовых файлов: они требуют
// src/core/server.js, который в production без CONSENT_SECRET завершает
// процесс на этапе require.
require(path.join(__dirname, "..", "test", "setup-env.js"));

const testDir = path.join(__dirname, "..", "test");

const files = fs
  .readdirSync(testDir)
  .filter((name) => name.endsWith(".test.js"))
  .sort();

if (files.length === 0) {
  console.error("Не найдено ни одного файла тестов в", testDir);
  process.exit(1);
}

for (const name of files) {
  console.log(`# Файл: test/${name}`);
  require(path.join(testDir, name));
}
