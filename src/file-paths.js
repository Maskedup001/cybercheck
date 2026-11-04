// Единый источник путей для HEAD-проб и критических находок. Раньше списки
// дублировались в server.js, web-probes.js, scoring.js и в UI, и добавление
// пятого пути легко давало расхождение «UI одно — score другое».

// Порядок важен: он задаёт порядок в files.results и в отчёте.
const SENSITIVE_FILE_PATHS = [
  "/.env",
  "/.git/config",
  "/.DS_Store",
  "/backup.zip",
];

// Открытие этих путей — критическая находка (severity "high" в словаре
// находок). /.DS_Store остаётся low-риском и сюда не входит.
const CRITICAL_FILE_PATHS = new Set(["/.env", "/.git/config", "/backup.zip"]);

module.exports = { SENSITIVE_FILE_PATHS, CRITICAL_FILE_PATHS };
