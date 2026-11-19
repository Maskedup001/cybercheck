// Окружение тестов не должно зависеть от оболочки/CI.
//
// src/core/server.js читает NODE_ENV на загрузке модуля и в production без
// CONSENT_SECRET завершает процесс ещё до регистрации тестов. Поэтому оба
// раннера подключают этот файл до тестовых файлов: `npm test` (через
// scripts/run-tests.js) и `npm run test:isolated` (через --require).
process.env.NODE_ENV = "test";
process.env.CONSENT_SECRET ||= "test-consent-secret";
