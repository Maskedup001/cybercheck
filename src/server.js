// Точка входа: читает окружение и поднимает HTTP-сервер. Вся логика — в
// src/core: config.js проверяет переменные, server.js собирает Express и
// запускает сканирование.
const { readConfig } = require("./core/config");
const { startServer } = require("./core/server");

startServer(readConfig());
