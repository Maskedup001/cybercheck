# CyberCheck

Учебный проект — сканер безопасности веб-сайтов (МЭИ, Проектная деятельность).

## Что проверяет

- Открытые порты (80, 443, 22, 3306, 8080)
- SSL-сертификат (валидность, срок действия, издатель)
- HTTP-заголовки безопасности (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)
- Версию веб-сервера

## Стек

- Node.js + Express (бэкенд)
- Vanilla JavaScript + CSS (фронтенд)
- GitHub Actions (CI)

## Запуск

```bash
npm install
npm start
```

Открыть: http://localhost:3000

## Демо

Введи адрес тестового сайта (например, `demo.testfire.net`) или своего.

⚠️ Сканируй только свои или авторизованные ресурсы.

## Disclaimer

См. [DISCLAIMER.md](./DISCLAIMER.md).

## License

MIT
