# CyberCheck

> ⚠️ **ВНИМАНИЕ!** Инструмент предназначен только для тестирования собственных систем или систем, на которые у вас есть официальное письменное разрешение. Несанкционированное сканирование чужих доменов может быть нарушением закона (**ст. 272 УК РФ**). Автор не несёт ответственности за использование инструмента третьими лицами.

---

CyberCheck — сканер внешней безопасности веб-сайта. Проверяет доступность пяти портов, TLS-сертификат, четыре HTTP-заголовка безопасности и превращает результат в **Risk Score** (0–100, A–F) со списком находок и рекомендаций. Написан на Node.js + Express, фронтенд — vanilla JS без сборки.

Документация: [архитектура и модель угроз](docs/architecture.md) · [политика безопасности](.github/SECURITY.md) · [DISCLAIMER](DISCLAIMER.md).

## Что проверяет

| Группа | Проверка | Как |
|---|---|---|
| Порты | 80, 443, 22, 3306, 8080 | TCP-connect, 3 с на порт, параллельно |
| TLS | наличие TLS, валидность цепочки, срок действия, издатель | `tls.connect` с `rejectUnauthorized: false` (сертификат читается, но не принимается на веру) |
| Заголовки | `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` | `GET /` по HTTPS, при ошибке — по HTTP; тело не скачивается |
| Гигиена | `Server`, фактический протокол (HTTP/HTTPS) | те же заголовки ответа |
| Оценка | Risk Score 0–100, буква A–F, находки с приоритетом и рекомендацией | `src/scoring.js`, чистая функция |

Сканируется только корень сайта: путь и нестандартный порт из введённого URL игнорируются. Редиректы не разворачиваются (см. «Ограничения»).

## Risk Score

Оценка считается на сервере в `src/scoring.js` и приходит в ответе полями `score`, `grade`, `findings`.

**Веса (сумма — 100):**

| Фактор | Баллы |
|---|---|
| Валидный TLS-сертификат | 20 |
| До истечения сертификата больше 30 дней | 5 |
| `Strict-Transport-Security` | 15 |
| `Content-Security-Policy` | 15 |
| `X-Frame-Options` | 10 |
| `X-Content-Type-Options` | 10 |
| Заголовок `Server` не раскрыт | 5 |
| Нет открытых портов 22 и 3306 | 15 |
| Порт 8080 закрыт | 5 |

**Жёсткие потолки** — они важнее суммы весов и не дают «набрать» A из второстепенных факторов:

| Условие | Максимум |
|---|---|
| Не удалось проверить заголовки (`headers.error`) | 60 (фактически ≤ 45: баллы за заголовки не начисляются) |
| HTTPS отсутствует | 30 |
| Сертификат невалиден/просрочен | 40 |
| Открыт порт 3306 | 70 |

**Буквы:** A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F < 20.

**Находка (`findings[]`)** — объект с полями `id`, `title`, `desc`, `severity` (`high` / `medium` / `low`), `weight` и `recommendation`. Находки сортируются по весу; `severity` управляет цветом в интерфейсе. Тексты сформулированы как «снижает защиту», а не «сайт уязвим»: оценка — эвристика, а не заключение об уязвимости.

Оценка детерминирована: одинаковый вход даёт одинаковый выход, сеть внутри `scoring.js` не используется. Контракт и тесты описаны в [архитектуре](docs/architecture.md).

## Стек

- Node.js 22–24 + Express 4
- Vanilla JavaScript (ES-модули) + CSS без сборщика
- `node:test` + GitHub Actions

## Быстрый старт

Требуется Node.js 22–24.

```bash
npm ci
PUBLIC_ORIGIN=http://localhost:3000 npm start
```

```powershell
# Windows PowerShell
npm ci
$env:PUBLIC_ORIGIN="http://localhost:3000"; npm start
```

Открыть: http://localhost:3000

> Переменная `PUBLIC_ORIGIN` **обязательна вне Render**. Она задаёт единственный origin, которому разрешены CORS-запросы к API. Без неё (и без `RENDER_EXTERNAL_URL`) сервер завершается с кодом 1 — это защита от случайного открытия API всем доменам.

### Переменные окружения

Шаблон — в [`.env.example`](.env.example). Файл `.env` **не подгружается автоматически**: переменные задаются перед командой запуска или через `node --env-file=.env src/server.js` (Node 20.6+).

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PORT` | `3000` | Порт HTTP-сервера |
| `PUBLIC_ORIGIN` | — | Origin фронтенда для CORS (например, `https://cybercheck.example`). Имеет приоритет над `RENDER_EXTERNAL_URL`; из значения берётся только `origin` |
| `RENDER_EXTERNAL_URL` | — | Подставляется Render автоматически для веб-сервисов; используется как fallback, если `PUBLIC_ORIGIN` не задан. Вручную задавать не нужно |
| `TRUST_PROXY` | `0` | Число доверенных прокси. `1` — на Render. Включать только если приложение недоступно напрямую: при `> 0` адрес клиента берётся из `X-Forwarded-For` |
| `DEMO_MODE` | `false` | Разрешает сканировать `localhost` и `127.0.0.1`. Только при `NODE_ENV=development`, иначе процесс завершается |
| `NODE_ENV` | — | `development` или `production`; влияет на `DEMO_MODE` и текст 404 |

Корректность `PUBLIC_ORIGIN` проверяется на старте: значение парсится как URL и должно иметь схему `http:` или `https:`. Из URL берётся только `origin` — путь и завершающий слэш отбрасываются.

### Режим демонстрации

Для локального стенда нужны две переменные:

```bash
PUBLIC_ORIGIN=http://localhost:3000 DEMO_MODE=true NODE_ENV=development npm start
```

`DEMO_MODE` без явного `NODE_ENV=development` останавливает сервер: ошибка конфигурации не открывает доступ к внутренней сети, а закрывает сервис (fail-closed). В продакшене демо-режим не включается.

## API

Один API-маршрут. Аутентификации нет — ограничение по IP-адресу.

```http
POST /api/scan
Content-Type: application/json

{
  "url": "example.com",
  "consent": true,
  "consentTimestamp": 1761600000000
}
```

`consentTimestamp` — миллисекунды; принимается окно от 15 минут в прошлом до 1 минуты в будущем (запас на дрейф часов). `consent` должен быть строго `true`.

Успешный ответ:

```json
{
  "host": "example.com",
  "ports": [{ "port": 443, "status": "open" }],
  "ssl": {
    "hasSSL": true,
    "valid": true,
    "verifyError": null,
    "daysLeft": 74,
    "validTo": "Jan  9 12:00:00 2027 GMT",
    "validToISO": "2027-01-09T12:00:00.000Z",
    "issuer": "Let's Encrypt"
  },
  "headers": {
    "protocol": "HTTPS",
    "server": "nginx",
    "csp": true,
    "xframe": true,
    "hsts": true,
    "xcontent": true
  },
  "score": 95,
  "grade": "A",
  "findings": [
    {
      "id": "server-exposed",
      "title": "Раскрыт Server",
      "desc": "Заголовок раскрывает ПО и версию.",
      "severity": "low",
      "weight": 5,
      "recommendation": "Скройте Server через конфиг nginx/apache."
    }
  ]
}
```

Ошибки — всегда JSON `{ "error": "..." }` без стека и внутренних деталей:

| Код | Когда |
|---|---|
| 400 | невалидный `url`, нет согласия, устаревший timestamp, приватный/неразрешимый адрес |
| 413 | тело больше 8 КБ |
| 429 | повторный скан с того же IP раньше чем через 10 секунд (заголовок `Retry-After` не выставляется) |
| 500 | непредвиденная ошибка; подробности только в серверном логе |

`GET /healthz` → `{ "ok": true, "uptime": 12.34 }` — для health-check хостинга.

## Тестирование

```bash
npm test
```

Запускается `node --test test/*.test.js` — 12 тестов в двух файлах:

- `test/net-guard.test.js` — 3 теста: 20 приватных/служебных адресов блокируются, 4 публичных разрешаются, мусорный ввод блокируется (fail-closed). Покрыты IPv4-mapped, IPv4-compatible, NAT64 и `::/96`.
- `test/scoring.test.js` — 9 тестов: «всё хорошо» → A; нет CSP → не A; нет HSTS → не A; нет XCTO → ≤ 90; просроченный сертификат → ≤ 40 (D/F); нет HTTPS → ≤ 30; `headers.error` → ≤ 60 и находка; открытый 3306 → ≤ 70; `server: "не указан"` не считается раскрытием (100/A, находки `server-exposed` нет).

Не покрыто: HTTP-слой (`server.js` вызывает `exit`/`listen` при импорте, поэтому не импортируется), `resolvePublicIps` (внутри `dns.lookup`), `rateKey`, рендер отчёта. Как это закрыть — в [архитектуре](docs/architecture.md).

CI (`.github/workflows/ci.yml`) на каждый push и PR: `npm ci` → `npm audit --audit-level=high` → проверка загрузки `checks.js` → `node --check src/server.js` → `npm test` → запуск сервера и smoke-проверка `/`.

## Деплой на Render

### Вариант 1. Blueprint (рекомендуется)

В репозитории есть [`render.yaml`](render.yaml): web-сервис, план `starter`, `npm ci` / `npm start`, health-check `/healthz`, `NODE_ENV=production`, `TRUST_PROXY=1`.

1. Render → **New** → **Blueprint** → выбрать репозиторий.
2. Render читает `render.yaml` и создаёт сервис. `PUBLIC_ORIGIN` в blueprint не задан намеренно: Render сам передаёт `RENDER_EXTERNAL_URL` (например, `https://cybercheck.onrender.com`), и `server.js` использует её как fallback.
3. После первого деплоя проверить `/healthz` и один скан.

Это zero-config-путь: вводить переменные вручную не нужно. Если переменная `PUBLIC_ORIGIN` всё же задана, она имеет приоритет над `RENDER_EXTERNAL_URL`.

> **Свой домен.** `RENDER_EXTERNAL_URL` — это всегда `*.onrender.com`. Если вы привязали кастомный домен, браузер будет отправлять `Origin: https://ваш-домен`, а CORS разрешает только onrender-адрес → API вернёт ошибку CORS. В этом случае **обязательно** задайте `PUBLIC_ORIGIN=https://ваш-домен` в панели Render (Environment) и сделайте redeploy. Один сервис поддерживает один origin.

### Вариант 2. Вручную через дашборд

- Build: `npm ci`, Start: `npm start`
- Env: `NODE_ENV=production`, `PUBLIC_ORIGIN=https://<service>.onrender.com`, `TRUST_PROXY=1`
- Health Check Path: `/healthz`
- План: **Starter**. На плане Free инстанс засыпает, первый скан после простоя может занять 30–50 с; клиентский таймаут — 45 с, ретрая нет.
- Внешний rate-limit (Cloudflare / Render WAF) обязателен для публичного запуска: встроенный лимит живёт в памяти процесса.

### Проверка после деплоя

```bash
curl -s https://<service>.onrender.com/healthz
curl -s -o /dev/null -w "%{http_code}\n" https://<service>.onrender.com/
curl -s -X POST https://<service>.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"example.com","consent":true,"consentTimestamp":1761600000000}'
```

## Структура проекта

```
cybercheck/
├── .github/
│   ├── workflows/
│   │   └── ci.yml                  # CI: install → audit → syntax → test → smoke
│   └── SECURITY.md                 # Политика безопасности (вкладка Security)
├── docs/
│   └── architecture.md             # Архитектура, контракт скоринга, модель угроз
├── public/                         # Клиентская часть (статика)
│   ├── index.html                  # Страница сканера
│   ├── legal.html                  # Пользовательское соглашение
│   ├── favicon.svg
│   ├── robots.txt
│   └── assets/
│       ├── css/
│       │   ├── main.css            # @import-точка входа
│       │   ├── tokens.css          # дизайн-токены (цвета, отступы, шрифты)
│       │   ├── reset.css
│       │   ├── base.css
│       │   ├── layout.css
│       │   ├── utilities.css
│       │   ├── print.css           # печатная версия отчёта (A4)
│       │   └── components/
│       │       ├── button.css
│       │       ├── consent.css
│       │       ├── scan-form.css
│       │       └── result.css      # отчёт, оценка, findings
│       ├── js/
│       │   ├── app.js              # контроллер формы и состояния
│       │   ├── api.js              # fetch + AbortController (45 с) + нормализация
│       │   └── render-result.js    # рендер отчёта только через DOM API/textContent
│       └── screenshots/
│           └── og-cover.png        # OG-обложка
├── src/                            # Серверная часть
│   ├── server.js                   # Express, конфиг, валидация, лимит, сборка ответа
│   ├── checks.js                   # порты, TLS, HTTP-заголовки
│   ├── scoring.js                  # Risk Score и findings (чистая функция)
│   └── net-guard.js                # SSRF-защита: isPublicIp, resolvePublicIps
├── test/
│   ├── net-guard.test.js           # 3 теста SSRF-классификации
│   └── scoring.test.js             # 9 тестов калибровки скоринга
├── .env.example                    # Шаблон переменных окружения
├── .gitignore
├── package.json
├── package-lock.json
├── render.yaml                     # Blueprint для Render
├── README.md
├── DISCLAIMER.md                   # Юридические предупреждения
└── LICENSE                         # MIT
```

> `node_modules/` создаётся после `npm install` и в репозиторий не попадает.
>
> `SECURITY.md` лежит в `.github/` — именно оттуда GitHub показывает его на вкладке **Security**. При переносе в другую папку вкладка исчезнет.

## Безопасность

- **SSRF-защита** — DNS-резолв, проверка **всех** полученных адресов на публичность (`ipaddr.js`, разрешён только `unicast`), подключение **по проверенному IP**, без повторного резолва. Блокируются loopback, private, link-local, CGNAT, multicast, ULA, 6to4, Teredo, NAT64, IPv4-mapped и IPv4-compatible `::/96`. Смешанный DNS-ответ (публичный + приватный) — полный отказ.
- **Валидация входа** — тип и длина `url`, `consent === true`, окно `consentTimestamp`, `new URL()`, регулярное выражение для hostname. IPv6-литералы сознательно не поддерживаются и отсекаются.
- **Нет эксплуатации** — только TCP-connect, TLS-хендшейк и чтение заголовков; тело ответа уничтожается сразу после заголовков.
- **XSS** — рендер только через `textContent`/DOM API, `innerHTML` не используется; строгий CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Ошибки** — единый обработчик, наружу только обобщённый JSON, стек — в серверный лог.
- **CORS** — один явный origin, без `*`.
- **Лимит тела** — 8 КБ; **таймауты** — 3–5 с на сетевые операции, 45 с на клиенте, 20 с на graceful shutdown.
- **Секретов нет** — внешних API и БД нет; `.env` в `.gitignore`.

Подробности и модель угроз — в [docs/architecture.md](docs/architecture.md). Порядок сообщения об уязвимостях — в [.github/SECURITY.md](.github/SECURITY.md).

## Ограничения

Честный список того, чего сервис не делает и где может ошибаться. Для публичного запуска и B2B-продажи часть пунктов обязательна к закрытию — см. раздел «Roadmap».

1. **Лимит частоты — best effort.** 10 секунд на IP (IPv6 — на подсеть `/64`), карта в памяти процесса, `MAX_KEYS = 10 000`, LRU-вытеснение. Обходится распределённым источником или выделенной `/48`. N реплик = N независимых лимитов. Глобального лимита и потолка одновременных сканов нет — это P1 для публичного запуска.
2. **Согласие — не проверка владения доменом.** `consent: true` подделывается одной строкой `curl`; `consentTimestamp` формируется клиентом. Механизм фиксирует намерение, но не подтверждает право на скан. Verification (DNS TXT / файл / meta) не реализован.
3. **Редиректы не разворачиваются.** Если 443 закрыт, а 80 отдаёт 301 на HTTPS, в отчёт попадут заголовки редиректа, а не сайта. Оценка при этом может быть занижена.
4. **IPv6-литералы не поддерживаются.** `http://[2606:4700::1111]` возвращает 400 «Некорректный адрес». Это осознанный отказ вместо неработающей поддержки.
5. **Скан ограничен.** Только пять фиксированных портов, только `GET /`, только корень сайта. Путь (`/admin`) и нестандартный порт (`:8443`) из URL игнорируются. Поддомены не перебираются.
6. **TLS 1.0/1.1.** Node по умолчанию не устанавливает соединение ниже TLS 1.2, поэтому хост, поддерживающий только TLS 1.0/1.1, будет показан как «SSL отсутствует», хотя TLS там есть — просто слабый. Различать версии протоколов сканер пока не умеет.
7. **Нет истории, БД, аккаунтов, API-ключей и share-ссылок.** Сервис stateless: результат живёт только в ответе и в DOM. PDF — это диалог печати браузера (`window.print()`), без обложки, логотипа, имени клиента и нумерации страниц.
8. **PII в логах.** В stdout пишутся hostname цели и IP клиента; ротации и TTL нет. Политики приватности и обработки персональных данных нет — для коммерческого использования (152-ФЗ) это блокер, а не «мелочь».
9. **Оценка — эвристика.** A не означает «сайт безопасен»: проверяются четыре заголовка и сертификат. Нет проверок cookie-флагов, CORS, DNS (SPF/DMARC/DKIM), открытых файлов, технологий. Risk Score не является заключением об уязвимостях и не заменяет аудит.
10. **Один origin в CORS.** Мультидомен (apex + www, кастомный домен) не поддерживается: в `PUBLIC_ORIGIN` можно указать только один origin.
11. **`npm audit` в CI может «покраснеть»** на новом CVE в транзитивной зависимости и заблокировать не связанный с ним PR. Пока это осознанный компромисс; план — nightly-аудит + `continue-on-error` для push в main.

## Roadmap

- **v1.2.0** — глобальный rate-limit и семафор параллельных сканов, verification домена, мультидомен в CORS, приватность.
- **v1.3.0** — PostgreSQL, история, API-ключи, share-ссылки, рефакторинг `server.js` на `app.js`/`config.js`, тесты HTTP-слоя.
- **Дальше** — пассивные модули для пентеста: TLS-версии и шифры, cookie/CORS, DNS/email, утечки и fingerprinting.

## Disclaimer

См. [DISCLAIMER.md](./DISCLAIMER.md).

## License

MIT — см. [LICENSE](./LICENSE).
