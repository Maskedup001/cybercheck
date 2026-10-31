# CyberCheck

> ⚠️ **ВНИМАНИЕ!** Инструмент предназначен только для тестирования собственных систем или систем, на которые у вас есть официальное письменное разрешение. Несанкционированное сканирование чужих доменов может быть нарушением закона (**ст. 272 УК РФ**). Автор не несёт ответственности за использование инструмента третьими лицами.

---

CyberCheck — сканер внешней безопасности веб-сайта. Проверяет доступность пяти портов, TLS-сертификат и его версию, четыре HTTP-заголовка безопасности и превращает результат в **Risk Score** (0–100, A–F) со списком находок и рекомендаций. Написан на Node.js + Express, фронтенд — vanilla JS без сборки.

Документация: [архитектура и модель угроз](docs/architecture.md) · [политика безопасности](.github/SECURITY.md) · [DISCLAIMER](DISCLAIMER.md).

**Текущая версия: 1.2.0.** Что нового относительно 1.1.0: определение TLS 1.0/1.1, расширенная валидация URL (IDN, длина, схемы), HSTS без TLS больше не даёт баллов, skip-link и `aria-describedby`, JSON-404, retry для портов и заголовков, `buildReport()`.

## Что проверяет

| Группа | Проверка | Как |
|---|---|---|
| Порты | 80, 443, 22, 3306, 8080 | TCP-connect, 3 с на попытку, один retry |
| TLS | наличие TLS, валидность, срок, издатель, версия протокола, поддержка TLS 1.0/1.1 | `tls.connect` с `rejectUnauthorized: false`; отдельный probe на TLS 1.0/1.1 |
| Заголовки | `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` | `GET /` по HTTPS, при ошибке — по HTTP; тело не скачивается |
| Гигиена | `Server`, фактический протокол (HTTP/HTTPS) | те же заголовки ответа |
| Оценка | Risk Score 0–100, буква A–F, находки с приоритетом и рекомендацией | `src/scoring.js`, чистая функция |

Сканируется только корень сайта: путь и нестандартный порт из введённого URL игнорируются. Редиректы не разворачиваются, IPv6-литералы не поддерживаются (см. «Ограничения»).

## Risk Score

Оценка считается на сервере в `src/scoring.js` и приходит в ответе полями `score`, `grade`, `findings`.

**Веса (сумма — 100):**

| Фактор | Баллы |
|---|---|
| Валидный TLS-сертификат | 20 |
| До истечения сертификата больше 30 дней | 5 |
| `Strict-Transport-Security` (только при валидном TLS) | 15 |
| `Content-Security-Policy` | 15 |
| `X-Frame-Options` | 10 |
| `X-Content-Type-Options` | 10 |
| Заголовок `Server` не раскрыт | 5 |
| Нет открытых портов 22 и 3306 | 15 |
| Порт 8080 закрыт | 5 |
| **Поддержка TLS 1.0/1.1** | **−10** |

**Жёсткие потолки** — они важнее суммы весов:

| Условие | Максимум |
|---|---|
| Не удалось проверить заголовки (`headers.error`) | 60 (фактически ≤ 45: баллы за заголовки не начисляются) |
| HTTPS отсутствует | 30 |
| Сертификат невалиден/просрочен | 40 |
| Открыт порт 3306 | 70 |
| Поддержка TLS 1.0/1.1 | 85 (B — не A) |

**Буквы:** A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F < 20.

**Находка (`findings[]`)** — объект с полями `id`, `title`, `desc`, `severity` (`high` / `medium` / `low`), `weight` и `recommendation`. Находки сортируются по весу; `severity` управляет цветом. Тексты сформулированы как «снижает защиту», а не «сайт уязвим».

Оценка детерминирована: одинаковый вход даёт одинаковый выход, сеть внутри `scoring.js` не используется. Контракт и тесты — в [архитектуре](docs/architecture.md).

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

> Переменная `PUBLIC_ORIGIN` **обязательна вне Render**. Она задаёт единственный origin для CORS. Без неё (и без `RENDER_EXTERNAL_URL`) сервер завершается с кодом 1 — защита от случайного открытия API всем доменам.

### Переменные окружения

Шаблон — в [`.env.example`](.env.example). Файл `.env` **не подгружается автоматически**: переменные задаются перед командой запуска или через `node --env-file=.env src/server.js` (Node 20.6+).

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PORT` | `3000` | Порт HTTP-сервера |
| `PUBLIC_ORIGIN` | — | Origin фронтенда для CORS (например, `https://cybercheck.example`). Имеет приоритет над `RENDER_EXTERNAL_URL`; из значения берётся только `origin` |
| `RENDER_EXTERNAL_URL` | — | Подставляется Render автоматически для веб-сервисов; fallback, если `PUBLIC_ORIGIN` не задан |
| `TRUST_PROXY` | `0` | Число доверенных прокси. `1` — на Render. Включать только если приложение недоступно напрямую |
| `DEMO_MODE` | `false` | Разрешает сканировать `localhost` и `127.0.0.1`. Только при `NODE_ENV=development` |
| `NODE_ENV` | — | `development` или `production`; влияет на `DEMO_MODE` и текст 404 |

`PUBLIC_ORIGIN` проверяется на старте: значение парсится как URL и должно иметь схему `http:` или `https:`.

### Режим демонстрации

```bash
PUBLIC_ORIGIN=http://localhost:3000 DEMO_MODE=true NODE_ENV=development npm start
```

`DEMO_MODE` без явного `NODE_ENV=development` останавливает сервер: ошибка конфигурации не открывает доступ к внутренней сети, а закрывает сервис (fail-closed). Демо-режим поддерживает только `localhost` и `127.0.0.1`; IPv6-литералы, включая `::1`, отсекаются на валидации.

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

`consentTimestamp` — миллисекунды; принимается окно от 15 минут в прошлом до 1 минуты в будущем. `consent` должен быть строго `true`. Поддерживаются только `http`/`https`; URL длиной до 2048 символов; IDN и завершающая точка нормализуются.

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
    "issuer": "Let's Encrypt",
    "tlsVersion": "TLSv1.3",
    "supportsOldTls": false
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
| 400 | невалидный `url`, нет согласия, устаревший timestamp, приватный/неразрешимый адрес, неподдерживаемая схема |
| 413 | тело больше 8 КБ |
| 429 | повторный скан с того же IP раньше чем через 10 секунд (заголовок `Retry-After` не выставляется) |
| 500 | непредвиденная ошибка; подробности только в серверном логе |

Неизвестные пути отдают `404 { "error": "Не найдено" }`. `GET /healthz` → `{ "ok": true, "uptime": 12.34 }`.

## Тестирование

```bash
npm test
```

Запускается `node --test test/*.test.js` — **16 тестов** в трёх файлах:

- `test/net-guard.test.js` — 3 теста: 20 приватных/служебных адресов блокируются, 4 публичных разрешаются, мусорный ввод блокируется (fail-closed). Покрыты IPv4-mapped, IPv4-compatible, NAT64 и `::/96`.
- `test/scoring.test.js` — 11 тестов: «всё хорошо» → 100/A; нет CSP → 85/B; нет HSTS → 85/B; нет XCTO → 90/A; просроченный сертификат → ≤ 40; нет HTTPS → ≤ 30; `headers.error` → ≤ 60 и находка; открытый 3306 → ≤ 70; `server: "не указан"` не считается раскрытием; HSTS без TLS не даёт баллов (20); TLS 1.0/1.1 → 85/B.
- `test/checks.test.js` — 2 теста `checkPort`: закрытый порт не висит и не считается открытым (`refused`/`closed`), открытый порт определяется (`open`).

Не покрыто: HTTP-слой (400/404/429/CORS), `checkHeaders` retry, `checkOldTls`/`supportsOldTls`, URL-валидация, `buildReport`, рендер отчёта. Как это закрыть — в [архитектуре](docs/architecture.md).

CI (`.github/workflows/ci.yml`) на каждый push и PR: `npm ci` → `npm audit --audit-level=high` → проверка загрузки `checks.js` → `node --check src/server.js` → `npm test` → запуск сервера и smoke-проверка `/`.

## Деплой на Render

### Вариант 1. Blueprint

В репозитории есть [`render.yaml`](render.yaml): web-сервис, план `starter`, `npm ci` / `npm start`, health-check `/healthz`, `NODE_ENV=production`, `TRUST_PROXY=1`.

1. Render → **New** → **Blueprint** → выбрать репозиторий.
2. Render читает `render.yaml` и создаёт сервис. `PUBLIC_ORIGIN` в blueprint не задан намеренно: Render сам передаёт `RENDER_EXTERNAL_URL` (например, `https://cybercheck.onrender.com`), и `server.js` использует её как fallback.
3. После первого деплоя проверить `/healthz` и один скан.

Если `PUBLIC_ORIGIN` задан, он имеет приоритет над `RENDER_EXTERNAL_URL`.

> **Свой домен.** `RENDER_EXTERNAL_URL` — это всегда `*.onrender.com`. Если привязан кастомный домен, браузер отправляет `Origin: https://ваш-домен`, а CORS разрешает только onrender-адрес → API вернёт CORS-ошибку. В этом случае **обязательно** задайте `PUBLIC_ORIGIN=https://ваш-домен` и сделайте redeploy. Поддерживается только один origin.

### Вариант 2. Вручную

- Build: `npm ci`, Start: `npm start`
- Env: `NODE_ENV=production`, `PUBLIC_ORIGIN=https://<service>.onrender.com`, `TRUST_PROXY=1`
- Health Check Path: `/healthz`
- План: **Starter**. На Free инстанс засыпает, первый скан после простоя может занять 30–50 с; клиентский таймаут — 45 с, ретрая нет.

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
│       │   ├── tokens.css          # дизайн-токены
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
│       │   └── render-result.js    # рендер отчёта через DOM API/textContent
│       └── screenshots/
│           └── og-cover.png        # OG-обложка
├── src/                            # Серверная часть
│   ├── server.js                   # Express, конфиг, валидация, лимит, buildReport
│   ├── checks.js                   # порты, TLS (включая 1.0/1.1), заголовки
│   ├── scoring.js                  # Risk Score и findings (чистая функция)
│   └── net-guard.js                # SSRF-защита: isPublicIp, resolvePublicIps
├── test/
│   ├── net-guard.test.js           # 3 теста SSRF-классификации
│   ├── scoring.test.js             # 11 тестов скоринга
│   └── checks.test.js              # 2 теста checkPort
├── .env.example
├── .gitignore
├── package.json
├── package-lock.json
├── render.yaml
├── README.md
├── DISCLAIMER.md
└── LICENSE                         # MIT
```

> `node_modules/` создаётся после `npm install` и в репозиторий не попадает.
>
> `SECURITY.md` лежит в `.github/` — именно оттуда GitHub показывает его на вкладке **Security**.

## Безопасность

- **SSRF-защита** — DNS-резолв, проверка **всех** адресов на публичность (`ipaddr.js`, только `unicast`), подключение **по проверенному IP**, без повторного резолва. Блокируются loopback, private, link-local, CGNAT, multicast, ULA, 6to4, Teredo, NAT64, IPv4-mapped и `::/96`.
- **Валидация URL** — только `http`/`https`, длина ≤ 2048, hostname ≤ 253, IDN/punycode, снятие завершающей точки, IPv6-литералы отклоняются, приватные адреса — через SSRF-контур.
- **Нет эксплуатации** — TCP-connect, TLS-хендшейк (включая probe TLS 1.0/1.1) и чтение заголовков; тело ответа уничтожается сразу после заголовков. Это не фаззинг и не подбор.
- **XSS** — рендер только через `textContent`/DOM API, `innerHTML` не используется; строгий CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Ошибки** — единый обработчик, наружу только обобщённый JSON, стек — в серверный лог.
- **CORS** — один явный origin, без `*`.
- **Лимит тела** — 8 КБ; **таймауты** — 3–5 с на сетевые операции, 45 с на клиенте, 40 с на graceful shutdown.
- **Ретраи** — порты и заголовки повторяются один раз; это может означать более одного запроса к цели.
- **Секретов нет** — внешних API и БД нет; `.env` в `.gitignore`.

Подробности и модель угроз — в [docs/architecture.md](docs/architecture.md). Порядок сообщения об уязвимостях — в [.github/SECURITY.md](.github/SECURITY.md).

## Ограничения

1. **Лимит частоты — best effort.** 10 секунд на IP (IPv6 — на подсеть `/64`), карта в памяти процесса, `MAX_KEYS = 10 000`, LRU. Обходится распределённым источником или `/48`. N реплик = N лимитов. Глобального лимита и потолка одновременных сканов нет.
2. **Согласие — не проверка владения доменом.** `consent: true` подделывается одной строкой `curl`; `consentTimestamp` формируется клиентом. Verification не реализован.
3. **Редиректы не разворачиваются.** Если 443 закрыт, а 80 отдаёт 301 на HTTPS, в отчёт попадут заголовки редиректа, а не сайта.
4. **IPv6-литералы не поддерживаются.** `http://[2606:4700::1111]` возвращает 400.
5. **Скан ограничен.** Пять фиксированных портов, `GET /`, только корень сайта. Путь и нестандартный порт (`:8443`) из URL игнорируются; поддомены не перебираются.
6. **TLS 1.0/1.1 — детект, а не гарантия.** `checkOldTls` может дать ложное отрицание, если OpenSSL/сборка Node запрещает TLS 1.0/1.1 на своём уровне. Шифры и цепочка сертификатов не проверяются. Основное TLS-соединение допускает TLS 1.0, чтобы прочитать сертификат старого сервера. На медленном TLS возможен race с 5-секундным таймаутом (см. architecture).
7. **Общего таймаута скана нет.** Худший сценарий — около 35,5 с (порты 6,5 + TLS 8 + заголовки 21). Graceful shutdown ждёт 40 с, но Render может прислать SIGKILL раньше; клиентский таймаут — 45 с.
8. **Нет истории, БД, аккаунтов, API-ключей и share-ссылок.** PDF — диалог печати браузера (`window.print()`), без обложки/лого/нумерации.
9. **PII в логах.** Hostname и IP клиента пишутся в stdout; ротации и TTL нет. Политики приватности нет — для 152-ФЗ это блокер.
10. **Оценка — эвристика.** A не означает «сайт безопасен». Порог A = 90, поэтому сайт без одного заголовка (например, XCTO) всё ещё получает A; старый TLS специально ограничен 85 (B). Risk Score не заменяет аудит.
11. **Один origin в CORS.** Мультидомен (apex + www, кастомный домен) не поддерживается.
12. **`npm audit` в CI** может «покраснеть» на новом CVE и заблокировать несвязанный PR.
13. **OG-картинка** — абсолютный URL на `raw.githubusercontent.com`; превью зависит от доступности GitHub. `canonical` и `og:url` не заданы.
14. **Нет политики приватности** в `legal.html`; для B2B (152-ФЗ) нужна отдельная страница.

## Roadmap

- **v1.2.0 (текущая)** — TLS 1.0/1.1, валидация URL/IDN, HSTS без TLS, a11y, JSON-404, retry, `buildReport`.
- **v1.3.0** — глобальный rate-limit и семафор параллельных сканов, verification домена, мультидомен в CORS, приватность.
- **v1.4.0** — PostgreSQL, история, API-ключи, share-ссылки, рефакторинг `server.js` на `app.js`/`config.js`, тесты HTTP-слоя.
- **Дальше** — пассивные модули для пентеста: TLS-шифры и цепочка, cookie/CORS, DNS/email, утечки, fingerprinting.

## Disclaimer

См. [DISCLAIMER.md](./DISCLAIMER.md).

## License

MIT — см. [LICENSE](./LICENSE).
