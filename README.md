# CyberCheck

> ⚠️ **ВНИМАНИЕ!** Инструмент предназначен только для тестирования собственных систем или систем, на которые у вас есть официальное письменное разрешение. Несанкционированное сканирование чужих доменов может быть нарушением закона (**ст. 272 УК РФ**). Автор не несёт ответственности за использование инструмента третьими лицами.

---

CyberCheck — сканер внешней безопасности веб-сайта. Проверяет доступность пяти портов, TLS-сертификат и его версию, security-заголовки и cookie-флаги, SPF/DMARC/CAA, HEAD-пробы типовых файлов утечки, `security.txt`, CORS и WAF/CMS-признаки, а затем превращает результат в **Risk Score** (0–100, A–F) со списком находок и рекомендаций. Написан на Node.js + Express, фронтенд — vanilla JS без сборки. Отчёт открывается прямо в браузере: кольцо оценки, вердикт словами, карточки находок и детали проверки — и печатается в A4.

Документация: [архитектура и модель угроз](docs/architecture.md) · [политика безопасности](.github/SECURITY.md) · [DISCLAIMER](DISCLAIMER.md).

**Текущая версия: 2.1.0.**

Ключевое в релизе:

- **Интерфейс.** Отчёт-«приборная панель»: кольцо оценки на `conic-gradient`, вердикт словами, карточки находок с бейджем важности и OWASP-тегом, а также карточки деталей — порты, TLS, заголовки, почтовая безопасность, cookie, технологии и открытые файлы.
- **Дизайн-система.** Компонентов стало десять вместо четырёх: добавились `badge`, `scan-status`, `score`, `findings`, `details` и `legal`; все 16 файлов подключены через `@import` в `main.css`, без сборщика и без inline-стилей (иначе не пройдёт `style-src 'self'`).
- **Юридические документы.** `/legal.html` и `/privacy.html` с оглавлением: `legal-toc.js` строит его из заголовков разделов, ведёт подсветку через `aria-current="location"` и переносит фокус в раздел при клике. Без JS оглавление скрыто, текст читается линейно.
- **Доступность.** Skip-link, `aria-describedby` у поля, `aria-invalid` только на том контроле, о котором говорит ошибка, `role="alert"`/`role="status"`, кастомный чекбокс поверх нативного `input`, поддержка `prefers-reduced-motion` и `prefers-contrast`.
- **Печать.** A4-версия отчёта: `@page`, `print-color-adjust: exact`, `break-inside: avoid`, имя файла `CyberCheck_<host>_<дата>`.
- **Надёжность.** Единый error handler последним в стеке, JSON-404, `no-store` на динамике и ETag на статике, семафор на 25 одновременных сканов с `Retry-After: 60`, общий таймаут скана 60 с при клиентских 65 с. Обрыв соединения клиентом прерывает скан, а слот семафора освобождается в `finally`; TLS-проверка не тратится на порту 80, а при ошибке заголовков проверяется следующий веб-порт; `Host` собирается с портом для 8080; `unhandledRejection` и `uncaughtException` попадают в лог.
- **Скоринг.** Буква A требует 95+; положительные веса дают ровно 100, старый TLS — отдельный −10; каждая находка получает OWASP-тег, а критические новые проверки имеют жёсткие потолки.
- **Зависимости.** `body-parser` 1.20.9 и `qs` 6.16.1 зафиксированы через `overrides`.

**Что нового в 2.1.0.** DNS/email-проверки (SPF, DMARC, CAA), cookie-флаги, дополнительные security-заголовки, HEAD-пробы `/.env`, `/.git/config`, `/.DS_Store`, `/backup.zip`, `security.txt`, CORS `*` и WAF/CMS-фингерпринт. Пересчитан Risk Score: сумма весов 100, новые потолки для открытых файлов и CORS, OWASP-теги у всех находок. В дашборде появились карточки почты, cookie, технологий и открытых файлов. Серверный таймаут — 60 с, клиентский — 65 с; 89 тестов.

**Что нового в 2.0.1.** Отдельная находка `ssl-error` вместо ложного «Нет SSL» при сетевой ошибке TLS; порты 80 и 8080 не считаются TLS-ошибкой; fallback 443 → 80 → 8080 с сохранением валидного сертификата и ошибки TLS с 443; перебор до трёх IP из DNS; серверный таймаут 40 с; `TRUST_PROXY` — целое 0–10; `Server: nginx/2` теперь даёт находку; DNS-ожидание прерывается при обрыве клиента; CI ставит зависимости с `--ignore-scripts`; 27 тестов.

**Почему 2.0.0, а не 1.3.0 (история).** Контракт `POST /api/scan` расширился, но не сломался: добавлены `ssl.tlsVersion` и `ssl.supportsOldTls`. Изменилось всё остальное, что видит потребитель: буква A теперь требует 95 баллов (было 90), поэтому часть сайтов переедет из A в B; появились `503` и `504`; новая вёрстка всех трёх страниц; CSS вырос с 10 файлов до 17; добавился маршрут `/privacy.html`.

## Что проверяет

| Группа | Проверка | Как |
|---|---|---|
| Порты | 80, 443, 22, 3306, 8080 | TCP-connect, 3 с на попытку, один retry |
| TLS | наличие TLS, валидность, срок, издатель, версия протокола, поддержка TLS 1.0/1.1 | `tls.connect` с `rejectUnauthorized: false` и одним retry; отдельный probe на TLS 1.0/1.1; на 80 TLS не проверяется, на 8080 провал TLS трактуется как HTTP-порт, а не как `ssl-error` |
| Заголовки | `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` | `GET /` по HTTPS (на 443 — всегда, даже если TLS-хендшейк не удался); при ошибке — по HTTP; если порт не ответил, проверяется следующий из 443 → 80 → 8080; тело не скачивается |
| Гигиена | `Server`, фактический протокол (HTTP/HTTPS) | те же заголовки ответа |
| DNS/Email | SPF, DMARC (политика `none` / `quarantine` / `reject`), CAA | `node:dns/promises`: TXT, `_dmarc.<домен>`, CAA; ошибки DNS не роняют скан |
| Cookie | `Secure`, `HttpOnly`, `SameSite` в `Set-Cookie` | значения cookie не сохраняются, только имя и флаги |
| Доп. заголовки | `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` | наличие в ответе |
| Файлы | `/.env`, `/.git/config`, `/.DS_Store`, `/backup.zip` | `HEAD`, таймаут 2 с; `200` — critical, `403` — WAF/запрет, остальное — данные |
| CORS/security.txt | `Access-Control-Allow-Origin: *`, `/.well-known/security.txt` | заголовок корневого ответа и GET security.txt |
| Fingerprint | WAF (Cloudflare, Sucuri, Akamai), CMS (WordPress, Drupal, Joomla, Bitrix) | заголовки/куки и ограниченное тело HTML (до 64 КБ) |
| Оценка | Risk Score 0–100, буква A–F, находки с приоритетом, рекомендацией и OWASP-тегом | `src/scoring.js`, чистая функция |

Сканируется только корень сайта: путь и нестандартный порт из введённого URL игнорируются. Редиректы не разворачиваются, IPv6-литералы не поддерживаются (см. «Ограничения»). Если у домена несколько A/AAAA-записей, проверяется до трёх адресов, пока не найдётся узел с открытым веб-портом.

## Risk Score

Оценка считается на сервере в `src/scoring.js` и приходит в ответе полями `score`, `grade`, `findings`.

**Веса (сумма положительных — ровно 100):**

| Блок | Проверка | Баллы |
|---|---|---:|
| TLS | Валидный TLS-сертификат | 12 |
| TLS | До истечения сертификата больше 30 дней | 3 |
| TLS | **Поддержка TLS 1.0/1.1** | **−10 (штраф сверх 100)** |
| Заголовки | `Strict-Transport-Security` (только при валидном TLS) | 8 |
| Заголовки | `Content-Security-Policy` | 10 |
| Заголовки | `X-Frame-Options` | 6 |
| Заголовки | `X-Content-Type-Options` | 6 |
| Заголовки | В `Server` нет номера версии | 3 |
| Заголовки | Referrer-Policy | 2 |
| Заголовки | Permissions-Policy | 2 |
| Заголовки | Cross-Origin-Opener-Policy | 2 |
| Заголовки | CORS не `*` | 3 |
| Cookie | Secure | 3 |
| Cookie | HttpOnly | 2 |
| Cookie | SameSite | 1 |
| DNS/Email | SPF присутствует | 4 |
| DNS/Email | DMARC `quarantine`/`reject` | 3 |
| DNS/Email | CAA присутствует | 2 |
| Порты | Нет открытых 22/3306 | 10 |
| Порты | Порт 8080 закрыт | 2 |
| Файлы | `/.env` не открыт | 7 |
| Файлы | `/.git/config` не открыт | 4 |
| Файлы | `/backup.zip` не открыт | 2 |
| Файлы | `/.DS_Store` не открыт | 1 |
| security.txt | `/.well-known/security.txt` присутствует | 2 |
| **Итого** | | **100** |

**Жёсткие потолки** — применяются после суммирования, итог — минимум из суммы и всех подошедших ограничений:

| Условие | Максимум |
|---|---:|
| `files.critical`/`exposed` содержит `/.env` | **40 (D)** |
| `files.critical`/`exposed` содержит `/.git/config` | **50 (D)** |
| `files.critical`/`exposed` содержит `/backup.zip` | **50 (D)** |
| `headers.corsWildcard === true` | **60 (C)** |
| Не удалось проверить заголовки (`headers.error`) | 60 |
| Ошибка TLS (`ssl.error`) | 60 |
| HTTPS отсутствует | 30 |
| Сертификат невалиден/просрочен | 40 |
| Открыт порт 3306 | 70 |
| Поддержка TLS 1.0/1.1 | 85 (B — не A) |
| Сертификат истекает через ≤ 7 дней | 90 (B — не A) |
| Любая находка `medium` или `high` | 90 (B — не A) |

`files.critical` принимается и как массив строк, и как массив `{ path, severity }`; `files.exposed` тоже поддерживается. Для `/.DS_Store` отдельного потолка нет: это low-находка. `403`/`404`/ошибка HEAD не считаются экспозицией и потолок не включают.

**Буквы:** A ≥ 95, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F < 20.

Буква A достижима только при оценке 95+: потолок 90 для находок `medium`/`high` означает, что любая серьёзная находка опускает результат до B.

Сертификат, истекающий в течение 30 дней, даёт находку `ssl-expiring` уровня `low` и не приносит 3 балла. При `daysLeft <= 7` дополнительно включается потолок 90 (B); при 8–30 днях сайт с идеальной гигиеной остаётся A (97).

Если TLS-соединение не установилось, отчёт не утверждает «SSL нет»: приходит `ssl.hasSSL: false`, `ssl.error` (например, `HANDSHAKE_FAILED`), находка `ssl-error` уровня `medium` и потолок 60. `no-ssl` и потолок 30 остаются только для случая, когда TLS действительно не настроен (порт 80/8080 отвечает по HTTP). Карточка TLS в этом случае пишет «Не удалось проверить TLS», а не «SSL не настроен».

Новые проверки дают находки `spf-missing`, `dmarc-missing`/`dmarc-weak`/`dmarc-invalid`, `caa-missing`, `cookie-no-secure`/`cookie-no-httponly`/`cookie-no-samesite`, `no-referrer-policy`/`no-permissions-policy`/`no-coop`, `cors-wildcard`, `exposed-env`/`exposed-git`/`exposed-backup`/`exposed-dsstore`, `security-txt-missing`. WAF/CMS — информационные `waf-detected`/`cms-detected` с `weight: 0`.

**Находка (`findings[]`)** — объект с полями `id`, `title`, `desc`, `severity` (`high` / `medium` / `low`), `weight`, `recommendation` и `owasp` (например, `A05:2021 Security Misconfiguration`). Находки сортируются по весу; `severity` управляет цветом. OWASP-тег — маркировка категории, а не заявление о сертификации.

Оценка детерминирована: одинаковый вход даёт одинаковый выход, сеть внутри `scoring.js` не используется. Контракт и тесты — в [архитектуре](docs/architecture.md).

## Стек

- Node.js 22–24 + Express 4
- Vanilla JavaScript (ES-модули) + CSS без сборщика: 16 `@import` в `main.css` (токены, reset, база, layout, утилиты, печать и 10 компонентов)
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
| `PORT` | `3000` | Порт HTTP-сервера. Целое 0–65535; иначе процесс завершается с кодом 1 |
| `PUBLIC_ORIGIN` | — | Origin фронтенда для CORS (например, `https://cybercheck.example`). Имеет приоритет над `RENDER_EXTERNAL_URL`; из значения берётся только `origin` |
| `RENDER_EXTERNAL_URL` | — | Подставляется Render автоматически для веб-сервисов; fallback, если `PUBLIC_ORIGIN` не задан |
| `TRUST_PROXY` | `0` | Целое 0–10. `0` — не доверять прокси, `1` — Render. `true`, мусор и значения вне диапазона завершают процесс с кодом 1; при `>0` включается доверие к `X-Forwarded-For` |
| `DEMO_MODE` | `false` | Разрешает сканировать `localhost` и `127.0.0.1`. Только при `NODE_ENV=development` |
| `NODE_ENV` | — | `development` или `production`; влияет на `DEMO_MODE` и текст 404 |

`PUBLIC_ORIGIN` проверяется на старте: значение парсится как URL и должно иметь схему `http:` или `https:`. `TRUST_PROXY` должен совпадать с числом реальных прокси: при завышенном значении `req.ip` берётся из подставленного `X-Forwarded-For` и лимит обходится одним заголовком.

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
    "server": "nginx/1.18.0",
    "csp": true,
    "xframe": true,
    "hsts": true,
    "xcontent": true,
    "referrerPolicy": true,
    "permissionsPolicy": true,
    "coop": true,
    "corsWildcard": false,
    "accessControlAllowOrigin": null,
    "cookies": [
      {
        "name": "session",
        "secure": true,
        "httpOnly": true,
        "sameSite": true,
        "sameSiteValue": "lax"
      }
    ],
    "cookieSummary": {
      "total": 1,
      "secure": 1,
      "httpOnly": 1,
      "sameSite": 1,
      "missingSecure": 0,
      "missingHttpOnly": 0,
      "missingSameSite": 0
    }
  },
  "dns": {
    "applicable": true,
    "spf": {
      "present": true,
      "record": "v=spf1 -all",
      "multiple": false,
      "error": null
    },
    "dmarc": {
      "present": true,
      "record": "v=DMARC1; p=reject",
      "policy": "reject",
      "strict": true,
      "weak": false,
      "error": null
    },
    "caa": {
      "present": true,
      "records": [{ "critical": 0, "issue": "letsencrypt.org" }],
      "error": null
    }
  },
  "files": {
    "port": 443,
    "protocol": "HTTPS",
    "results": [
      {
        "path": "/.env",
        "status": 404,
        "exposed": false,
        "blocked": false,
        "error": null
      }
    ],
    "exposed": [],
    "blocked": [],
    "critical": []
  },
  "securityTxt": {
    "path": "/.well-known/security.txt",
    "status": 200,
    "present": true,
    "blocked": false,
    "error": null
  },
  "fingerprint": {
    "waf": { "name": "cloudflare", "evidence": ["cf-ray"] },
    "cms": null,
    "server": "cloudflare",
    "status": 200,
    "error": null,
    "bodyBytes": 1420
  },
  "score": 97,
  "grade": "A",
  "findings": [
    {
      "id": "server-exposed",
      "title": "Раскрыт Server",
      "desc": "В заголовке Server есть номер версии — это упрощает подбор эксплойтов.",
      "severity": "low",
      "weight": 3,
      "recommendation": "Уберите версию из заголовка Server или скройте его в конфиге nginx/apache.",
      "owasp": "A05:2021 Security Misconfiguration"
    },
    {
      "id": "waf-detected",
      "title": "Обнаружен WAF",
      "desc": "WAF: cloudflare. Это защитный слой, а не недостаток.",
      "severity": "low",
      "weight": 0,
      "recommendation": "Проверьте, что правила WAF обновляются.",
      "owasp": "A05:2021 Security Misconfiguration"
    }
  ]
}
```

Оценка теперь учитывает новые данные: `dns`, `files`, `securityTxt`, `fingerprint` и расширенные поля `headers`. Каждая находка содержит `owasp`; WAF/CMS — информационные находки с `weight: 0`. Для `files` критичны только `200` на `/.env`, `/.git/config` и `/backup.zip`; `403` не считается экспозицией.

Ошибки — всегда JSON `{ "error": "..." }` без стека и внутренних деталей:

| Код | Когда |
|---|---|
| 400 | невалидный `url`, нет согласия, устаревший timestamp, приватный/неразрешимый адрес, неподдерживаемая схема |
| 413 | тело больше 8 КБ |
| 429 | повторный скан с того же IP раньше чем через 10 секунд; `Retry-After` содержит число секунд |
| 503 | сервер уже ведёт 25 сканирований одновременно; `Retry-After: 60` |
| 504 | DNS не ответил за 5 секунд или скан не уложился в 60 секунд |
| 500 | непредвиденная ошибка; подробности только в серверном логе |

Неизвестные пути отдают `404 { "error": "Не найдено" }`. `GET /healthz` → `{ "ok": true, "uptime": 12.34 }`.

## Тестирование

```bash
npm test
```

Запускается `node --test test/*.test.js` — **89 тестов** в восьми файлах:

- `test/net-guard.test.js` — 3 теста: 20 приватных/служебных адресов блокируются, 4 публичных разрешаются, мусорный ввод блокируется (fail-closed). Покрыты IPv4-mapped, IPv4-compatible, NAT64 и `::/96`.
- `test/scoring.test.js` — 29 тестов: сумма весов 100; TLS/SSL, заголовки, порты; потолки `.env`/`.git`/`backup`/CORS; DMARC `p=none`; DNS timeout и `ENODATA`; cookie-флаги; `security.txt`; WAF/CMS; OWASP-теги у всех находок.
- `test/checks.test.js` — 4 теста: `checkPort` на закрытом и открытом порту, `checkHeaders` (CSP, X-Frame-Options, cookie-флаги, дополнительные заголовки, CORS), `checkSSL` с `HANDSHAKE_FAILED`.
- `test/dns-security.test.js` — 19 тестов: SPF, DMARC (`reject`/`quarantine`/`none`), CAA, IP/localhost, таймауты, DNS-ошибки и abort.
- `test/header-analysis.test.js` — 23 теста: разбор `Set-Cookie`, сводка флагов, Referrer-Policy/Permissions-Policy/COOP, ACAO `*`, WAF (Cloudflare/Sucuri/Akamai), CMS (WordPress/Drupal/Joomla/Bitrix).
- `test/web-probes.test.js` — 8 тестов: HEAD-пробы (200/403/404/301), `security.txt`, фингерпринт, Host/connectIp, таймаут и abort.
- `test/frontend-contract.test.js` — 2 теста: нормализация `owasp`/новых полей в `api.js` и наличие карточек/OWASP-класса в `render-result.js`.
- `test/server.test.js` — 1 тест: сервер запускается с `TRUST_PROXY=0` (на случайном порту) и не падает.

Не покрыто: HTTP-слой (400/404/429/503/CORS), интеграция новых проб в `server.js` (сборка `dns/files/securityTxt/fingerprint`), `checkOldTls`/`supportsOldTls`, URL-валидация, `buildReport`, DOM-рендер карточек и печать. Как это закрыть — в [архитектуре](docs/architecture.md).

CI (`.github/workflows/ci.yml`) на каждый push и PR: `npm ci --ignore-scripts` → `npm audit --audit-level=high --omit=dev` → проверка загрузки `checks.js` → `node --check src/server.js` → разбор модулей фронтенда через `vm.SourceTextModule` → `npm test` → запуск сервера и smoke-проверка `/`.

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
- План: **Starter**. На Free инстанс засыпает, первый скан после простоя может занять 30–50 с; клиентский таймаут — 65 с, ретрая нет.

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
│   │   └── ci.yml                  # CI: install → audit → syntax → modules → test → smoke
│   └── SECURITY.md                 # Политика безопасности (вкладка Security)
├── docs/
│   └── architecture.md             # Архитектура, контракт скоринга, модель угроз
├── public/                         # Клиентская часть (статика)
│   ├── index.html                  # Страница сканера
│   ├── legal.html                  # Пользовательское соглашение
│   ├── privacy.html                # Политика конфиденциальности
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
│       │       ├── badge.css       # бейджи ok / warn / bad / muted
│       │       ├── scan-form.css
│       │       ├── consent.css     # строка согласия с кастомным чекбоксом
│       │       ├── scan-status.css # индикатор сканирования
│       │       ├── result.css      # каркас отчёта
│       │       ├── score.css       # кольцо оценки и вердикт
│       │       ├── findings.css    # карточки находок
│       │       ├── details.css     # сетка деталей проверки
│       │       └── legal.css       # документ с оглавлением
│       ├── js/
│       │   ├── app.js              # контроллер формы и состояния
│       │   ├── api.js              # fetch + AbortController (65 с) + нормализация
│       │   ├── render-result.js    # рендер отчёта через DOM API/textContent
│       │   └── legal-toc.js        # оглавление юридических страниц + scroll-spy
│       └── screenshots/
│           └── og-cover.png        # OG-обложка
├── src/                            # Серверная часть
│   ├── server.js                   # Express, конфиг, валидация, лимит, buildReport
│   ├── checks.js                   # порты, TLS, заголовки, cookie-флаги
│   ├── dns-security.js             # SPF, DMARC, CAA
│   ├── header-analysis.js          # Set-Cookie, security-заголовки, WAF/CMS
│   ├── web-probes.js               # HEAD-файлы, security.txt, fingerprint
│   ├── scoring.js                  # Risk Score и findings (чистая функция)
│   └── net-guard.js                # SSRF-защита: isPublicIp, resolvePublicIps
├── test/
│   ├── net-guard.test.js           # 3 теста SSRF-классификации
│   ├── scoring.test.js             # 29 тестов скоринга
│   ├── checks.test.js              # 4 теста: порты, заголовки, cookie, TLS
│   ├── dns-security.test.js        # 19 тестов SPF/DMARC/CAA
│   ├── header-analysis.test.js     # 23 теста cookie/заголовков/WAF/CMS
│   ├── web-probes.test.js          # 8 тестов HEAD/security.txt/fingerprint
│   ├── frontend-contract.test.js   # 2 теста нормализации/карточек/OWASP
│   └── server.test.js              # 1 тест: запуск с TRUST_PROXY=0
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
- **Нет эксплуатации** — TCP-connect, TLS-хендшейк (включая probe TLS 1.0/1.1), чтение заголовков и ограниченного тела HTML (до 64 КБ для фингерпринта), HEAD-пробы четырёх путей и GET `security.txt`. Это не фаззинг и не подбор.
- **SSRF новых проб** — HEAD-файлы, `security.txt`, CORS и фингерпринт подключаются только к `connectIp`; `hostname` используется лишь в `Host` и TLS SNI. DNS-запросы SPF/DMARC/CAA идут к резолверу и не открывают сокет на цель.
- **XSS** — рендер только через `textContent`/DOM API, `innerHTML` не используется; строгий CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Ошибки** — единый обработчик, наружу только обобщённый JSON, стек — в серверный лог.
- **CORS** — один явный origin, без `*`.
- **Лимит тела** — 8 КБ; **таймауты** — 60 с на весь скан, 2–5 с на отдельные сетевые операции, 65 с на клиенте, 40 с на graceful shutdown.
- **Кэширование** — `/` и `/api/*` отдаются с `no-store`: результат скана не оседает ни в браузере, ни в промежуточном кэше. Статика наоборот перепроверяется по ETag и отвечает 304.
- **Ретраи** — порты, TLS и заголовки повторяются один раз; это может означать более одного запроса к цели.
- **Секретов нет** — внешних API и БД нет; `.env` в `.gitignore`.

Подробности и модель угроз — в [docs/architecture.md](docs/architecture.md). Порядок сообщения об уязвимостях — в [.github/SECURITY.md](.github/SECURITY.md).

## Ограничения

1. **Лимит частоты — best effort.** 10 секунд на IP (IPv6 — на подсеть `/64`), карта в памяти процесса, `MAX_KEYS = 10 000`, LRU. Обходится распределённым источником или `/48`. N реплик = N лимитов. Потолок одновременных сканов есть — 25 на процесс, сверх этого 503, — но глобального лимита по суммарной нагрузке нет. Отдельно: `TRUST_PROXY` должен совпадать с числом реальных прокси (допустимо 0–10); при завышенном значении `req.ip` берётся из подставленного `X-Forwarded-For` и окно обходится одним заголовком.
2. **Согласие — не проверка владения доменом.** `consent: true` подделывается одной строкой `curl`; `consentTimestamp` формируется клиентом. Verification не реализован.
3. **Редиректы не разворачиваются.** Если 443 закрыт, а 80 отдаёт 301 на HTTPS, в отчёт попадут заголовки редиректа, а не сайта.
4. **IPv6-литералы не поддерживаются.** `http://[2606:4700::1111]` возвращает 400.
5. **Скан ограничен.** Пять фиксированных портов, `GET /`, только корень сайта. Путь и нестандартный порт (`:8443`) из URL игнорируются; поддомены не перебираются. Из DNS-ответа проверяется до трёх адресов; в отчёте не указано, какой именно IP проверялся, и при нескольких A-записях описывается один узел.
6. **TLS 1.0/1.1 — детект, а не гарантия.** `checkOldTls` может дать ложное отрицание, если OpenSSL/сборка Node запрещает TLS 1.0/1.1 на своём уровне. Шифры и цепочка сертификатов не проверяются. Основное TLS-соединение допускает TLS 1.0, чтобы прочитать сертификат старого сервера. На медленном TLS возможен race с 5-секундным таймаутом (см. architecture).
7. **Таймаут скана — 60 с.** Один веб-порт может занять до 31,5 с (TLS 10,5 + заголовки 21), плюс DNS/файлы/security.txt/fingerprint. Перебор трёх веб-портов вместе с пробами может превысить 60 с — такая цель обрывается 504-й. Graceful shutdown ждёт 40 с, но Render может прислать SIGKILL раньше; клиентский таймаут — 65 с.
8. **Нет истории, БД, аккаунтов, API-ключей и share-ссылок.** PDF — диалог печати браузера (`window.print()`), без обложки/лого/нумерации.
9. **PII в логах.** Hostname и IP клиента пишутся в stdout; ротации и TTL нет. `privacy.html` описывает это поведение, но для 152-ФЗ нужна отдельная юридическая проработка.
10. **Оценка — эвристика.** A не означает «сайт безопасен». Порог A = 95, а любая находка `medium`/`high` ограничивает оценку 90 (B), поэтому сайт без одного заголовка уже не получит A; старый TLS специально ограничен 85 (B). Сертификат, истекающий через ≤7 дней, ограничен 90 (B); при 8–30 днях находка `ssl-expiring` остаётся `low` и букву не меняет. Risk Score не заменяет аудит.
11. **Один origin в CORS.** Мультидомен (apex + www, кастомный домен) не поддерживается.
12. **`npm audit` в CI** может «покраснеть» на новом CVE и заблокировать несвязанный PR.
13. **OG-превью статичное.** Обложка раздаётся с того же origin (`/assets/screenshots/og-cover.png`), `canonical` и `og:url` заданы на всех трёх страницах. Генерации превью под конкретный отчёт нет — одна картинка на весь сайт.
14. **Политика приватности есть** (`privacy.html`), но это описание фактического поведения сервиса, а не юридически выверенный документ. Для B2B по 152-ФЗ нужна отдельная проработка: согласие на обработку, сроки хранения, ответственное лицо.
15. **Нужен современный браузер.** `:has()` (подсветка строки согласия), `conic-gradient` (кольцо оценки) и `100dvh` есть в Chrome 105+, Safari 15.4+, Firefox 121+. В старых браузерах деградация мягкая: скан и отчёт работают, подсветка согласия и `dvh` — нет.
16. **DNS/email — по точному hostname.** SPF/CAA запрашиваются для введённого домена, DMARC — `_dmarc.<hostname>`. Для `www.example.com` запись `_dmarc.example.com` не подставляется; сканируйте apex, если нужна зона целиком.
17. **HEAD-проба — только четыре пути.** `200` на `/.env`, `/.git/config` или `/backup.zip` даёт critical и потолок 40/50/50; `/.DS_Store` — low. SPA/редирект-заглушка тоже может вернуть `200` — это ложное срабатывание. `403` трактуется как WAF/запрет и не является уязвимостью. Ответы `301/302/401/405` — только данные.
18. **Фингерпринт — эвристика.** WAF определяется по заголовкам/кукам (Cloudflare, Sucuri, Akamai), CMS — по кукам/meta/HTML (WordPress, Drupal, Joomla, Bitrix). Кастомные сборки, закрытый бэкенд и сжатый/бинарный ответ могут не определиться; тело читается не больше 64 КБ.
19. **CORS проверяется по корню.** `Access-Control-Allow-Origin: *` смотрится в ответе `/`; отдельные API-эндпоинты не обходятся.

## Roadmap

- **2.1.0 (текущая)** — DNS/email (SPF/DMARC/CAA), cookie-флаги, Referrer-Policy/Permissions-Policy/COOP, HEAD-пробы файлов, `security.txt`, CORS `*`, WAF/CMS-фингерпринт; новый скоринг на 100 с OWASP и потолками; карточки почты/cookie/технологий/файлов; 60/65 с; 89 тестов.
- **2.0.1** — `ssl-error` вместо ложного «Нет SSL», HTTP-порты 80/8080, fallback 443 → 80 → 8080, до трёх IP, таймаут 40 с, `TRUST_PROXY` 0–10, 27 тестов.
- **2.0.0** — отчёт-«приборная панель», дизайн-система и разбиение CSS на компоненты, юридические страницы с оглавлением, печать A4, a11y, семафор на 25 сканов, JSON-404, раздельное кэширование.
- **2.2.0** — глобальный rate-limit, verification домена, мультидомен в CORS, PostgreSQL, история, API-ключи, share-ссылки, рефакторинг `server.js` на `app.js`/`config.js`, тесты HTTP-слоя.
- **Дальше** — пассивные модули для пентеста: TLS-шифры и цепочка, cookie/CORS-политики, DNS/email, утечки, fingerprinting.

## Disclaimer

См. [DISCLAIMER.md](./DISCLAIMER.md).

## License

MIT — см. [LICENSE](./LICENSE).
