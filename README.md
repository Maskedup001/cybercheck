# CyberCheck

![version](https://img.shields.io/badge/version-2.2.0-blue)
![tests](https://img.shields.io/badge/tests-215%20passed-brightgreen)
![node](https://img.shields.io/badge/node-22%E2%80%9324-339933)
![license](https://img.shields.io/badge/license-MIT-green)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF)

> ⚠️ **ВНИМАНИЕ!** Инструмент предназначен только для тестирования собственных систем или систем, на которые у вас есть официальное письменное разрешение. Несанкционированное сканирование чужих доменов может быть нарушением закона (**ст. 272 УК РФ**). Автор не несёт ответственности за использование инструмента третьими лицами.

---

CyberCheck — сканер внешней безопасности веб-сайта. Проверяет доступность пяти портов, TLS-сертификат и его версию, security-заголовки и cookie-флаги, SPF/DMARC/CAA, HEAD-пробы типовых файлов утечки, `security.txt`, CORS и WAF/CMS-признаки, а затем превращает результат в **Risk Score** (0–100, A–F) со списком находок и рекомендаций. Написан на Node.js + Express, фронтенд — vanilla JS без сборки. Отчёт открывается прямо в браузере: кольцо оценки, вердикт словами, карточки находок и детали проверки — и печатается в A4. Скан запускается только с короткоживущим HMAC-токеном согласия (15 минут), который страница получает при загрузке.

Документация: [архитектура и модель угроз](docs/architecture.md) · [политика безопасности](.github/SECURITY.md) · [DISCLAIMER](DISCLAIMER.md).

**Текущая версия: 2.2.0.**

Ключевое в релизе:

- **Архитектура.** Серверные модули разложены по доменам: `src/core` — конфигурация, HTTP-слой, SSRF-защита и общий контракт путей; `src/probes` — порты, TLS, заголовки, DNS/email и веб-пробы; `src/utils` — бюджеты времени и лимиты. Фронтенд — `api/client.js` и `ui/` (рендер, модель отчёта, оглавление).
- **Безопасность.** Закрыт аудит: согласие подтверждается HMAC-подписанным токеном (`CONSENT_SECRET`, HMAC-SHA256, TTL 15 минут, сравнение через `crypto.timingSafeEqual`), а не голым флагом `consent`. Разбор недоверенного HTML сделан линейным — `hasGeneratorMeta()` ищет `<meta>` без вложенных квантификаторов, значения заголовков обрезаются до 120 символов, тело фингерпринта — до 64 КБ. SSRF-контур не менялся: подключение только по проверенному `connectIp`. Лимит частоты считает ключ по реальному IP из правого края `X-Forwarded-For`, а не по подставленному клиентом значению.
- **Интерфейс.** Отчёт-«приборная панель»: кольцо оценки на `conic-gradient`, вердикт словами, карточки находок с бейджем важности и OWASP-тегом, а также карточки деталей — порты, TLS, cookie, почтовая безопасность, технологии, открытые файлы и заголовки. Над находками — фильтры «Все / Критичные / Важные / Замечания» с количеством, рядом с PDF — копирование сводки в буфер.
- **Человеческий язык.** Вместо `DMARC: p=reject` — «Строгий (Блокировка)», вместо `p=none` — «Мониторинг»; SPF и CAA показывают «Настроен / Не настроен». У сложных терминов (SPF, DMARC, CAA, HSTS, CSP, COOP, CORS, cookie-флагов, TLS и security.txt) есть подсказки при наведении и маленькая SVG-иконка, которая не печатается. `security.txt` перенесён из «Открытых файлов» в карточку технологий.
- **Визуальная иерархия.** Критические находки отмечаются красной полосой слева и красным бейджем, но сохраняют обычный фон карточки; важные — янтарной полосой, информационные WAF/CMS не попадают в список «Что исправить». Карточки появляются с мягкой анимацией, у кнопок есть аккуратный hover; `prefers-reduced-motion` отключает движение.
- **Дизайн-система.** Десять компонентов: кнопка, форма, согласие, статус скана, каркас отчёта, оценка, находки, детали, бейджи и юридические страницы. Всё связано 16 `@import` в `main.css`, без сборщика и без inline-стилей (иначе не пройдёт `style-src 'self'`).
- **Юридические документы.** `/legal.html` и `/privacy.html` с оглавлением: `legal-toc.js` строит его из заголовков разделов, ведёт подсветку через `aria-current="location"` и переносит фокус в раздел при клике. Без JS оглавление скрыто, текст читается линейно. В соглашении есть оговорка про ст. 272 УК РФ и прямое «это не юридическая консультация»; в политике перечислены Render и DNS-резолвер как участники обработки.
- **Доступность.** Skip-link, `aria-describedby` у поля, `aria-invalid` только на том контроле, о котором говорит ошибка, `role="alert"`/`role="status"`, `aria-pressed` у фильтров, кастомный чекбокс поверх нативного `input`, поддержка `prefers-reduced-motion` и `prefers-contrast: more`.
- **Печать.** A4-версия отчёта: `@page`, `print-color-adjust: exact`, `break-inside: avoid`, имя файла `CyberCheck_<host>_<дата>` (небезопасные для имени файла символы, включая `:` у IPv6, заменяются). Печать всегда содержит все находки, даже если на экране включён фильтр.
- **Надёжность.** Единый error handler последним в стеке, JSON-404, `no-store` на `/` и `/api/*` (юридические страницы — `revalidate`), ETag на статике, семафор на 25 одновременных сканов с `Retry-After: 60`, общий таймаут скана 60 с при клиентских 65 с. Обрыв соединения клиентом прерывает скан, а слот семафора освобождается в `finally`; TLS-проверка не тратится на порту 80, а при ошибке заголовков проверяется следующий веб-порт; `Host` собирается с портом для 8080; `unhandledRejection` и `uncaughtException` попадают в лог.
- **Скоринг.** Буква A требует 95+; положительные веса дают ровно 100, старый TLS — отдельный −10; каждая находка получает OWASP-тег, а критические новые проверки имеют жёсткие потолки.
- **Зависимости.** `body-parser` 1.20.9 и `qs` 6.16.1 зафиксированы через `overrides`; CI и Render ставят зависимости с `--ignore-scripts`.

## Что проверяет

| Группа | Проверка | Как |
|---|---|---|
| Порты | 80, 443, 22, 3306, 8080 | TCP-connect, 3 с на весь этап (все попытки вместе), один retry |
| TLS | наличие TLS, валидность, срок, издатель, версия протокола, поддержка TLS 1.0/1.1 | `tls.connect` с `rejectUnauthorized: false` и одним retry; отдельный probe на TLS 1.0/1.1; на 80 TLS не проверяется, на 8080 провал TLS трактуется как HTTP-порт, а не как `ssl-error` |
| Заголовки | `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` | `GET /` по HTTPS (на 443 — всегда, даже если TLS-хендшейк не удался); при ошибке — по HTTP; если порт не ответил, проверяется следующий из 443 → 80 → 8080; тело не скачивается |
| Гигиена | `Server`, фактический протокол (HTTP/HTTPS) | те же заголовки ответа |
| DNS/Email | SPF, DMARC (политика `none` / `quarantine` / `reject`), CAA | `node:dns/promises`: TXT, `_dmarc.<домен>`, CAA; ошибки DNS не роняют скан |
| Cookie | `Secure`, `HttpOnly`, `SameSite` в `Set-Cookie` | значения cookie не сохраняются, только имя и флаги |
| Доп. заголовки | `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` | наличие в ответе |
| Файлы | `/.env`, `/.git/config`, `/.DS_Store`, `/backup.zip` | `HEAD`, таймаут 2 с; `200` с не-HTML содержимым на `.env`/`.git/config`/`backup.zip` — critical, на `.DS_Store` — low; `200 text/html` — SPA-заглушка, не экспозиция; `403` — WAF/запрет, остальное — данные |
| CORS/security.txt | `Access-Control-Allow-Origin: *`, `/.well-known/security.txt` | заголовок корневого ответа и GET security.txt |
| Fingerprint | WAF (Cloudflare, Sucuri, Akamai), CMS (WordPress, Drupal, Joomla, Bitrix) | заголовки/куки и ограниченное тело HTML (до 64 КБ) |
| Оценка | Risk Score 0–100, буква A–F, находки с важностью, рекомендацией и OWASP-тегом | `src/scoring.js`, чистая функция |

Сканируется только корень сайта: путь и нестандартный порт из введённого URL игнорируются. Редиректы не разворачиваются. IPv6-литералы поддерживаются: `URL.hostname` приходит в скобках, сервер снимает их для DNS/отчёта и возвращает скобки только в `Host`/SNI. Если у домена несколько A/AAAA-записей, проверяется до трёх адресов, пока не найдётся узел с открытым веб-портом.

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
| DNS/Email | SPF с рабочим `all` (`-all`/`~all`) | 4 |
| DNS/Email | DMARC `quarantine`/`reject` | 3 |
| DNS/Email | CAA присутствует | 2 |
| Порты | Нет открытых 22/3306 | 10 |
| Порты | Порт 8080 закрыт | 2 |
| Файлы | `/.env` не открыт | 7 |
| Файлы | `/.git/config` не открыт | 4 |
| Файлы | `/backup.zip` не открыт | 2 |
| Файлы | `/.DS_Store` не открыт | 1 |
| security.txt | Проверка не вернула уверенный `404` | 2 |
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

`files.critical` принимается и как массив строк, и как массив `{ path, severity }`; `files.exposed` тоже поддерживается. Для `/.DS_Store` отдельного потолка нет: это low-находка. `403`/`404`/ошибка HEAD и `200 text/html` (SPA-заглушка) не считаются экспозицией и потолок не включают; за `403`, ошибку, редирект и SPA-заглушку баллы не начисляются (отсутствие файла не доказано), а подтверждённый `404` считается отсутствием. Если `files` или `securityTxt` не проверялись (`null`), баллы за них начисляются: отсутствие данных не считается экспозицией. Для `security.txt` штрафует явный `404` и некорректный `200` (нет `Contact`/не `text/plain`); `403`, сетевой сбой и другие статусы нейтральны. При `headers.error` итог всё равно ограничен 60.

**Буквы:** A ≥ 95, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F < 20.

Буква A достижима только при оценке 95+: потолок 90 для находок `medium`/`high` означает, что любая серьёзная находка опускает результат до B.

Сертификат, истекающий в течение 30 дней, даёт находку `ssl-expiring` уровня `low` и не приносит 3 балла. При `daysLeft <= 7` дополнительно включается потолок 90 (B); при 8–30 днях сайт с идеальной гигиеной остаётся A (97).

Если TLS-соединение не установилось, отчёт не утверждает «SSL нет»: приходит `ssl.hasSSL: false`, `ssl.error` (например, `HANDSHAKE_FAILED`), находка `ssl-error` уровня `medium` и потолок 60. `no-ssl` и потолок 30 остаются только для случая, когда TLS действительно не настроен (порт 80/8080 отвечает по HTTP). Карточка TLS в этом случае пишет «Не удалось проверить TLS», а не «SSL не настроен».

Новые проверки дают находки `spf-missing`, `dmarc-missing`/`dmarc-weak`/`dmarc-invalid`, `caa-missing`, `cookie-no-secure`/`cookie-no-httponly`/`cookie-no-samesite`, `no-referrer-policy`/`no-permissions-policy`/`no-coop`, `cors-wildcard`, `exposed-env`/`exposed-git`/`exposed-backup`/`exposed-dsstore`, `security-txt-missing`/`security-txt-invalid`. WAF/CMS — информационные `waf-detected`/`cms-detected` с `weight: 0`.

**Находка (`findings[]`)** — объект с полями `id`, `title`, `desc`, `severity` (`high` / `medium` / `low`), `weight`, `recommendation` и `owasp` (например, `A05:2021 Security Misconfiguration`). Находки сортируются по важности (high → medium → low), внутри уровня — по весу; `severity` управляет цветом и фильтрами. OWASP-тег — маркировка категории, а не заявление о сертификации.

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

В production нужен ещё секрет подписи согласия — без него сервер не стартует:

```bash
npm ci
PUBLIC_ORIGIN=https://cybercheck.example \
CONSENT_SECRET="$(node -e 'console.log(require("node:crypto").randomBytes(32).toString("hex"))')" \
NODE_ENV=production npm start
```

```powershell
# Windows PowerShell
npm ci
$env:PUBLIC_ORIGIN="https://cybercheck.example"
$env:CONSENT_SECRET=(node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))")
$env:NODE_ENV="production"; npm start
```

В development токен подписывается встроенным `dev-secret-do-not-use-in-prod`, поэтому `CONSENT_SECRET` можно не задавать. В `NODE_ENV=production` без секрета процесс завершается с кодом 1: подписывать токены нечем, и fail-closed лучше, чем известный всем dev-секрет на проде.

### Переменные окружения

Шаблон — в [`.env.example`](.env.example). Файл `.env` **не подгружается автоматически**: переменные задаются перед командой запуска или через `node --env-file=.env src/server.js` (Node 20.6+).

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `PORT` | `3000` | Порт HTTP-сервера. Целое 0–65535; иначе процесс завершается с кодом 1 |
| `PUBLIC_ORIGIN` | — | Origin фронтенда для CORS (например, `https://cybercheck.example`). Имеет приоритет над `RENDER_EXTERNAL_URL`; из значения берётся только `origin` |
| `RENDER_EXTERNAL_URL` | — | Подставляется Render автоматически для веб-сервисов; fallback, если `PUBLIC_ORIGIN` не задан |
| `TRUST_PROXY` | `0` | Целое 0–10. `0` — не доверять прокси, `1` — Render. `true`, мусор и значения вне диапазона завершают процесс с кодом 1; при `>0` включается доверие к `X-Forwarded-For` |
| `DEMO_MODE` | `false` | Разрешает сканировать `localhost` и `127.0.0.1`. Только при `NODE_ENV=development` |
| `NODE_ENV` | — | `development` или `production`; `production` кэширует HTML-шаблон и требует `CONSENT_SECRET`, `development` разрешает `DEMO_MODE`; на текст 404 не влияет |
| `CONSENT_SECRET` | `dev-secret-do-not-use-in-prod` (только вне production) | Секрет HMAC-SHA256 для токенов согласия. **Обязателен при `NODE_ENV=production`**, иначе процесс завершается с кодом 1. Смена секрета инвалидирует все выданные токены (TTL 15 минут) |

`PUBLIC_ORIGIN` проверяется на старте: значение парсится как URL и должно иметь схему `http:` или `https:`. `TRUST_PROXY` должен совпадать с числом реальных прокси: при завышенном значении ключ лимита берётся из подставленного `X-Forwarded-For` и окно обходится одним заголовком.

### Режим демонстрации

```bash
PUBLIC_ORIGIN=http://localhost:3000 DEMO_MODE=true NODE_ENV=development npm start
```

`DEMO_MODE` без явного `NODE_ENV=development` останавливает сервер: ошибка конфигурации не открывает доступ к внутренней сети, а закрывает сервис (fail-closed). Демо-режим поддерживает `localhost`, `127.0.0.1` и `::1`; остальные приватные адреса отсекаются.

## API

Один API-маршрут. Аутентификации нет: доступ ограничен лимитом по IP, а запуск скана требует HMAC-токена согласия.

```http
POST /api/scan
Content-Type: application/json

{
  "url": "example.com",
  "consent": true,
  "consentToken": "1793794200000.<HMAC-SHA256-base64url>"
}
```

`consent` должен быть строго `true`. `consentToken` — HMAC-подпись, а не клиентская метка времени: сервер подставляет её в HTML при каждой отдаче страницы (скрытое поле `data-js="consent-token"`, плейсхолдер `__CONSENT_TOKEN__`). Формат — `<issuedAt>.<mac>`, где `issuedAt` — миллисекунды выпуска, а `mac` — `HMAC-SHA256(CONSENT_SECRET, issuedAt)` в base64url. Токен живёт **15 минут**; подпись сверяется через `crypto.timingSafeEqual`, поэтому подделать её без секрета нельзя. Просроченный, отсутствующий или искажённый токен даёт `400 { "error": "Подтверждение устарело или недействительно. Обнови страницу." }`. Токен доказывает только то, что запрос пришёл со страницы, выданной сервером не раньше 15 минут назад; владение доменом он не подтверждает.

Поддерживаются только `http`/`https`; URL длиной до 2048 символов; IDN и завершающая точка нормализуются.

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

Оценка учитывает `dns`, `files`, `securityTxt` и расширенные поля `headers`; `fingerprint` даёт только информационные находки `weight: 0` и score не меняет. Каждая находка содержит `owasp`. Для `files` критичны только `200` с не-HTML содержимым на `/.env`, `/.git/config` и `/backup.zip`; `200 text/html` и `403` не считаются экспозицией.

Дополнительные поля контракта: у `headers` — `hstsState`, `cspState`, `xframeState`, `xcontentState`, `referrerPolicyState`, `permissionsPolicyState`, `coopState` (`ok` / `weak` / `missing`); у `ssl` — `tlsConfirmed`; у `dns.spf` — `multiple` и `weak`; у `dns.dmarc` — `multiple` и `weak`; у `dns.caa` — `restrictive`; у `cookieSummary` — `insecureNone`. Они нужны, чтобы UI отличал «заголовка нет» от «заголовок есть, но защита выключена», и не расходился со скорингом.

Ошибки — всегда JSON `{ "error": "..." }` без стека и внутренних деталей:

| Код | Когда |
|---|---|
| 400 | невалидный `url`, нет согласия, просроченный или поддельный `consentToken`, приватный/неразрешимый адрес, DNS-таймаут, неподдерживаемая схема |
| 413 | тело больше 8 КБ |
| 429 | повторный скан с того же IP раньше чем через 10 секунд; `Retry-After` содержит число секунд |
| 503 | сервер уже ведёт 25 сканирований одновременно; `Retry-After: 60` |
| 504 | скан не уложился в 60 секунд |
| 500 | непредвиденная ошибка; подробности только в серверном логе |

Неизвестные пути отдают `404 { "error": "Не найдено" }`. `GET /healthz` → `{ "ok": true, "uptime": 12.34 }`.

## Тестирование

```bash
npm test
```

Запускается `node --test test/*.test.js` — **215 тестов** в двенадцати файлах:

- `test/net-guard.test.js` — 9 тестов: 20 приватных/служебных адресов блокируются, 4 публичных разрешаются, мусорный ввод блокируется (fail-closed), инъекция резолвера, таймаут и смешанный DNS-ответ.
- `test/scoring.test.js` — 47 тестов: сумма весов 100; `FILE_CHECKS` совпадает с путями HEAD-проб; TLS/SSL, заголовки, порты; потолки `.env`/`.git`/`backup`/CORS; DMARC `p=none`; DNS timeout и `ENODATA`; cookie-флаги; `security.txt` (404 и некорректный 200); WAF/CMS; OWASP-теги у всех находок; сортировка находок.
- `test/checks.test.js` — 12 тестов: `checkPort` на закрытом и открытом порту, дедлайн и отказ от нелитерального `connectIp`, `checkHeaders` (CSP, X-Frame-Options, cookie-флаги, дополнительные заголовки, CORS, weak-значения, IPv6 `Host`), `checkSSL` с `HANDSHAKE_FAILED`, самоподписанным сертификатом и отменённым сигналом.
- `test/dns-security.test.js` — 24 теста: SPF, DMARC (`reject`/`quarantine`/`none`), CAA, IP/localhost, таймауты, DNS-ошибки и abort.
- `test/header-analysis.test.js` — 31 тест: разбор `Set-Cookie`, сводка флагов, Referrer-Policy/Permissions-Policy/COOP, CSP с permissive-источниками, ACAO `*`, WAF (Cloudflare/Sucuri/Akamai), CMS (WordPress/Drupal/Joomla/Bitrix), отсутствие ReDoS на ~58 КБ `<meta>`-текста.
- `test/web-probes.test.js` — 12 тестов: HEAD-пробы (200/403/404/301), `security.txt`, фингерпринт, Host/connectIp, таймаут, abort и частичное тело.
- `test/scan-helpers.test.js` — 22 теста: `parseTarget`, `normalizeHostname`, `hostHeaderFor`, `rateKey`, бюджеты и дедлайны, `selectWebPorts`, `withCriticalFiles`, `buildReport`, `isHtmlRequestPath` (включая NTFS ADS и обратные слэши), `isLiteralIp`.
- `test/rate-limit.test.js` — 10 тестов: кулдаун, LRU, sweep, потолок одновременных сканов, лишний `finish`, таймер чистки.
- `test/report-model.test.js` — 25 тестов: `sanitizeText`, критичность путей, `filesNote`, `tlsNotice`, `caaState`, `secureContextState`, склонения, имя отчёта и `buildShareText`.
- `test/frontend-contract.test.js` — 7 тестов: нормализация `owasp`/новых полей в `api/client.js`, мусорные `score`/`grade`/`ports`, сетевые ошибки, SVG-иконка подсказки, ENOTFOUND для SPF, безопасный DOM и экспорты `ui/render-result.js`.
- `test/server.test.js` — 4 теста: запуск с `TRUST_PROXY=0`; ключ лимита берётся из реального IP прокси, а не из подставленного `X-Forwarded-For`; при `trustProxy=0` заголовок игнорируется полностью; сервер отклоняет скан с поддельным токеном согласия.
- `test/server-http.test.js` — 12 тестов: `/healthz`, HTML с подставленным `BASE_URL` и security-заголовками, защита от шаблонов в статике, редирект `/index.html`, 400/415/413, 404 для неизвестного `/api/scan/*`, кулдаун 429, CORS и JSON-404.

Не покрыто: `checkOldTls`/`supportsOldTls` (нужен TLS-стенд), 503/504, интеграция оркестрации скана в `core/server.js`, DOM-рендер карточек и печать, retry `checkHeaders`. `createApp()` уже экспортируется, поэтому HTTP-слой можно тестировать через supertest без запуска процесса. Как это закрыть — в [архитектуре](docs/architecture.md).

CI (`.github/workflows/ci.yml`, Node 24) на каждый push и PR: `npm ci --ignore-scripts` → `npm audit --audit-level=high --omit=dev` → проверка загрузки probe-модулей → `node --check` для `src/server.js` и `core/{config,server}.js` → рекурсивный разбор модулей фронтенда через `vm.SourceTextModule` → `npm test` → запуск сервера и smoke-проверка `/`.

## Деплой на Render

### Вариант 1. Blueprint

В репозитории есть [`render.yaml`](render.yaml): web-сервис, план `starter`, `npm ci --ignore-scripts` / `npm start`, health-check `/healthz`, `NODE_ENV=production`, `TRUST_PROXY=1` и `CONSENT_SECRET` с `generateValue: true` — Render создаёт секрет сам.

1. Render → **New** → **Blueprint** → выбрать репозиторий.
2. Render читает `render.yaml` и создаёт сервис. `PUBLIC_ORIGIN` в blueprint не задан намеренно: Render сам передаёт `RENDER_EXTERNAL_URL` (например, `https://cybercheck.onrender.com`), и `server.js` использует её как fallback.
3. После первого деплоя проверить `/healthz` и один скан.

Если `PUBLIC_ORIGIN` задан, он имеет приоритет над `RENDER_EXTERNAL_URL`. `generateValue` срабатывает при **создании** сервиса: если сервис уже существует, добавьте `CONSENT_SECRET` вручную в *Environment* и сделайте redeploy, иначе процесс завершится с кодом 1.

> **Свой домен.** `RENDER_EXTERNAL_URL` — это всегда `*.onrender.com`. Если привязан кастомный домен, браузер отправляет `Origin: https://ваш-домен`, а CORS разрешает только onrender-адрес → API вернёт CORS-ошибку. В этом случае **обязательно** задайте `PUBLIC_ORIGIN=https://ваш-домен` и сделайте redeploy. Поддерживается только один origin.

### Вариант 2. Вручную

- Build: `npm ci --ignore-scripts`, Start: `npm start`
- Env: `NODE_ENV=production`, `PUBLIC_ORIGIN=https://<service>.onrender.com`, `TRUST_PROXY=1`, `CONSENT_SECRET=<случайные 32 байта в hex>` — без него сервер не стартует
- Health Check Path: `/healthz`
- План: **Starter**. На Free инстанс засыпает, первый скан после простоя может занять 30–50 с; клиентский таймаут — 65 с, ретрая нет.

### Проверка после деплоя

```bash
curl -s https://<service>.onrender.com/healthz
curl -s -o /dev/null -w "%{http_code}\n" https://<service>.onrender.com/
TOKEN=$(curl -s https://<service>.onrender.com/ \
  | grep -o 'data-js="consent-token" value="[^"]*"' \
  | sed 's/.*value="//;s/"$//')
curl -s -X POST https://<service>.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"example.com\",\"consent\":true,\"consentToken\":\"$TOKEN\"}"
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
│       │   ├── app.js              # контроллер формы, состояние, копирование
│       │   ├── api/
│       │   │   └── client.js       # fetch + AbortController (65 с) + нормализация
│       │   ├── ui/
│       │   │   ├── render-result.js # рендер отчёта через DOM API/textContent
│       │   │   ├── report-model.js  # чистые функции отчёта и текст для буфера
│       │   │   └── legal-toc.js     # оглавление юридических страниц + scroll-spy
│       └── screenshots/
│           └── og-cover.png        # OG-обложка
├── src/                            # Серверная часть
│   ├── server.js                   # точка входа: readConfig() + startServer()
│   ├── scoring.js                  # Risk Score и findings (чистая функция)
│   ├── core/
│   │   ├── config.js               # PUBLIC_ORIGIN, PORT, TRUST_PROXY, DEMO_MODE
│   │   ├── server.js               # Express, страницы, лимит, маршрут /api/scan
│   │   ├── net-guard.js            # SSRF-защита: isPublicIp, resolvePublicIps
│   │   └── file-paths.js           # общий список путей и критических файлов
│   ├── probes/
│   │   ├── ports.js                # TCP-проверка пяти портов
│   │   ├── tls.js                  # сертификат, версия TLS, TLS 1.0/1.1
│   │   ├── http-headers.js         # заголовки ответа, cookie-флаги, CORS
│   │   ├── header-analysis.js      # разбор Set-Cookie, WAF/CMS-эвристики
│   │   ├── dns-security.js         # SPF, DMARC, CAA
│   │   └── web-probes.js           # HEAD-файлы, security.txt, fingerprint
│   └── utils/
│       ├── scan-helpers.js         # parseTarget, бюджеты, buildReport
│       └── rate-limit.js           # кулдаун, семафор, LRU
├── test/                           # 12 тестовых файлов + fixtures/tls
│   ├── net-guard.test.js           # 9 тестов SSRF-классификации
│   ├── scoring.test.js             # 47 тестов скоринга
│   ├── checks.test.js              # 12 тестов: порты, TLS, заголовки
│   ├── dns-security.test.js        # 24 теста SPF/DMARC/CAA
│   ├── header-analysis.test.js     # 31 тест cookie/заголовков/WAF/CMS
│   ├── web-probes.test.js          # 12 тестов HEAD/security.txt/fingerprint
│   ├── scan-helpers.test.js        # 22 теста бюджета и сборки отчёта
│   ├── rate-limit.test.js          # 10 тестов лимитов
│   ├── report-model.test.js        # 25 тестов модели отчёта
│   ├── frontend-contract.test.js   # 7 тестов нормализации и DOM
│   ├── server.test.js              # 4 теста: запуск, XFF, токен согласия
│   ├── server-http.test.js         # 12 тестов HTTP-слоя
│   └── fixtures/tls/self-signed.js # сертификат для тестов TLS
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
- **Валидация URL** — только `http`/`https`, длина ≤ 2048, hostname ≤ 253, IDN/punycode, снятие завершающей точки и скобок IPv6, приватные адреса — через SSRF-контур.
- **Нет эксплуатации** — TCP-connect, TLS-хендшейк (включая probe TLS 1.0/1.1), чтение заголовков и ограниченного тела HTML (до 64 КБ для фингерпринта), HEAD-пробы четырёх путей и GET `security.txt`. Это не фаззинг и не подбор.
- **SSRF новых проб** — HEAD-файлы, `security.txt`, CORS и фингерпринт подключаются только к `connectIp`; `hostname` используется лишь в `Host` и TLS SNI. DNS-запросы SPF/DMARC/CAA идут к резолверу и не открывают сокет на цель.
- **XSS** — рендер только через `textContent`/DOM API, `innerHTML` не используется; строгий CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Токен согласия (HMAC)** — страница получает `<issuedAt>.<HMAC-SHA256(issuedAt)>` в base64url; сервер проверяет подпись через `crypto.timingSafeEqual` и TTL 15 минут. Голый `{"consent": true}` без токена отклоняется 400-й. Секрет — `CONSENT_SECRET`, обязателен в production. В production кэшируется только HTML-шаблон, а токен подставляется на каждый ответ: закэшированный токен истёк бы через 15 минут после старта и сломал бы все сканы до перезапуска.
- **ReDoS** — данные цели разбираются за линейное время: `hasGeneratorMeta()` ищет `<meta>` без регулярок с вложенными квантификаторами, длина значений заголовков (`Server`, `issuer`) ограничена 120 символами, тело фингерпринта — 64 КБ. Тест на ~58 КБ «ядовитого» HTML требует меньше 500 мс.
- **Ошибки** — единый обработчик, наружу только обобщённый JSON, стек — в серверный лог.
- **CORS** — один явный origin, без `*`.
- **Лимит тела** — 8 КБ; **таймауты** — 60 с на весь скан, 2–5 с на отдельные сетевые операции, 65 с на клиенте, 40 с на graceful shutdown.
- **Кэширование** — `/` и `/api/*` отдаются с `no-store`: результат скана не оседает ни в браузере, ни в промежуточном кэше. Статика наоборот перепроверяется по ETag и отвечает 304.
- **Ретраи** — порты, TLS и заголовки повторяются один раз; это может означать более одного запроса к цели.
- **Ключ лимита** — берётся из правого элемента `X-Forwarded-For` (его дописывает наш прокси), а не из левого, который контролирует клиент; при `TRUST_PROXY=0` заголовок игнорируется полностью.
- **Один секрет** — `CONSENT_SECRET` для подписи токенов; внешних API, БД и аккаунтов нет; `.env` в `.gitignore`.

Подробности и модель угроз — в [docs/architecture.md](docs/architecture.md). Порядок сообщения об уязвимостях — в [.github/SECURITY.md](.github/SECURITY.md).

## Ограничения

1. **Лимит частоты — best effort.** 10 секунд на IP (IPv6 — на подсеть `/64`), карта в памяти процесса, `MAX_KEYS = 10 000`, LRU; фоновая чистка раз в 30 секунд, поэтому запись может жить до ~30 секунд. Обходится распределённым источником или `/48`. N реплик = N лимитов. Потолок одновременных сканов есть — 25 на процесс, сверх этого 503, — но глобального лимита по суммарной нагрузке нет. Отдельно: `TRUST_PROXY` должен совпадать с числом реальных прокси (допустимо 0–10); при завышенном значении ключ лимита берётся из подставленного `X-Forwarded-For` и окно обходится одним заголовком.
2. **Согласие не проверяет владение доменом.** Нужны `consent: true` и валидный `consentToken`: подпись HMAC-SHA256 сверяется через `timingSafeEqual`, просроченный (старше 15 минут) и поддельный токен дают 400. Но токен лишь подтверждает, что запрос пришёл со страницы сканера не раньше 15 минут назад: любой, кто открыл страницу, получает рабочий токен, поэтому доказательством прав на домен это не является. Verification не реализован; токен не привязан к сессии или IP и переиспользуется в пределах TTL.
3. **Редиректы не разворачиваются.** Если 443 закрыт, а 80 отдаёт 301 на HTTPS, в отчёт попадут заголовки редиректа, а не сайта.
4. **IPv6 без zone-id.** `http://[2606:4700::1111]` поддерживается, но link-local с zone-id (`fe80::1%eth0`) — нет: URL-парсер и `net.isIP` такой литерал не принимают. Для `DEMO_MODE` разрешены `localhost`, `127.0.0.1` и `::1`.
5. **Скан ограничен.** Пять фиксированных портов, `GET /`, только корень сайта. Путь и нестандартный порт (`:8443`) из URL игнорируются; поддомены не перебираются. Из DNS-ответа проверяется до трёх адресов; в отчёте не указано, какой именно IP проверялся, и при нескольких A-записях описывается один узел.
6. **TLS 1.0/1.1 — детект, а не гарантия.** `checkOldTls` может дать ложное отрицание, если OpenSSL/сборка Node запрещает TLS 1.0/1.1 на своём уровне. Шифры и цепочка сертификатов не проверяются. Основное TLS-соединение допускает TLS 1.0, чтобы прочитать сертификат старого сервера. На медленном TLS возможен race с 5-секундным таймаутом (см. architecture).
7. **Таймаут скана — 60 с.** Один веб-порт укладывается примерно в 13 с: до 3 с на TCP-этап, до 5 с на TLS (включая `checkOldTls`) и до 5 с на заголовки; плюс общие DNS/веб-пробы. Перебор трёх веб-портов вместе с пробами может превысить 60 с — такая цель обрывается 504-й. Graceful shutdown ждёт 40 с, но Render может прислать SIGKILL раньше; клиентский таймаут — 65 с.
8. **Нет истории, БД, аккаунтов, API-ключей и share-ссылок.** PDF — диалог печати браузера (`window.print()`): печатается шапка отчёта, но нет обложки, отдельного логотипа и нумерации страниц.
9. **PII в логах.** Hostname и IP клиента пишутся в stdout; ротации и TTL нет. `privacy.html` описывает это поведение, но для 152-ФЗ нужна отдельная юридическая проработка.
10. **Оценка — эвристика.** A не означает «сайт безопасен». Порог A = 95, а любая находка `medium`/`high` ограничивает оценку 90 (B), поэтому сайт без одного заголовка уже не получит A; старый TLS специально ограничен 85 (B). Сертификат, истекающий через ≤7 дней, ограничен 90 (B); при 8–30 днях находка `ssl-expiring` остаётся `low` и букву не меняет. Risk Score не заменяет аудит.
11. **Один origin в CORS.** Мультидомен (apex + www, кастомный домен) не поддерживается.
12. **`npm audit` в CI** может «покраснеть» на новом CVE и заблокировать несвязанный PR.
13. **OG-превью статичное.** Обложка раздаётся с того же origin (`/assets/screenshots/og-cover.png`), `canonical` и `og:url` заданы на всех трёх страницах. Генерации превью под конкретный отчёт нет — одна картинка на весь сайт.
14. **Политика приватности есть** (`privacy.html`), но это описание фактического поведения сервиса, а не юридически выверенный документ. Для B2B по 152-ФЗ нужна отдельная проработка: согласие на обработку, сроки хранения, ответственное лицо.
15. **Нужен современный браузер.** `:has()` (подсветка строки согласия), `conic-gradient` (кольцо оценки) и `100dvh` есть в Chrome 108+, Safari 15.4+, Firefox 121+. В старых браузерах деградация мягкая: скан и отчёт работают, подсветка согласия и `dvh` — нет.
16. **DNS/email — по точному hostname.** SPF/CAA запрашиваются для введённого домена, DMARC — `_dmarc.<hostname>`. Для `www.example.com` запись `_dmarc.example.com` не подставляется; сканируйте apex, если нужна зона целиком.
17. **HEAD-проба — только четыре пути.** `200` с не-HTML содержимым на `/.env`, `/.git/config` или `/backup.zip` даёт critical и потолок 40/50/50; `/.DS_Store` — low. `200 text/html` распознаётся как SPA-заглушка и не считается экспозицией, но catch-all с другим Content-Type всё ещё может дать ложное срабатывание. `403` трактуется как WAF/запрет и не является уязвимостью. Ответы `301/302/401/405` — только данные.
18. **Фингерпринт — эвристика.** WAF определяется по заголовкам/кукам (Cloudflare, Sucuri, Akamai), CMS — по кукам/meta/HTML (WordPress, Drupal, Joomla, Bitrix). Кастомные сборки, закрытый бэкенд и сжатый/бинарный ответ могут не определиться; тело читается не больше 64 КБ.
19. **CORS проверяется по корню.** `Access-Control-Allow-Origin: *` смотрится в ответе `/`; отдельные API-эндпоинты не обходятся.
20. **Копирование отчёта требует защищённого контекста.** `navigator.clipboard.writeText` доступен на HTTPS или `localhost`. На HTTP-стенде кнопка не падает, а честно сообщает, что браузер не дал доступ к буферу; текст отчёта при этом остаётся на экране.

## Roadmap

- **2.3.0** — глобальный rate-limit, verification домена, мультидомен в CORS, PostgreSQL, история, API-ключи, share-ссылки, тесты 503/504 и DOM-рендера.
- **Дальше** — дополнительные модули для пентеста: TLS-шифры и цепочка, cookie/CORS-политики, DNS/email, утечки, fingerprinting.

## Disclaimer

См. [DISCLAIMER.md](./DISCLAIMER.md).

## License

MIT — см. [LICENSE](./LICENSE).
