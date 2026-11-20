# CyberCheck

![version](https://img.shields.io/badge/version-2.3.0-blue)
![tests](https://img.shields.io/badge/tests-296%20passed-brightgreen)
![node](https://img.shields.io/badge/node-22%E2%80%9324-339933)
![license](https://img.shields.io/badge/license-MIT-green)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF)

> ⚠️ **ВНИМАНИЕ!** Инструмент предназначен только для тестирования собственных систем или систем, на которые у вас есть официальное письменное разрешение. Несанкционированное сканирование чужих доменов может быть нарушением закона (**ст. 272 УК РФ**). Автор не несёт ответственности за использование инструмента третьими лицами.

---

CyberCheck — сканер внешней безопасности веб-сайта. Проверяет доступность пяти портов, TLS-сертификат и его версию, security-заголовки и cookie-флаги, SPF/DMARC/CAA, GET-пробы типовых файлов утечки с проверкой сигнатур содержимого, `security.txt`, CORS и WAF/CMS-признаки, а затем превращает результат в **Risk Score** (0–100, A–F) со списком находок и рекомендаций. Написан на Node.js + Express, фронтенд — vanilla JS без сборки. Отчёт открывается прямо в браузере: кольцо оценки, вердикт словами, карточки находок и детали проверки — и печатается в A4. Скан запускается только с короткоживущим HMAC-токеном согласия (15 минут), который страница получает при загрузке.

Документация: [архитектура и модель угроз](docs/architecture.md) · [политика безопасности](.github/SECURITY.md) · [DISCLAIMER](DISCLAIMER.md).

**Текущая версия: 2.3.0.**

Что нового в 2.3.0:

- **Доказательные проверки.** Файлы утечки читаются `GET` с проверкой сигнатуры содержимого: `KEY=VALUE` для `/.env`, `[core]` для `/.git/config`, ZIP-магия для `/backup.zip`, магия формата для `/.DS_Store`. `200` без сигнатуры — `NO_SIGNATURE` («не проверено»), а не экспозиция. `security.txt` читается до 32 КБ, обрезанное тело — отдельное состояние `TRUNCATED`, а не «файла нет».
- **Клоакинг.** Веб-порт, который ответил заголовками, опрашивается дважды — браузерным `User-Agent` и `CyberCheck/<version>`. Если набор security-заголовков, cookie или CORS отличается, появляется находка `cloaking-detected` (`high`, `weight: 0`) и потолок 90.
- **HSTS и HTTP→HTTPS.** 8 баллов HSTS разделены: 5 — за заголовок, 3 — за подтверждённый `301/308` с открытого HTTP на HTTPS. Подтверждённое отсутствие редиректа даёт `no-http-redirect` (`high`); если порт 80 не проверялся, баллы не снимаются.
- **CSP и кликджекинг.** Несколько одноимённых заголовков разбираются как отдельные политики, CSP в `<meta http-equiv>` учитывается, `frame-ancestors` закрывает кликджекинг без `X-Frame-Options`.
- **DNS/email, порты, TLS.** SPF `redirect=` считается рабочей политикой; DMARC `reject`/`quarantine` при `pct < 100` даёт `dmarc-partial`; пробы портов различают `open`/`refused`/`filtered`/`closed`; `supportsOldTls` может быть `null` — «не проверено», а не «отключено».
- **Устойчивость сервера.** Строгая валидация `NODE_ENV`, предупреждение о dev-секрете, таймауты сокетов, `maxConnections = 4096`, лимит 64 сокета на IP при прямом доступе и потолок 2 скана на сокет-адрес против подмены `X-Forwarded-For`.
- **Тесты.** 296 тестов в 13 файлах. `npm test` идёт через `scripts/run-tests.js` (один процесс, без `spawn`), классический прогон с изоляцией — `npm run test:isolated`; добавлен исполняемый DOM-тест рендера.

Ключевые возможности:

- **Сканер.** Пять портов, TLS и версия протокола, security-заголовки и cookie-флаги, SPF/DMARC/CAA, файлы утечки, `security.txt`, CORS и WAF/CMS-признаки — в одном отчёте с **Risk Score** (0–100, A–F), находками, рекомендациями и OWASP-тегами.
- **Интерфейс.** Отчёт-«приборная панель»: кольцо оценки, вердикт словами, фильтры «Все / Критичные / Важные / Замечания», карточки деталей, копирование сводки; рендер только через DOM API и `textContent`.
- **Человеческий язык и доступность.** SPF/DMARC/CAA формулируются словами, у сложных терминов есть подсказки; skip-link, `aria-*`, кастомный чекбокс, `prefers-reduced-motion` и `prefers-contrast: more`.
- **Печать и юридические страницы.** A4-версия с именем `CyberCheck_<host>_<дата>`; `/legal.html` и `/privacy.html` с оглавлением; в соглашении — ст. 272 УК РФ и оговорка «это не юридическая консультация».
- **Безопасность и зависимости.** SSRF-инвариант (подключение только по проверенному IP), HMAC-токен согласия, строгий CSP без `unsafe-inline`, `no-store` на `/` и `/api/*`; четыре runtime-зависимости, `body-parser`/`qs` зафиксированы через `overrides`, CI и Render ставят их с `--ignore-scripts`.

## Что проверяет

| Группа | Проверка | Как |
|---|---|---|
| Порты | 80, 443, 22, 3306, 8080 | TCP-connect, 3 с на весь этап (все попытки вместе), один retry. Состояния пробы: `open` — соединение прошло, `refused` — RST, `filtered` — таймаут/DROP (состояние не измерено), `closed` — локальный отказ. В ответе `ports` — только открытые порты |
| TLS | наличие TLS, валидность, срок, издатель, версия протокола, поддержка TLS 1.0/1.1 | `tls.connect` с `rejectUnauthorized: false` и одним retry; отдельный probe на TLS 1.0/1.1 (`supportsOldTls` может быть `null` — проверка не выполнена); на 80 TLS не проверяется, на 8080 провал TLS трактуется как HTTP-порт, а не как `ssl-error` |
| Заголовки | `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` | `GET /` по HTTPS (на 443 — всегда, даже если TLS-хендшейк не удался); при ошибке — по HTTP; если порт не ответил, проверяется следующий из 443 → 80 → 8080. Same-origin редиректы (301/302/303/307/308) преследуются до 3 хопов. Тело читается до 64 КБ только чтобы увидеть CSP в `<meta http-equiv>`; повторяющиеся CSP/XFO/Referrer-Policy/Permissions-Policy разбираются как отдельные политики; `frame-ancestors` засчитывается вместо `X-Frame-Options` |
| HTTP→HTTPS | подтверждённый редирект с открытого HTTP на HTTPS | отдельный `GET /` по HTTP на порт 80 при живом TLS; редиректом считается только `3xx` с `Location: https://…`; подтверждённое отсутствие даёт находку `no-http-redirect` |
| Клоакинг | совпадение ответа браузеру и сканеру | второй `GET /` на веб-порт, давший успешные заголовки, с `User-Agent: CyberCheck/<version>`; сравниваются security-заголовки, cookie и CORS. Отличие — находка `cloaking-detected` (`high`) |
| Гигиена | `Server`, фактический протокол (HTTP/HTTPS) | те же заголовки ответа |
| DNS/Email | SPF (включая `redirect=`), DMARC (`none` / `quarantine` / `reject`, `pct`), CAA | `node:dns/promises`: TXT, `_dmarc.<домен>`, CAA; ошибки DNS не роняют скан |
| Cookie | `Secure`, `HttpOnly`, `SameSite` в `Set-Cookie` | значения cookie не сохраняются, только имя и флаги |
| Доп. заголовки | `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` | наличие в ответе |
| Файлы | `/.env`, `/.git/config`, `/.DS_Store`, `/backup.zip` | `GET`, таймаут 2 с, тело до 4 КБ; экспозиция подтверждается только сигнатурой содержимого: `KEY=VALUE` для `.env`, `[core]` для `.git/config`, ZIP-магия для `backup.zip`, магия `.DS_Store`. `200` без сигнатуры — «не проверено» (`NO_SIGNATURE`), а не экспозиция; `403` — WAF/запрет |
| CORS/security.txt | `Access-Control-Allow-Origin: *`, `/.well-known/security.txt` | заголовок корневого ответа и GET security.txt |
| Fingerprint | WAF (Cloudflare, Sucuri, Akamai), CMS (WordPress, Drupal, Joomla, Bitrix) | заголовки/куки и ограниченное тело HTML (до 64 КБ) |
| Оценка | Risk Score 0–100, буква A–F, находки с важностью, рекомендацией и OWASP-тегом | `src/scoring.js`, чистая функция |

Сканируется только корень сайта: путь и нестандартный порт из введённого URL игнорируются. Преследуются только same-origin редиректы (тот же хост, схема и порт) — до 3 хопов; переход на другой origin, схему или порт не выполняется, поэтому `http://` → `https://` редирект заголовками не разворачивается. IPv6-литералы поддерживаются: `URL.hostname` приходит в скобках, сервер снимает их для DNS/отчёта и возвращает скобки только в `Host`/SNI. Если у домена несколько A/AAAA-записей, проверяется до трёх адресов, пока не найдётся узел с открытым веб-портом.

## Risk Score

Оценка считается на сервере в `src/scoring.js` и приходит в ответе полями `score`, `grade`, `findings`.

**Веса (сумма положительных — ровно 100):**

| Блок | Проверка | Баллы |
|---|---|---:|
| TLS | Валидный TLS-сертификат | 12 |
| TLS | До истечения сертификата больше 30 дней | 3 |
| TLS | **Поддержка TLS 1.0/1.1** | **−10 (штраф сверх 100)** |
| Заголовки | `Strict-Transport-Security` (только при валидном TLS) | 5 |
| Заголовки | Подтверждённый редирект HTTP→HTTPS (только при валидном TLS) | 3 |
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
| security.txt | Найден или не проверен (не `404` и не некорректный `200`) | 2 |
| **Итого** | | **100** |

Три балла за редирект HTTP→HTTPS начисляются, если редирект подтверждён **или** порт 80 не удалось проверить (закрыт/фильтруется): штраф снимается только когда 80 ответил без `3xx` на `https://`. DMARC `quarantine`/`reject` при `pct < 100` даёт 2 из 3 и находку `dmarc-partial`.

**Жёсткие потолки** — применяются после суммирования, итог — минимум из суммы и всех подошедших ограничений:

| Условие | Максимум |
|---|---:|
| `files.critical`/`exposed` содержит `/.env` | **40 (D)** |
| `files.critical`/`exposed` содержит `/.git/config` | **50 (D)** |
| `files.critical`/`exposed` содержит `/backup.zip` | **50 (D)** |
| `headers.corsWildcard === true` | **60 (C)** |
| Не удалось проверить заголовки (`headers.error`) или корневой ответ `>= 300` | 60 |
| Ошибка TLS (`ssl.error`), кроме случая `ssl.tlsConfirmed === true` | 60 |
| TLS не проверялся: 443 не ответил (`ssl.tlsChecked === false`) | 60 |
| HTTPS отсутствует | 30 |
| Сертификат невалиден/просрочен | 40 |
| Открыт порт 3306 | 70 |
| Поддержка TLS 1.0/1.1 | 85 (B — не A) |
| Сертификат истекает через ≤ 7 дней | 90 (B — не A) |
| Любая находка `medium` или `high` | 90 (B — не A) |

`files.critical` принимается и как массив строк, и как массив `{ path, severity }`; `files.exposed` тоже поддерживается. Для `/.DS_Store` отдельного потолка нет: это low-находка. Экспозиция подтверждается только совпадением содержимого с сигнатурой; `200` без сигнатуры даёт `error: "NO_SIGNATURE"` и не считается ни открытием, ни закрытием (баллы за путь не начисляются). `403`/`404`/ошибка пробы не считаются экспозицией и потолок не включают; за `403`, ошибку, редирект и заглушку баллы не начисляются (отсутствие файла не доказано), а подтверждённый `404` считается отсутствием. Если `files` или `securityTxt` не проверялись (`null`), баллы за них начисляются: отсутствие данных не считается экспозицией. Для `security.txt` штрафует явный `404` и некорректный `200` (нет `Contact`/не `text/plain`); `403`, сетевой сбой, оборванное по лимиту тело (`TRUNCATED`) и другие статусы нейтральны. При `headers.error` или ответе `>= 300` итог ограничен 60.

**Буквы:** A ≥ 95, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F < 20.

Буква A достижима только при оценке 95+: потолок 90 для находок `medium`/`high` означает, что любая серьёзная находка опускает результат до B.

Сертификат, истекающий в течение 30 дней, даёт находку `ssl-expiring` уровня `low` и не приносит 3 балла. При `daysLeft <= 7` дополнительно включается потолок 90 (B); при 8–30 днях сайт с идеальной гигиеной остаётся A (97).

Если TLS-соединение не установилось, отчёт не утверждает «SSL нет»: приходит `ssl.hasSSL: false`, `ssl.error` (например, `HANDSHAKE_FAILED`), находка `ssl-error` уровня `medium` и потолок 60. `no-ssl` и потолок 30 остаются только для случая, когда TLS действительно не настроен (порт 80/8080 отвечает по HTTP). Карточка TLS в этом случае пишет «Не удалось проверить TLS», а не «SSL не настроен». Если порт 443 не ответил (таймаут/фильтр), TLS не проверялся: приходит `ssl.tlsChecked: false`, находка `tls-not-checked` уровня `medium` и потолок 60 — «SSL не настроен» и потолок 30 остаются только для доказанного отсутствия TLS.

Новые проверки дают находки `cloaking-detected`, `no-http-redirect`, `no-https-first`, `old-tls-unchecked`, `headers-not-checked`/`headers-unavailable`, `dmarc-partial`, `spf-missing`, `dmarc-missing`/`dmarc-weak`/`dmarc-invalid`, `caa-missing`, `cookie-no-secure`/`cookie-no-httponly`/`cookie-no-samesite`, `no-referrer-policy`/`no-permissions-policy`/`no-coop`, `cors-wildcard`, `exposed-env`/`exposed-git`/`exposed-backup`/`exposed-dsstore`, `security-txt-missing`/`security-txt-invalid`. `cloaking-detected`, `old-tls-unchecked` и `headers-not-checked` имеют `weight: 0`, но `cloaking-detected` — `high`, поэтому включает общий потолок 90. WAF/CMS — информационные `waf-detected`/`cms-detected` с `weight: 0`.

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
| `NODE_ENV` | — | `development`, `production` или `test`; любое другое непустое значение — процесс завершается с кодом 1. `production` кэширует HTML-шаблон и требует `CONSENT_SECRET`, `development` разрешает `DEMO_MODE` и встроенный dev-секрет |
| `CONSENT_SECRET` | `dev-secret-do-not-use-in-prod` (только вне production) | Секрет HMAC-SHA256 для токенов согласия. **Обязателен при `NODE_ENV=production`**, иначе процесс завершается с кодом 1. Смена секрета инвалидирует все выданные токены (TTL 15 минут) |

`PUBLIC_ORIGIN` проверяется на старте: значение парсится как URL и должно иметь схему `http:` или `https:`. `TRUST_PROXY` должен совпадать с числом реальных прокси: при завышенном значении ключ лимита берётся из подставленного `X-Forwarded-For` и окно обходится одним заголовком. `NODE_ENV` тоже валидируется: неизвестное значение (например, `staging`) — ошибка конфигурации. Если `NODE_ENV` задан и отличается от `development`, а `CONSENT_SECRET` не задан, сервер печатает предупреждение: токены подписываются публичным dev-секретом.

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
    "status": 200,
    "location": null,
    "server": "nginx/1.18.0",
    "csp": true,
    "cspFrameAncestors": true,
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
    "error": null,
    "truncated": false
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

Пример сокращён: в реальном ответе `files.results` содержит все четыре пути, `headers` — состояния `*State`, а `findings` — все находки.

Оценка учитывает `dns`, `files`, `securityTxt` и расширенные поля `headers` (включая `status`, `location` и `cspFrameAncestors`); `fingerprint` даёт только информационные находки `weight: 0` и score не меняет. Каждая находка содержит `owasp`. Файл утечки считается открытым только когда `200` и содержимое совпало с сигнатурой (`KEY=VALUE` для `/.env`, `[core]` для `/.git/config`, ZIP-магия для `/backup.zip`, магия `.DS_Store`). `200` без сигнатуры — `error: "NO_SIGNATURE"`: путь не подтверждён ни как открытый, ни как закрытый, баллы за него не начисляются.

Дополнительные поля контракта: у `headers` — `status`, `location`, `hstsState`, `cspState`, `xframeState`, `xcontentState`, `referrerPolicyState`, `permissionsPolicyState`, `coopState` (`ok` / `weak` / `missing`), `cspFrameAncestors`; у `ssl` — `tlsConfirmed`, `tlsChecked` (`false` — 443 не ответил, TLS не проверялся) и `supportsOldTls` (`true` / `false` / `null` — не проверено); у `securityTxt` — `truncated`; у `dns.spf` — `multiple` и `weak`; у `dns.dmarc` — `multiple`, `pct`, `partial`, `pctInvalid`, `strict`, `weak`; у `dns.caa` — `restrictive`; у `cookieSummary` — `insecureNone`. В массиве `ports` есть только открытые порты (`status: "open"`): `refused`/`filtered`/`closed` — внутренние состояния пробы и в ответ не попадают. `httpRedirectsToHttps` (`true` / `false` / `null`) и признак клоакинга — входные данные скоринга, а не поля ответа: наружу они видны как находки `no-http-redirect` и `cloaking-detected`. Эти поля нужны, чтобы UI отличал «заголовка нет» от «заголовок есть, но защита выключена» и «проверить не удалось», и не расходился со скорингом.

Ошибки — всегда JSON `{ "error": "..." }` без стека и внутренних деталей:

| Код | Когда |
|---|---|
| 400 | невалидный `url`, нет согласия, просроченный или поддельный `consentToken`, приватный/неразрешимый адрес, DNS-таймаут, неподдерживаемая схема |
| 413 | тело больше 8 КБ |
| 429 | повторный скан с того же IP раньше чем через 10 секунд **или** с одного сокет-адреса уже идут 2 скана; `Retry-After` содержит число секунд |
| 503 | сервер уже ведёт 25 сканирований одновременно; `Retry-After: 60` |
| 504 | скан не уложился в 60 секунд |
| 500 | непредвиденная ошибка; подробности только в серверном логе |

Неизвестные пути отдают `404 { "error": "Не найдено" }`. `GET /healthz` → `{ "ok": true, "uptime": 12.34 }`.

## Тестирование

```bash
npm test
```

Запускается `npm test` → `node scripts/run-tests.js` — **296 тестов** в тринадцати файлах. Скрипт подключает файлы по очереди в одном процессе: `node --test` поднимает отдельный процесс на каждый файл, и там, где создание процессов запрещено (песочницы, Windows AppContainer), весь набор падал бы с `spawn EPERM`, хотя тесты рабочие. Классический прогон с изоляцией — `npm run test:isolated`.

- `test/net-guard.test.js` — 9 тестов: 20 приватных/служебных адресов блокируются, 4 публичных разрешаются, мусорный ввод блокируется (fail-closed), инъекция резолвера, таймаут и смешанный DNS-ответ.
- `test/scoring.test.js` — 67 тестов: сумма весов 100; `FILE_CHECKS` совпадает с путями файловых проб; TLS/SSL, заголовки, порты; потолки `.env`/`.git`/`backup`/CORS; HSTS 5+3 и редирект HTTP→HTTPS; `filtered`-порт не даёт баллов; `supportsOldTls: null` и `daysLeft: NaN`; `tlsChecked === false` → `tls-not-checked`; `status ≥ 300` — «не проверено»; DMARC `p=none` и `pct < 100`; DNS timeout и `ENODATA`; cookie-флаги; `security.txt` (404, некорректный и оборванный 200); `200` без сигнатуры файла; `frame-ancestors` вместо XFO; клоакинг доходит до оценки через `buildReport`; заморозка `WEIGHTS`; WAF/CMS; OWASP-теги; сортировка находок.
- `test/checks.test.js` — 19 тестов: `checkPort` с состояниями `open`/`refused`/`filtered`, дедлайн и отказ от нелитерального `connectIp`, `checkHeaders` (CSP, X-Frame-Options, cookie-флаги, дополнительные заголовки, CORS, weak-значения, IPv6 `Host`, несколько CSP-заголовков, CSP в `<meta>`, `frame-ancestors`, таймаут тела, same-origin редирект), `checkSSL` с точными кодами `HANDSHAKE_FAILED`/`TIMEOUT`/`ABORTED` и поведенческими проверками вместо замеров времени.
- `test/dns-security.test.js` — 29 тестов: SPF (включая `redirect=`), DMARC (`reject`/`quarantine`/`none`, `pct`), CAA, IP/localhost, таймауты, DNS-ошибки и abort.
- `test/header-analysis.test.js` — 42 теста: разбор `Set-Cookie`, сводка флагов, Referrer-Policy/Permissions-Policy/COOP, CSP с permissive-источниками, несколько одноимённых заголовков, CSP из `<meta>`, `frame-ancestors`, ACAO `*`, WAF (Cloudflare/Sucuri/Akamai), CMS (WordPress/Drupal/Joomla/Bitrix), отсутствие ReDoS на ~58 КБ `<meta>`-текста.
- `test/web-probes.test.js` — 20 тестов: GET-пробы файлов с сигнатурами содержимого (200/403/404/301), `security.txt` (включая обрезку тела), фингерпринт, браузерный `User-Agent`, Host/connectIp, same-origin и запрет cross-origin редиректов, лимит в три хопа, таймаут, abort и частичное тело.
- `test/scan-helpers.test.js` — 23 теста: `parseTarget`, `normalizeHostname`, `hostHeaderFor`, `rateKey`, бюджеты и дедлайны, `selectWebPorts`, `withCriticalFiles`, `buildReport`, `isHtmlRequestPath` (включая NTFS ADS и обратные слэши), `isLiteralIp`.
- `test/rate-limit.test.js` — 17 тестов: кулдаун, LRU, sweep, потолок одновременных сканов, лимит на сокет-адрес (`maxPerEdge`) и его освобождение, лишний `finish`, таймер чистки.
- `test/report-model.test.js` — 25 тестов: `sanitizeText`, критичность путей, `filesNote`, `tlsNotice`, `caaState`, `secureContextState`, склонения, имя отчёта и `buildShareText`.
- `test/frontend-contract.test.js` — 12 тестов: поведенческий контракт `scanTarget` (dns/files/securityTxt/fingerprint доходят до рендера), настоящий `import()` модулей и их экспорты, нормализация `owasp`/новых полей, мусорные `score`/`grade`/`ports`, сетевые ошибки, SVG-иконка подсказки, ENOTFOUND для SPF, вызовы решений CAA/TLS, отсутствие HTML-синков и инлайн-скриптов на страницах.
- `test/render-dom.test.js` — 1 тест: исполняемый DOM-стенд, который рендерит отчёт с XSS-payload во всех полях и проверяет, что HTML-синки не вызывались, а payload остался текстом.
- `test/server.test.js` — 11 тестов: запуск с `TRUST_PROXY=0` в процессе (без `spawn`); ключ лимита берётся из реального IP прокси, а не из подставленного `X-Forwarded-For`; при `trustProxy=0` заголовок игнорируется полностью; сервер отклоняет скан с поддельным токеном согласия; валидация `NODE_ENV`/`PORT`/`TRUST_PROXY`; `redirectsToHttps`.
- `test/server-http.test.js` — 17 тестов: `/healthz`, HTML с подставленным `BASE_URL` и security-заголовками, защита от шаблонов в статике, редирект `/index.html`, 400/415/413, 404 для неизвестного `/api/scan/*`, кулдаун 429, CORS и JSON-404; точные директивы CSP (без `unsafe-inline`/`unsafe-eval`/`*`) и `upgrade-insecure-requests` в production; таймауты и потолки сокетов; лимит 64 сокета на IP при прямом доступе.

Не покрыто: `checkOldTls` (нужен TLS-стенд со старым протоколом), 503/504, интеграция оркестрации скана в `core/server.js`, печать отчёта, retry `checkHeaders`. `createHttpServer()` и `applySocketLimits()` экспортируются, поэтому HTTP-слой тестируется в процессе без запуска сервера. Как это закрыть — в [архитектуре](docs/architecture.md).

CI (`.github/workflows/ci.yml`, Node 24) на каждый push и PR: `npm ci --ignore-scripts` → `npm audit --audit-level=high --omit=dev` → проверка загрузки probe-модулей → `node --check` для `src/server.js` и `core/{config,server}.js` → рекурсивный разбор модулей фронтенда через `vm.SourceTextModule` → проверка реальных экспортов `api/client.js` через `import()` → `npm test` → запуск сервера и smoke-проверка `/`.

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
│   ├── architecture.md             # Архитектура, контракт скоринга, модель угроз
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
│   │   ├── config.js               # PUBLIC_ORIGIN, PORT, TRUST_PROXY, DEMO_MODE, NODE_ENV
│   │   ├── server.js               # Express, страницы, лимит, маршрут /api/scan
│   │   ├── net-guard.js            # SSRF-защита: isPublicIp, resolvePublicIps
│   │   └── file-paths.js           # общий список путей и критических файлов
│   ├── probes/
│   │   ├── ports.js                # TCP-проверка пяти портов
│   │   ├── tls.js                  # сертификат, версия TLS, TLS 1.0/1.1
│   │   ├── http-headers.js         # заголовки ответа, cookie-флаги, CORS
│   │   ├── header-analysis.js      # разбор Set-Cookie, WAF/CMS-эвристики
│   │   ├── dns-security.js         # SPF, DMARC, CAA
│   │   └── web-probes.js           # GET-пробы файлов, security.txt, fingerprint
│   └── utils/
│       ├── scan-helpers.js         # parseTarget, бюджеты, buildReport
│       └── rate-limit.js           # кулдаун, семафор, LRU
├── scripts/
│   └── run-tests.js                # npm test: общий процесс без spawn
├── test/                           # 13 тестовых файлов, setup-env.js и fixtures/tls
│   ├── net-guard.test.js           # 9 тестов SSRF-классификации
│   ├── scoring.test.js             # 66 тестов скоринга
│   ├── checks.test.js              # 19 тестов: порты, TLS, заголовки
│   ├── dns-security.test.js        # 29 тестов SPF/DMARC/CAA
│   ├── header-analysis.test.js     # 42 теста cookie/заголовков/WAF/CMS
│   ├── web-probes.test.js          # 20 тестов GET-проб/security.txt/fingerprint
│   ├── scan-helpers.test.js        # 23 теста бюджета и сборки отчёта
│   ├── rate-limit.test.js          # 17 тестов лимитов
│   ├── report-model.test.js        # 25 тестов модели отчёта
│   ├── frontend-contract.test.js   # 12 тестов контракта и экспортов
│   ├── render-dom.test.js          # 1 исполняемый DOM-тест рендера
│   ├── server.test.js              # 11 тестов: запуск, XFF, конфиг, токен
│   ├── server-http.test.js         # 17 тестов HTTP-слоя и CSP
│   ├── setup-env.js                # NODE_ENV/CONSENT_SECRET до загрузки тестов
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
- **Нет эксплуатации** — TCP-connect, TLS-хендшейк (включая probe TLS 1.0/1.1), чтение заголовков и ограниченного тела HTML (до 64 КБ для фингерпринта и meta-CSP), GET-пробы четырёх путей с чтением до 4 КБ и GET `security.txt`. Это не фаззинг и не подбор.
- **SSRF новых проб** — пробы файлов, `security.txt`, CORS и фингерпринт подключаются только к `connectIp`; `hostname` используется лишь в `Host` и TLS SNI. Same-origin редиректы повторяются тем же сокетом и не требуют нового резолва; переход на другой origin не выполняется. DNS-запросы SPF/DMARC/CAA идут к резолверу и не открывают сокет на цель.
- **XSS** — рендер только через `textContent`/DOM API, `innerHTML` не используется; строгий CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Токен согласия (HMAC)** — страница получает `<issuedAt>.<HMAC-SHA256(issuedAt)>` в base64url; сервер проверяет подпись через `crypto.timingSafeEqual` и TTL 15 минут. Голый `{"consent": true}` без токена отклоняется 400-й. Секрет — `CONSENT_SECRET`, обязателен в production. В production кэшируется только HTML-шаблон, а токен подставляется на каждый ответ: закэшированный токен истёк бы через 15 минут после старта и сломал бы все сканы до перезапуска.
- **ReDoS** — данные цели разбираются за линейное время: `hasGeneratorMeta()` ищет `<meta>` без регулярок с вложенными квантификаторами, длина значений заголовков (`Server`, `issuer`) ограничена 120 символами, тело фингерпринта — 64 КБ. Тест на ~58 КБ «ядовитого» HTML требует меньше 500 мс.
- **Ошибки** — единый обработчик, наружу только обобщённый JSON, стек — в серверный лог.
- **CORS** — один явный origin, без `*`.
- **Лимит тела** — 4 КБ на файловую пробу, 32 КБ на `security.txt`, 64 КБ на фингерпринт и meta-CSP, 8 КБ на тело API-запроса; **таймауты** — 60 с на весь скан, 2–5 с на отдельные сетевые операции, 65 с на клиенте, 40 с на graceful shutdown.
- **Кэширование** — `/` и `/api/*` отдаются с `no-store`: результат скана не оседает ни в браузере, ни в промежуточном кэше. Статика наоборот перепроверяется по ETag и отвечает 304.
- **Ретраи** — порты, TLS и заголовки повторяются один раз; это может означать более одного запроса к цели.
- **Сокеты и DoS** — `headersTimeout` 10 с, `requestTimeout` 15 с, `keepAliveTimeout` 5 с, `maxConnections = 4096`, `maxRequestsPerSocket = 100`. При прямом доступе (`TRUST_PROXY=0`) — не больше 64 одновременных сокетов с одного IP; сверх лимита сокет уничтожается.
- **Ключ лимита** — берётся из правого элемента `X-Forwarded-For` (его дописывает наш прокси), а не из левого, который контролирует клиент; при `TRUST_PROXY=0` заголовок игнорируется полностью. Дополнительно считается сокет-адрес: не больше 2 одновременных сканов с одного edge-сокета, что закрывает исчерпание пула подменным `X-Forwarded-For`.
- **Один секрет** — `CONSENT_SECRET` для подписи токенов; внешних API, БД и аккаунтов нет; `.env` в `.gitignore`.

Подробности и модель угроз — в [docs/architecture.md](docs/architecture.md). Порядок сообщения об уязвимостях — в [.github/SECURITY.md](.github/SECURITY.md).

## Ограничения

1. **Лимит частоты — best effort.** 10 секунд на IP (IPv6 — на подсеть `/64`), карта в памяти процесса, `MAX_KEYS = 10 000`, LRU; фоновая чистка раз в 30 секунд, поэтому запись может жить до ~30 секунд. Обходится распределённым источником или `/48`. N реплик = N лимитов. Потолок одновременных сканов есть — 25 на процесс, сверх этого 503, — но глобального лимита по суммарной нагрузке нет. Дополнительно действует потолок 2 скана на сокет-адрес: он закрывает обход пула подменным `X-Forwarded-For` при прямом доступе, но за общим прокси (Render) сокет-адрес — это адрес edge, поэтому там лимит фактически ограничивает общую параллельность двумя сканами. Отдельно: `TRUST_PROXY` должен совпадать с числом реальных прокси (допустимо 0–10); при завышенном значении ключ лимита берётся из подставленного `X-Forwarded-For` и окно обходится одним заголовком.
2. **Согласие не проверяет владение доменом.** Нужны `consent: true` и валидный `consentToken`: подпись HMAC-SHA256 сверяется через `timingSafeEqual`, просроченный (старше 15 минут) и поддельный токен дают 400. Но токен лишь подтверждает, что запрос пришёл со страницы сканера не раньше 15 минут назад: любой, кто открыл страницу, получает рабочий токен, поэтому доказательством прав на домен это не является. Verification не реализован; токен не привязан к сессии или IP и переиспользуется в пределах TTL.
3. **Преследуются только same-origin редиректы.** Заголовки читаются с конечного same-origin ответа (до 3 хопов: тот же хост, схема и порт). Если 443 закрыт, а 80 отдаёт `301` на `https://`, меняются схема и порт — такой редирект не разворачивается, и в отчёт попадут заголовки редиректа, а не сайта.
4. **IPv6 без zone-id.** `http://[2606:4700::1111]` поддерживается, но link-local с zone-id (`fe80::1%eth0`) — нет: URL-парсер и `net.isIP` такой литерал не принимают. Для `DEMO_MODE` разрешены `localhost`, `127.0.0.1` и `::1`.
5. **Скан ограничен.** Пять фиксированных портов, `GET /`, только корень сайта. Путь и нестандартный порт (`:8443`) из URL игнорируются; поддомены не перебираются. Из DNS-ответа проверяется до трёх адресов; в отчёте не указано, какой именно IP проверялся, и при нескольких A-записях описывается один узел.
6. **TLS 1.0/1.1 — детект, а не гарантия.** `checkOldTls` может дать ложное отрицание, если OpenSSL/сборка Node запрещает TLS 1.0/1.1 на своём уровне. Шифры и цепочка сертификатов не проверяются. Основное TLS-соединение допускает TLS 1.0, чтобы прочитать сертификат старого сервера. На медленном TLS возможен race с 5-секундным таймаутом (см. architecture); если бюджета не хватило, приходит `supportsOldTls: null` и находка `old-tls-unchecked`, а не ложное «отключено».
7. **Таймаут скана — 60 с.** Один веб-порт укладывается примерно в 18 с: до 3 с на TCP-этап, до 5 с на TLS (включая `checkOldTls`), до 5 с на заголовки и ещё до 5 с на контрольный запрос клоакинга. Проверка редиректа на порту 80 добавляет до 5 с. Перебор трёх веб-портов вместе с пробами может превысить 60 с — такая цель обрывается 504-й. Graceful shutdown ждёт 40 с, но Render может прислать SIGKILL раньше; клиентский таймаут — 65 с.
8. **Нет истории, БД, аккаунтов, API-ключей и share-ссылок.** PDF — диалог печати браузера (`window.print()`): печатается шапка отчёта, но нет обложки, отдельного логотипа и нумерации страниц.
9. **PII в логах.** Hostname и IP клиента пишутся в stdout; ротации и TTL нет. `privacy.html` описывает это поведение, но для 152-ФЗ нужна отдельная юридическая проработка.
10. **Оценка — эвристика.** A не означает «сайт безопасен». Порог A = 95, а любая находка `medium`/`high` ограничивает оценку 90 (B), поэтому сайт без одного заголовка уже не получит A; старый TLS специально ограничен 85 (B). Сертификат, истекающий через ≤7 дней, ограничен 90 (B); при 8–30 днях находка `ssl-expiring` остаётся `low` и букву не меняет. Risk Score не заменяет аудит.
11. **Один origin в CORS.** Мультидомен (apex + www, кастомный домен) не поддерживается.
12. **`npm audit` в CI** может «покраснеть» на новом CVE и заблокировать несвязанный PR.
13. **OG-превью статичное.** Обложка раздаётся с того же origin (`/assets/screenshots/og-cover.png`), `canonical` и `og:url` заданы на всех трёх страницах. Генерации превью под конкретный отчёт нет — одна картинка на весь сайт.
14. **Политика приватности есть** (`privacy.html`), но это описание фактического поведения сервиса, а не юридически выверенный документ. Для B2B по 152-ФЗ нужна отдельная проработка: согласие на обработку, сроки хранения, ответственное лицо.
15. **Нужен современный браузер.** `:has()` (подсветка строки согласия), `conic-gradient` (кольцо оценки) и `100dvh` есть в Chrome 108+, Safari 15.4+, Firefox 121+. В старых браузерах деградация мягкая: скан и отчёт работают, подсветка согласия и `dvh` — нет.
16. **DNS/email — по точному hostname.** SPF/CAA запрашиваются для введённого домена, DMARC — `_dmarc.<hostname>`. Для `www.example.com` запись `_dmarc.example.com` не подставляется; сканируйте apex, если нужна зона целиком.
17. **Файловая проба — только четыре пути.** Экспозиция подтверждается сигнатурой содержимого: `/.env` (`KEY=VALUE`), `/.git/config` (`[core]`), `/backup.zip` (ZIP-магия), `/.DS_Store` (магия). Подтверждённый `/.env`/`/.git/config`/`/backup.zip` даёт critical и потолок 40/50/50, `/.DS_Store` — low. `200` без сигнатуры — `NO_SIGNATURE`: баллы за путь не начисляются, но и находки нет; `403` трактуется как WAF/запрет. Ответы `301/302/401/405` — только данные (same-origin редиректы при этом преследуются).
18. **Фингерпринт — эвристика.** WAF определяется по заголовкам/кукам (Cloudflare, Sucuri, Akamai), CMS — по кукам/meta/HTML (WordPress, Drupal, Joomla, Bitrix). Кастомные сборки, закрытый бэкенд и сжатый/бинарный ответ могут не определиться; тело читается не больше 64 КБ.
19. **CORS проверяется по корню.** `Access-Control-Allow-Origin: *` смотрится в ответе `/`; отдельные API-эндпоинты не обходятся.
20. **Копирование отчёта требует защищённого контекста.** `navigator.clipboard.writeText` доступен на HTTPS или `localhost`. На HTTP-стенде кнопка не падает, а честно сообщает, что браузер не дал доступ к буферу; текст отчёта при этом остаётся на экране.
21. **Клоакинг — только по заголовкам.** Сравниваются security-заголовки, cookie и CORS ответов браузерному и сканерному `User-Agent`; различия в теле, контенте или статусе не анализируются. Основные пробы идут с браузерным `User-Agent` Chrome, а `CyberCheck/<version>` используется только в контрольном запросе: в логах цели обычные пробы выглядят как браузер.

## Roadmap

- **2.3.0 (текущая)** — доказательные файловые пробы по сигнатурам, клоакинг, HSTS 5+3 с проверкой редиректа, CSP из `<meta>` и `frame-ancestors`, DMARC `pct`, состояния портов, устойчивость сокетов; 296 тестов.
- **2.4.0** — глобальный rate-limit, verification домена, мультидомен в CORS, PostgreSQL, история, API-ключи, share-ссылки, тесты 503/504.
- **Дальше** — дополнительные модули для пентеста: TLS-шифры и цепочка, cookie/CORS-политики, DNS/email, утечки, fingerprinting.

## Disclaimer

См. [DISCLAIMER.md](./DISCLAIMER.md).

## License

MIT — см. [LICENSE](./LICENSE).
