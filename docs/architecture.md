# Архитектура CyberCheck

Документ отвечает на вопрос «как это устроено и почему именно так». Он не заменяет `README.md` (запуск, переменные, деплой) и `.github/SECURITY.md` (порядок сообщения об уязвимостях).

**Кодовые ориентиры:** `src/server.js` (точка входа), `src/core/{config,server,net-guard,file-paths}.js`, `src/probes/{ports,tls,http-headers,dns-security,header-analysis,web-probes}.js`, `src/utils/{scan-helpers,rate-limit}.js`, `src/scoring.js`, `public/assets/js/{app.js,api/client.js,ui/*}`, `test/*.test.js` — около 8 000 строк вместе с CSS, разметкой, тестами и фронтенд-скриптами.

> **Соглашение о ссылках.** Ссылки указывают на **функции и маркеры** в коде, а не на номера строк: номера устаревают от любой вставки, а имена — нет. Ищите `isPublicIp`, `resolvePublicIps`, `calculateScore`, `checkOldTls`, `createApp`, `startServer` или маркеры `Сначала валидация`, `Лимит частоты`, `Логируем ПОСЛЕ валидации`.

---

## 1. Назначение и границы

**Что делает:** по запросу `hostname` проверяет доступность пяти портов (`80, 443, 22, 3306, 8080`), читает TLS-сертификат на найденном веб-порту, определяет версию TLS и поддержку TLS 1.0/1.1, наличие security-заголовков и cookie-флагов, SPF/DMARC/CAA, HEAD-пробы файлов утечки, `security.txt`, CORS `*` и WAF/CMS-фингерпринт, затем считает Risk Score. Возвращает JSON `{host, ports, ssl, headers, dns, files, securityTxt, fingerprint, score, grade, findings}`.

**Чего не делает:**

* не эксплуатирует уязвимости и не аутентифицируется на цели;
* не аутентифицирует пользователей — API публичный;
* не хранит результаты (ни БД, ни файлов, ни кэша);
* не проверяет владение доменом (согласие — только фиксация намерения);
* не сканирует пути и нестандартные порты (`https://site:8443/admin` проверяется как `https://site/` на 80/443/8080);
* не разворачивает редиректы;
* не поддерживает IPv6-литералы — отклоняет их на валидации;
* не проверяет шифры и цепочку сертификатов (только leaf-сертификат и версию протокола).

Тело ответа не скачивается для обычных проверок заголовков; только `checkFingerprint()` читает не больше 64 КБ HTML для CMS-признаков и сразу уничтожает ответ после лимита.

---

## 2. Компоненты

```
┌──────────────────┐
│     Браузер      │  public/index.html
│    (vanilla)     │  assets/js/app.js → api/client.js → ui/render-result.js
│                  │  fetch("/api/scan")
└────────┬─────────┘
         │ POST /api/scan {url, consent, consentTimestamp}
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Express (src/core/server.js)                                │
│  helmet → cors → express.json(8kb) → pages → static         │
│                              │                              │
│                    POST /api/scan                           │
│                    ├─ валидация URL                          │
│                    ├─ protocol / hostname / domainRegex      │
│                    ├─ rateKey + cooldown (in-memory Map)    │
│                    ├─ console.log (hostname, ip)            │
│                    ├─ resolvePublicIps(host)                │
│                    ├─ checkPort ×5 / checkSSL / checkHeaders│
│                    ├─ checkDnsSecurity / web-probes.js       │
│                    └─ buildReport() → calculateScore()      │
│                              ▼                              │
│                    res.json({ …, score, grade, findings })  │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
                  ┌──────────────────┐   ┌──────────────────┐
                  │ core/net-guard.js│   │ probes/ports.js  │
                  │ resolvePublicIps │   │ probes/tls.js    │
                  │ isPublicIp       │   │ http-headers.js  │
                  └────────┬─────────┘   └────────┬─────────┘
                           │ dns.resolve4/6       │ TCP / TLS / HTTP
                           ▼                      ▼
                    ┌─────────────┐        ┌─────────────┐
                    │ DNS         │        │ Цель (сайт) │
                    └─────────────┘        └─────────────┘

  Ошибки ──→ единый error handler ──→ JSON без стека
  Неизвестный путь ──→ JSON 404
  Отчёт ──→ src/scoring.js (чистая функция) ──→ score/grade/findings
```

**Ключевые модули:**

| Модуль | Отвечает за | Не отвечает за |
|---|---|---|
| `core/config.js` | чтение и строгая проверка `PUBLIC_ORIGIN`, `PORT`, `TRUST_PROXY`, `DEMO_MODE`, `NODE_ENV` | маршруты, сеть |
| `core/server.js` | сборка Express (`createApp`), страницы, CORS, лимит, валидация URL, маршрут `/api/scan`, 404, запуск (`startServer`) | сетевые проверки, расчёт оценки |
| `core/net-guard.js` | решение «можно ли подключаться к этому хосту» | подключение |
| `core/file-paths.js` | единый список путей HEAD-проб и критических файлов | сами пробы |
| `probes/ports.js` | TCP-проверка пяти портов, retry в бюджете этапа | TLS, HTTP |
| `probes/tls.js` | TLS-сертификат, версия протокола, `checkOldTls` | заголовки, оценка |
| `probes/http-headers.js` | заголовки ответа, `Set-Cookie`, CORS, retry | DNS, файлы |
| `probes/header-analysis.js` | чистый разбор `Set-Cookie`, security-заголовков, ACAO `*`, WAF/CMS-эвристики | сеть, I/O |
| `probes/dns-security.js` | SPF, DMARC, CAA через `node:dns/promises` | HTTP/TCP-подключение к цели |
| `probes/web-probes.js` | HEAD-файлы, `security.txt`, фингерпринт; запросы только на `connectIp` | оценка, рендер |
| `utils/scan-helpers.js` | `parseTarget`, `rateKey`, бюджеты/дедлайны, `selectWebPorts`, `buildReport` | сеть, Express |
| `utils/rate-limit.js` | кулдаун, семафор, LRU-чистка | HTTP-ответы |
| `scoring.js` | Risk Score и находки по готовому отчёту | сеть, I/O, состояние |
| `public/assets/js/api/client.js` | fetch, таймаут 65 с, нормализация ответа | DOM |
| `public/assets/js/ui/*` | модель отчёта, рендер через DOM API, фильтры, печать, оглавление | решения о безопасности |

---

## 3. Путь запроса

| # | Шаг | Где искать | Что даёт |
|---|---|---|---|
| 1 | Валидация конфигурации (`PUBLIC_ORIGIN` / `RENDER_EXTERNAL_URL`) | `core/config.js` → `readConfig()` / `readOrigin()` | парсинг URL + схема; иначе `exit(1)` |
| 2 | `TRUST_PROXY` | `core/config.js` → `readTrustProxy()`; `core/server.js` → `app.set("trust proxy", …)` | целое 0–10; `0` — не доверять, `true`/мусор — `exit(1)` |
| 3 | Helmet + CSP | `core/server.js` → `createApp()` / `helmet({ … })` | XSS-защита, запрет фреймов, `no-referrer` |
| 4 | CORS | `core/server.js` → `cors({ origin: [publicOrigin] })` | только один origin |
| 5 | JSON 8 КБ | `core/server.js` → `express.json({ limit: "8kb" })` | 413 вместо стека |
| 6 | Страницы и статика | `core/server.js` → `pageHtml()` + `express.static(…)` | три HTML с подставленным BASE_URL и файлы `public/` |
| 7 | Валидация входа | `core/server.js` → маршрут `/api/scan` | `url` строкой, ≤ 2048; `consent === true`; timestamp в окне 15 мин назад / 1 мин вперёд |
| 8 | `new URL()` + схема | `utils/scan-helpers.js` → `parseTarget()` | только `http:`/`https:`; `ftp://` отклоняется |
| 9 | Hostname | `.toLowerCase().replace(/\.$/, "")`, длина ≤ 253, `net.isIP` + `domainRegex` | IDN/punycode, trailing dot, IPv4; IPv6-литералы — 400 |
| 10 | Семафор и лимит частоты | `utils/rate-limit.js` → `activeScans` (503), затем `CooldownGate.wait()` (429) | 503 и 429 до сети; 503 не сжигает 10 секунд |
| 11 | Лог | комментарий «Логируем ПОСЛЕ валидации» | после проверок — log injection невозможен |
| 12 | `resolvePublicIps` | `core/net-guard.js` | решение об SSRF |
| 13 | Порты → TLS → заголовки | `probes/ports.js`, `probes/tls.js`, `probes/http-headers.js`; fallback 443 → 80 → 8080, до трёх IP | скан |
| 14 | DNS/email + HTTP-пробы | `probes/dns-security.js` + `probes/web-probes.js`; HEAD/GET только на `connectIp` | `dns`, `files`, `securityTxt`, `fingerprint` |
| 15 | `buildReport` | `utils/scan-helpers.js` → `buildReport(host, ports, ssl, headers, extra)` | единая сборка + `calculateScore` |
| 16 | Ответ / 404 / ошибка | `res.json`, error handler, JSON-404 | без внутренних деталей; `no-store` на `/` и `/api/*`, `revalidate` для legal/privacy |

**Бюджет времени (худший сценарий):**

| Этап | Максимум |
|---|---|
| DNS-разрешение (входит в общий лимит) | до **5 с** |
| Порты (5 параллельно, один IP) | 3 с + 0,5 с + 3 с = **6,5 с** |
| Перебор IP (до трёх) | до **19,5 с**, если ни у одного нет веб-порта |
| TLS | main 5 с + retry 0,5 с + 5 с = **10,5 с**; успешный `checkOldTls` добавляет **3 с**, итого до **13,5 с** |
| Заголовки | HTTPS 5 + HTTP 5 + 1 + HTTPS 5 + HTTP 5 = **21 с** |
| Один веб-порт целиком | **до 34,5 с** |
| DNS/email (3 запроса параллельно) | до **3 с** |
| HEAD-файлы (4 параллельно) + security.txt + fingerprint | до **4 с** (2 с на попытку, с fallback на 443) |
| Три веб-порта последовательно | теоретически **> 100 с** |
| Фактический лимит скана (`withTimeout`) | **60 с** → 504 |

На 80 порту TLS не проверяется (`{ hasSSL: false }`), на 8080 провал TLS трактуется как HTTP-порт (без `ssl-error`). Если TLS на порту не поднялся, HTTPS-попытка пропускается (`hasTls`), и худший случай для заголовков — 11 с вместо 21. Исключение — порт 443: там HTTPS пробуется всегда (`hasTls || port === 443`), иначе медленный или неудачный хендшейк давал бы ложное «заголовки недоступны» на самом обычном TLS-сайте.

DNS-разрешение входит в те же 60 с: `withTimeout` запускается до `resolvePublicIps`, а его сигнал прерывает и DNS-ожидание. Клиентский таймаут — **65 с** (`TIMEOUT_MS` в `api/client.js`). Graceful shutdown — **40 с** (`core/server.js`), но Render может прислать SIGKILL раньше. Серверный лимит (60 с) сознательно меньше клиентского: 504 должен успеть дойти до браузера. Перебор трёх «молчащих» веб-портов вместе с пробами в 60 с может не уложиться — такая цель обрывается 504-й.

**`NO_WEB_PORT`.** Если ни один из портов 80/443/8080 не открыт, TLS и HTTP-пробы не запускаются: отчёт получает `ssl: {hasSSL:false, error:"NO_WEB_PORT"}`, `files/securityTxt/fingerprint: null`, а DNS-проверки всё равно досчитываются. Скоринг показывает `tls-not-checked` (`weight: 0`) вместо `no-ssl` и не применяет потолок 30 — иначе недоступный хост выглядел бы как сайт без HTTPS.

При fallback ошибка TLS с 443 не затирается успехом на 80: `bestSsl` обновляется только если у него ещё нет ни `hasSSL`, ни `error`. Валидный сертификат с 443 сохраняется, а `ssl-error` не превращается в «Нет SSL».

---

## 4. Модель доверия

| Субъект / данные | Доверяем? | Обоснование |
|---|---|---|
| `req.body` (url, consent, timestamp) | ❌ | валидируется; `consent` — только намерение |
| `req.ip` | ⚠️ условно | при `TRUST_PROXY=0` — адрес сокета; при `>0` — `X-Forwarded-For`, только за реальным прокси. В лог попадает лишь валидный IP (`net.isIP`), иначе `unknown` |
| DNS-ответ | ❌ | проверяются все адреса; смешанный ответ — отказ |
| `connectIp` | ✅ | подключаемся к проверенному IP, не к имени |
| Сертификат цели | ❌ | читается с `rejectUnauthorized:false`; валидность — по `authorizationError` |
| Заголовки цели | ❌ | извлекаются `Server`, security-заголовки, ACAO и `Set-Cookie`; значения cookie наружу не отдаются, только имя и флаги |
| Тело HTML цели | ❌ | читается не больше 64 КБ только для CMS-признаков; не исполняется и не сохраняется |
| DNS-записи (SPF/DMARC/CAA) | ❌ | парсятся как текст, ошибки/таймауты возвращаются данными, не роняют скан |
| `report` для скоринга | ❌ | `scoring.js` не ходит в сеть и не выполняет код; получает `dns/files/headers/...` как данные |
| Конфигурация (env) | ✅ в пределах процесса | `PUBLIC_ORIGIN`/`RENDER_EXTERNAL_URL`, `TRUST_PROXY`, `DEMO_MODE`, `NODE_ENV`, `PORT` |

---

## 5. Ключевой инвариант SSRF-защиты

1. **Резолв:** `dns.resolve4` и `dns.resolve6` параллельно (c-ares, не `getaddrinfo`) — все адреса.
2. **Проверка всех:** `if (!ips.every(isPublicIp)) return []` — хотя бы один приватный → отказ целиком.
3. **Подключение по проверенному IP:** `connectIp = resolvedIps[0]`, при неудаче перебираются до трёх адресов; hostname — только в `Host` и SNI.
4. **Новые HTTP-пробы:** HEAD-файлы, `security.txt`, фингерпринт и корневой CORS-ответ используют тот же `connectIp`; `probes/web-probes.js` не вызывает `fetch(hostname)` и не резолвит имя повторно. SPF/DMARC/CAA — это запросы к DNS-резолверу, а не сокет на цель, поэтому `connectIp` к ним не применяется.

**Почему закрыт DNS rebinding:** между проверкой и подключением нет повторного резолва. Даже если A-запись сменится, соединение пойдёт на проверенный IP.

**Классификация** — аллоулист `ipaddr.js.range() === "unicast"`. Блокируются private, loopback, link-local, CGNAT, ULA, multicast, 6to4, Teredo, NAT64, IPv4-mapped, `::/96`; нераспознанный ввод — fail closed.

**Чего схема не закрывает:** NAT64/DNS64 с нестандартным префиксом (нужен сетевой egress-фильтр) и публичные чужие цели (правовой, не технический вопрос).

**Ограничение выбора адреса.** Проверяются до трёх адресов из DNS-ответа (IPv4-адреса сортируются вперёд), пока не найдётся узел с открытым веб-портом. Если все три недоступны, отчёт описывает последний узел с открытыми портами. В ответе нет поля `ip`, поэтому при нескольких A-записях нельзя понять, какой именно узел проверен; перебор всех адресов умножал бы время скана.

---

## 6. Демо-режим и fail-closed

`DEMO_MODE=true` разрешает обойти SSRF-фильтр для `localhost`/`127.0.0.1` — единственная такая ветка. Включение защищено двумя условиями:

```
DEMO_MODE === "true"  И  NODE_ENV === "development"   →  работаем
иначе (если DEMO_MODE)                                 →  process.exit(1)
```

Логика инвертирована: при незаданном `NODE_ENV` демо-режим не включается, а сервер останавливается. IPv6-литералы, включая `::1`, отсекаются на валидации hostname; для демонстрации доступны только `localhost` и `127.0.0.1`.

---

## 7. Лимит частоты

```
rateKey(req.ip) → IPv4-mapped → IPv4
                → IPv6 → /64
                → невалидный → "unknown"
CooldownGate.entries: Map<key, timestamp>   TTL 10 с, чистка раз в 30 с, MAX_KEYS 10 000, LRU
```

Лимит списывается **после** валидации URL и hostname. Невалидные имена окно не занимают; невалидный IP попадает в общий бакет `"unknown"`; IPv6 нормализуется до `/64`, чтобы смена младших 64 бит не давала нового окна.

Что лимит **не** обещает:

* не защищает от `/48` или ботнета;
* не глобальный: N реплик = N лимитов;
* не ограничивает запросы, отвалившиеся на валидации;
* уязвим к неверному `TRUST_PROXY`;
* списывается до DNS-резолва (опечатка стоит 10 с).

Для публичного запуска нужен внешний лимит (`express-rate-limit` + Redis) — семафор ниже остаётся последней линией.

**Семафор параллельных сканов.** Отдельно от лимита частоты: `activeScans` в памяти процесса, потолок `MAX_CONCURRENT_SCANS = 25`. Сверх потолка — `503 { error: "Сервис занят…" }` с `Retry-After: 60`. Проверка потолка стоит **до** списания cooldown: ответ 503 не блокирует клиента на 10 секунд. Счётчик увеличивается один раз и уменьшается в `finally`, то есть на любом исходе.

Обрыв соединения клиентом не освобождает слот «вхолостую»: на `res.on("close")` срабатывает собственный `AbortController`, его сигнал объединяется с внутренним таймером через `AbortSignal.any`, и `checkPort`/`checkSSL`/`checkHeaders`/`web-probes` прекращают работу сразу, а не через 60 с. DNS-ожидание тоже прерывается по этому сигналу. Это защита от исчерпания дескрипторов, а не от нагрузки как таковой: 25 сканов × (до 3 IP × 5 портов + TLS + probe TLS 1.0/1.1 + HTTP-пробы с retry) даёт несколько сотен одновременных сокетов к целям. Лимит на IP от этого не спасает — он обходится сменой адреса.

---

## 8. Обработка ошибок и 404

Единый обработчик — `app.use((err, req, res, next) => …)` **последним** в стеке, после `/healthz` и JSON-404: Express идёт от места ошибки вперёд, поэтому обработчик, зарегистрированный выше маршрутов, чужие ошибки не увидит. Статус из `err.status`/`statusCode`, в лог — метод, путь и стек, наружу — `{ error: "…" }` без деталей. Работает независимо от `NODE_ENV`.

Неизвестные пути после `/healthz` отдают `404 { "error": "Не найдено" }` — включая отсутствующие статические файлы. Это осознанно: API-клиент всегда получает JSON.

Остаточный путь утечки — `next(err)` при `headersSent` → `finalhandler` (в dev умеет вернуть стек). Практически недостижимо, но `NODE_ENV=production` на проде всё ещё имеет смысл.

**Асинхронный обработчик.** Express 4 не ловит rejected promise. Все `await` находятся в `try/catch`, `req.body` — объект (body-parser strict), но это хрупко: новый `throw` до `try` уронит процесс. Приложение уже собирается в `createApp()`, а запуск отделён в `startServer()`; следующий шаг — вынести маршрут в отдельный модуль и покрыть supertest.

---

## 9. Фронтенд, CSP, a11y и печать

* `API_URL = "/api"` — относительный путь, работает за прокси и не конфликтует с `default-src 'self'`.
* Рендер — только `textContent` и DOM API (`createElement`, `append`); `innerHTML` отсутствует. В отчёт попадает `Server` чужого сервера — это данные третьей стороны.
* Обработчик формы вынесен из разметки (`addEventListener`), работает строгий `script-src 'self'` без `'unsafe-inline'`.
* `style-src 'self'`, инлайновых стилей нет.
* `X-Frame-Options: DENY` согласован с `frame-ancestors 'none'`.
* Клиентский таймаут 65 с через `AbortController`; `api/client.js` нормализует ответ, чтобы рендер не падал на неполном JSON.
* **CSS:** токены в `tokens.css` (`--color-*`, `--space-1..10`, `--control-height`, `--touch-target`, `--container-max`), база — `reset.css`, `base`, `layout`, `utilities`, печать — `print.css`, дальше по файлу на компонент (10 штук). Всё связано 16 `@import` в `main.css`: сборщика нет, поэтому порядок импортов и есть каскад — токены → reset → база → layout → утилиты → компоненты → печать.
* **Отчёт:** три блока — оценка (кольцо на `conic-gradient`, заполнение через CSS-переменную `--value`), «Что исправить» (карточки находок с бейджем важности и OWASP) и «Детали проверки» (семь карточек: порты, TLS, заголовки, почтовая безопасность, cookie, технологии, открытые файлы). `security.txt` живёт в карточке «Технологии»; WAF/CMS остаются там же информационными бейджами и не попадают в список исправлений.
* **Фильтры и копирование.** Над находками — кнопки «Все / Критичные / Важные / Замечания» с количеством; они переключают `hidden` у `li` и `aria-pressed` у кнопок, DOM не пересобирается. Кнопка «Скопировать отчёт» вызывает `navigator.clipboard.writeText(buildShareText(report))`; текст собирает чистая функция в `ui/report-model.js` (до пяти находок с рекомендациями). Без Clipboard API кнопка сообщает об ошибке через `role="status"`, а не молчит.
* **Человеческий язык.** `ui/render-result.js` переводит технические значения в понятные: DMARC `reject` → «Строгий (Блокировка)», `quarantine` → «Карантин (В спам)», `none` → «Мониторинг»; SPF и CAA → «Настроен / Не настроен». У терминов SPF, DMARC, CAA, HSTS, CSP, COOP, CORS и cookie-флагов есть `title`-подсказки; пунктирное подчёркивание показывает, что термин интерактивен.
* **Юридические страницы:** `legal.html` и `privacy.html` — документ с оглавлением. `ui/legal-toc.js` строит его из `.legal__section-title`, ведёт подсветку через `aria-current="location"` и сам обрабатывает клик (переход + перенос фокуса в раздел), поэтому подсветка переключается и на документе, который целиком влезает в экран. Без JS оглавление остаётся скрытым (`hidden`), текст читается линейно.
* **A11y:** skip-link на всех трёх страницах, `aria-describedby` у поля, `aria-invalid` ровно на том контроле, о котором говорит ошибка, `role="alert"`/`role="status"`, `aria-pressed` и `aria-controls` у фильтров, `dl`-семантика, focus на заголовке отчёта, кастомный чекбокс 18 px поверх нативного `input` (сам `input` остаётся фокусируемым и кликабельным).
* **Печать:** `document.title` = `CyberCheck_<host>_<локальная дата>`, host ≤ 60, `afterprint` сбрасывает title; `print.css` переопределяет токены, включая `--color-surface-raised` и `--color-warning`; находки читаемы с фонами. Кнопки отчёта и фильтры на бумагу не попадают, а скрытые фильтром находки печатаются все.
* **OG:** `og:title`, `og:description`, `og:type`, `og:url`, `og:image`, `og:image:alt`, `og:site_name`, `twitter:card`, `twitter:image` и `canonical` — на `index.html`, `legal.html` и `privacy.html`. Плейсхолдер `__BASE_URL__` подставляется в `pageHtml()` при отдаче, поэтому страницы не раздаются как обычная статика. Обложка хранится как JPEG, но с именем `.png`; сервер отдаёт её с `Content-Type: image/jpeg`, иначе `nosniff` заблокировал бы картинку.

---

## 10. Скоринг (Risk Score)

`src/scoring.js` — чистая функция без I/O. Одинаковый `report` даёт одинаковые `score`, `grade`, `findings`.

### 10.1. Контракт

```js
calculateScore(report) → { score, grade, findings }

report = {
  host: string,
  ports: [{ port: number, status: "open" }],
  ssl: {
    hasSSL: boolean, valid?: boolean, daysLeft?: number,
    supportsOldTls?: boolean, tlsConfirmed?: boolean,
    error?: "NO_WEB_PORT" | "HANDSHAKE_FAILED" | "CERT_PARSE_FAILED" | string
  },
  headers: { error?: true } | {
    hsts, csp, xframe, xcontent: boolean,
    hstsState, cspState, xframeState, xcontentState: "ok" | "weak" | "missing",
    referrerPolicy?, permissionsPolicy?, coop?, corsWildcard?: boolean,
    referrerPolicyState?, permissionsPolicyState?, coopState?,
    accessControlAllowOrigin?: string | null,
    cookies?: [{ name, secure, httpOnly, sameSite, sameSiteValue }],
    cookieSummary?: {
      total, secure, httpOnly, sameSite, insecureNone,
      missingSecure, missingHttpOnly, missingSameSite
    },
    server: string, protocol: "HTTP" | "HTTPS"
  },
  dns: {
    applicable: boolean,
    spf: { present, record, multiple, weak, error },
    dmarc: { present, record, policy, strict, weak, multiple, error },
    caa: { present, records, restrictive, error }
  },
  files: {
    exposed?: string[],
    critical?: Array<string|{path, severity}>,
    blocked?: string[],
    results?: [{ path, status, exposed, blocked, error }]
  },
  securityTxt: { present, status, blocked, error },
  fingerprint: { waf?: { name }, cms?: { name }, status, error, bodyBytes }
}
```

`Finding`:

```js
{
  id: string,             // "no-csp", "old-tls", "exposed-env", …
  title: string,
  desc: string,
  severity: "high" | "medium" | "low",
  weight: number,
  recommendation: string,
  owasp: string            // "A05:2021 Security Misconfiguration"
}
```

`id` — часть контракта: по нему строятся фильтры и diff. `owasp` — маркировка категории, а не сертификация. `weight: 0` используется для информационных находок (`waf-detected`, `cms-detected`) и ошибок, которые не должны снижать балл.

### 10.2. Веса и потолки

| Фактор | Баллы |
|---|---:|
| Валидный TLS (`hasSSL && valid`) | 12 |
| `daysLeft > 30` | 3 |
| HSTS (только при валидном TLS) | 8 |
| CSP | 10 |
| `X-Frame-Options` | 6 |
| `X-Content-Type-Options` | 6 |
| `Server` без номера версии | 3 |
| Referrer-Policy | 2 |
| Permissions-Policy | 2 |
| Cross-Origin-Opener-Policy | 2 |
| CORS не `*` | 3 |
| Cookie Secure | 3 |
| Cookie HttpOnly | 2 |
| Cookie SameSite | 1 |
| SPF | 4 |
| DMARC strict (`quarantine`/`reject`) | 3 |
| CAA | 2 |
| Нет открытых 22/3306 | 10 |
| Порт 8080 закрыт | 2 |
| `/.env` не открыт | 7 |
| `/.git/config` не открыт | 4 |
| `/backup.zip` не открыт | 2 |
| `/.DS_Store` не открыт | 1 |
| `security.txt` не отсутствует (нет уверенного `404`) | 2 |
| **Итого** | **100** |

Поддержка TLS 1.0/1.1 — отдельный штраф **−10** сверх суммы. Потолки применяются после суммирования:

| Условие | `score = min(score, …)` |
|---|---:|
| `files.critical`/`exposed` содержит `/.env` | 40 |
| `files.critical`/`exposed` содержит `/.git/config` | 50 |
| `files.critical`/`exposed` содержит `/backup.zip` | 50 |
| `headers.corsWildcard` | 60 |
| `headers.error` | 60 |
| `ssl.error` | 60 |
| `!ssl.hasSSL && !ssl.error` | 30 |
| `ssl.hasSSL && !ssl.valid` | 40 |
| открыт 3306 | 70 |
| `ssl.supportsOldTls` | 85 |
| `hasSSL && daysLeft <= 7` | 90 |
| есть находка `medium`/`high` | 90 |

Пороги: A ≥ **95**, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F < 20.

Потолок 90 для не-`low` находок и есть причина, по которой A = 95: любая серьёзная находка опускает результат до B.

### 10.3. Краевые случаи

* **`headers.error`** — баллы за HSTS/CSP/XFO/XCTO/`Server`/доп. заголовки/cookie/CORS не начисляются; находка `headers-unavailable`; потолок 60.
* **`ssl.error`** — TLS-хендшейк не удался (таймаут, reset, сертификат не разобран). Находка `ssl-error` уровня `medium`, потолок 60; `no-ssl` не создаётся, потому что отсутствие TLS не доказано. На 80 порту TLS не проверяется, на 8080 ошибка TLS трактуется как HTTP, а не как ошибка.
* **Нет TLS** — только при `hasSSL: false` **без** `error`: HSTS-баллы не начисляются (`h.hsts && hasSSL`); находка `no-hsts` не создаётся, потому что без HTTPS она была бы шумом. CSP/XFO/XCTO/`Server`/доп. заголовки/cookie считаются, но потолок 30 даёт E.
* **`NO_WEB_PORT`** — ни один веб-порт не открыт: `files/securityTxt/fingerprint: null`, находка `tls-not-checked` с `weight: 0`, потолок 30 не применяется, баллы за непроверенные секции начисляются. Это отличается от «HTTPS не настроен».
* **`tlsConfirmed`** — заголовки пришли по HTTPS, но сертификат не прочитан: `ssl-unverified` (`medium`), баллы TLS не начисляются, потолок 60 не применяется — сайт реально работает по HTTPS.
* **TLS 1.0/1.1** — `supportsOldTls` отнимает 10 и включает потолок 85, поэтому A при старом TLS невозможен: максимум B.
* **Просроченный сертификат** — `hasSSL: true`, `valid: false` → `bad-ssl`, потолок 40 (D).
* **`daysLeft` отсутствует или не число** — 3 балла не начисляются, находка не создаётся.
* **`Server` без номера версии** — `cloudflare`, `github.com`, `unknown`, `nginx`, `AmazonS3` версии не раскрывают: находки нет, 3 балла начисляются. Замечание `server-exposed` появляется, если в значении есть цифра в начале или после пробела/`/`: `nginx/1.18.0`, `Apache/2.4.49`, `Microsoft-IIS/10.0`, `nginx/2`. Регулярка — `/(?:^|[\s/])\d+(?:\.\d+)*/`; значение без разделителя (`AmazonS3`) версией не считается.
* **Сертификат истекает в течение 30 дней** — находка `ssl-expiring` уровня `low`, 3 балла не начисляются. При `daysLeft <= 7` дополнительно включается потолок 90 (B); при 8–30 днях сайт с идеальной гигиеной остаётся A (97).
* **Порт 22/3306** — отдельная находка на каждый, `high`, вес 10; 3306 включает потолок 70.
* **DNS-ошибки** — `ENODATA`/`ENOTFOUND` считаются отсутствием записи (`spf-missing`, `dmarc-missing`, `caa-missing`); `TIMEOUT`/`ESERVFAIL`/`ABORTED` и `applicable:false` баллы не отнимают и находку не создают.
* **Открытые файлы** — `200` на `/.env`/`/.git/config`/`/backup.zip` даёт потолок 40/50/50; `403`, `404`, `301` и сетевые ошибки экспозицией не считаются. `files.critical` и `files.exposed` поддерживаются.
* **`security.txt`** — 2 балла, если файл найден или проверка не дала уверенного `404`; только явный `404` создаёт `security-txt-missing`. `403`, сетевой сбой, редирект и прочие статусы нейтральны.
* **Неполные данные** — `files`/`securityTxt: null` (например, нет веб-порта) не считаются экспозицией, баллы за них начисляются; `headers.error` при этом ограничивает итог 60. Необязательные поля заголовков со значением `undefined` означают «не проверялось» и баллы не отнимают.
* **CORS `*`** — находка `cors-wildcard` high и потолок 60.
* **Cookie** — при отсутствии cookie баллы начисляются; `Secure` не штрафуется без HTTPS; `HttpOnly`/`SameSite` проверяются по `cookieSummary`.
* **Fingerprint** — WAF/CMS создают информационные находки с `weight: 0`, на score не влияют.
* **Неизвестный вход** — `ssl`/`headers`/`ports` отсутствуют → «нет TLS»/«ошибка заголовков»/«портов нет»; исключений нет.

### 10.4. Тесты

`test/scoring.test.js` — **45 тестов**:

* сумма положительных весов ровно 100 и `WEIGHTS`;
* идеальный отчёт → 100/A без находок;
* отсутствие CSP/HSTS/XCTO, просроченный и отсутствующий TLS, `ssl.error`, `tlsConfirmed`, истекающий сертификат;
* опасные порты 3306/8080, `Server` с версией и без;
* потолки `/.env` (40), `/.git/config` (50), `/backup.zip` (50), CORS `*` (60);
* DMARC `p=none`, DNS-таймаут (баллы не теряются) и `ENODATA` (находки);
* несколько SPF/DMARC-записей, слабый SPF, CAA только с iodef;
* cookie без Secure/HttpOnly/SameSite, SameSite=None без Secure;
* `security.txt`, `files:null`, проваленные HEAD-пробы, `dns.applicable:false`;
* WAF/CMS с `weight: 0`;
* `NO_WEB_PORT` → `tls-not-checked` без потолка 30;
* weak-значения security-заголовков;
* наличие `owasp` у каждой находки и сортировка high → medium → low.

### 10.5. Известные отклонения

* **A требует 95+.** Потолок 90 для находок `medium`/`high` означает: сайт без `X-Content-Type-Options` получает 90/B, а не A, хотя в отчёте рядом стоит красное «НЕТ». Это осознанная калибровка — буква A должна означать «придраться не к чему»; поэтому старый TLS ограничен 85, а любая находка тяжелее `low` — 90.
* **`headers.error`** — баллы за заголовки/cookie/CORS не начисляются; потолок 60 остаётся верхней границей.
* **`ssl-expiring` — low.** При 8–30 днях она не включает потолок 90 и меняет только 3 балла (A = 97); при `daysLeft <= 7` включается потолок 90 (B).
* **Мажорная версия ловится** (`nginx/2`): регулярка ищет цифру в начале или после пробела/`/`, поэтому `AmazonS3` и `github.com` остаются без находки.
* **`ssl-error` не равен `no-ssl`.** Отчёт с `error` честно говорит «не удалось проверить TLS» и не выдаёт отсутствие сертификата за факт; цена — потолок 60 вместо 30.
* **Fingerprint — информация.** WAF/CMS имеют `weight: 0` и не меняют score; это эвристика, а не доказательство наличия/отсутствия WAF.
* **`supportsOldTls` — детект, не доказательство.** Ложное отрицание возможно на сборках с запретом TLS 1.0/1.1.

---

## 11. Что сервер хранит и логирует

| Данные | Где | Срок |
|---|---|---|
| IP клиента | `CooldownGate.entries` (память) | TTL 10 с; фоновая чистка раз в 30 с, поэтому запись может жить до ~30 с |
| IP клиента | `console.log` | навсегда, без ротации |
| hostname цели | `console.log` | то же |
| Результаты скана | только HTTP-ответ | не сохраняются |
| Сертификаты, заголовки | только ответ | не сохраняются |
| Счётчик активных сканов | `activeScans` (память) | только на время скана |
| Секреты | — | отсутствуют |

Ничего не пишется на диск. Состояние в памяти — `Map` последних запросов и счётчик активных сканов. `/healthz` отдаёт `{ok, uptime}`.

---

## 12. Тестирование

Покрыто (**197 тестов** в 12 файлах):

* `test/net-guard.test.js` — 9 тестов: 20 адресов на блокировку (mapped, NAT64, `::/96`, `::7f00:1`), 4 на разрешение, 5 мусорных на fail-closed, инъекция резолвера, смешанный ответ, таймаут.
* `test/scoring.test.js` — 45 тестов (см. §10.4), включая веса 100, потолки файлов/CORS, DNS-ошибки, cookie, `NO_WEB_PORT` и OWASP.
* `test/checks.test.js` — 10 тестов: `checkPort` на закрытом и открытом порту, дедлайн, отказ от нелитерального `connectIp`, `checkHeaders` с cookie/доп. заголовками/CORS/weak-значениями, `checkSSL` с `HANDSHAKE_FAILED` и самоподписанным сертификатом.
* `test/dns-security.test.js` — 23 теста: SPF, DMARC (`reject`/`quarantine`/`none`), CAA, IP/localhost, таймауты, DNS-ошибки, abort.
* `test/header-analysis.test.js` — 30 тестов: `Set-Cookie`, сводка флагов, Referrer-Policy/Permissions-Policy/COOP, ACAO `*`, WAF и CMS.
* `test/web-probes.test.js` — 12 тестов: HEAD-файлы (200/403/404/301), `security.txt`, фингерпринт, Host/connectIp, таймаут, abort, частичное тело.
* `test/scan-helpers.test.js` — 19 тестов: `parseTarget`, `rateKey`, бюджеты, `selectWebPorts`, `withCriticalFiles`, `buildReport`, `isHtmlRequestPath`, `isLiteralIp`.
* `test/rate-limit.test.js` — 10 тестов: кулдаун, LRU, sweep, семафор, лишний `finish`, таймер.
* `test/report-model.test.js` — 22 теста: `sanitizeText`, критичность путей, `filesNote`, `tlsNotice`, `caaState`, `secureContextState`, склонения, имя отчёта.
* `test/frontend-contract.test.js` — 5 тестов: нормализация `owasp`/`dns`/`files`/`securityTxt`/`fingerprint` в `api/client.js`; мусорные `score`/`grade`/`ports`; сетевые ошибки; наличие карточек и `finding__owasp` в `ui/render-result.js`; отсутствие `.innerHTML` и экспорты.
* `test/server.test.js` — 1 тест: запуск с `TRUST_PROXY=0` на случайном порту.
* `test/server-http.test.js` — 11 тестов: `/healthz`, HTML с `BASE_URL` и security-заголовками, защита от шаблонов в статике, редирект, 400/415/413, 429-кулдаун, CORS, JSON-404.

`npm test` запускает все 12 файлов, CI — тот же набор плюс рекурсивный разбор модулей фронтенда через `vm.SourceTextModule`.

Не покрыто:

| Что | Почему | Как закрыть |
|---|---|---|
| Оркестрация скана в `core/server.js` | маршрут и перебор IP/портов пока внутри `createApp()` | вынести `probeTarget()` с инъекцией проверок |
| `checkHeaders` retry | требует сети/сокетов | локальный сервер или инъекция |
| `checkOldTls`/`supportsOldTls` | требует TLS-стенда | `tls.createServer({minVersion:"TLSv1"})` |
| 503/504 | нужны 25 параллельных сканов или зависший TLS | инъекция лимитера и таймаута |
| Рендер/печать/копирование | нет DOM-тестов | jsdom/happy-dom + мок Clipboard API |
| `server-http` не проверяет `/assets/screenshots/og-cover.png` | статика без MIME-контракта | отдельный тест `Content-Type` |

`createApp()` уже экспортируется, поэтому HTTP-слой можно перевести на supertest без запуска процесса.

---

## 13. Технический долг

| Долг | Влияние |
|---|---|
| Маршрут `/api/scan` остаётся внутри `createApp()` | логика скана и HTTP-ответа в одном файле; оркестрацию нельзя протестировать по частям |
| `startServer()` вешает `process.on` и `listen()` | импорт `core/server.js` безопасен, но запуск всё ещё неявный для тестов |
| Плоские фасады `src/*.js` | дублируют имена модулей; нужны, пока внешние потребители не перешли на домены |
| Лимит после валидации | поток невалидных запросов не ограничен |
| Семафор считает только свой процесс | при нескольких репликах потолок 25 умножается на их число |
| Лимит скана 60 с, а три веб-порта + пробы последовательно могут занять больше | цель с тремя «молчащими» веб-портами обрывается 504; один порт (34,5 с) укладывается |
| Новые пробы добавляют до 4 с (HEAD/security.txt/fingerprint), DNS-записи — до 3 с, DNS-разрешение — до 5 с | на медленной цели 60 с может не хватить; таймауты 2–5 с ограничивают вклад |
| HEAD-проба считает critical любой 200, включая SPA-заглушку | возможен false positive; контроль content-type/тела не реализован |
| DNS/email проверяется по точному hostname | для `www` DMARC apex `_dmarc.example.com` не подставляется |
| CORS проверяется только по корню | отдельные API-эндпоинты не обходятся |
| WAF/CMS-фингерпринт — эвристика | кастомные сборки и сжатые ответы могут не определиться |
| `checkOldTls` вызывается после `socket.end()`; `socket.setTimeout(0)` в колбэке `connect` снимает 5-секундный таймаут | race с таймаутом снят, но probe добавляет до 3 с к времени скана и зависит от OpenSSL |
| TLS-проба на 8080 остаётся: ошибка там подавляется, но лишний ClientHello уходит | небольшой шум в логах цели; 80 уже исключён |
| В ответе нет поля `ip` | при нескольких A-записях непонятно, какой узел проверен |
| Редиректы не разворачиваются | заголовки могут быть с 301-заглушки |
| Express 4 | не ловит rejected promise |
| Нет истории/БД | stateless, нет share/«до/после»/API-ключей |
| OG-превью статичное, без генерации под отчёт | одна картинка на все страницы |
| `og-cover.png` содержит JPEG | сервер отдаёт правильный MIME, но файл стоит перекодировать или переименовать |
| Политика приватности описывает фактическое поведение и прямо говорит, что не является юридическим заключением | для B2B по 152-ФЗ нужна отдельная проработка |

---

## 14. Модель угроз (кратко)

| Угроза | Контроль | Остаток |
|---|---|---|
| SSRF к внутренней сети/metadata | резолв + проверка всех IP + подключение по IP | NAT64 с нестандартным префиксом |
| SSRF через новые HEAD/GET-пробы | `probes/web-probes.js` всегда использует `connectIp`, Host/SNI — только hostname | — |
| DNS rebinding | подключение по проверенному IP | — |
| XSS через данные цели | `textContent`/DOM API, строгий CSP | — |
| Утечка стека | error handler, JSON без деталей | `next(err)` при `headersSent` |
| Подмена `X-Forwarded-For` | `"unknown"`, `/64` | неверный `TRUST_PROXY`: значение больше числа реальных хопов отдаёт `req.ip` клиенту |
| Abuse сканера | CORS, лимит, согласие, DISCLAIMER | распределённый источник, нет verification |
| DoS на сервис | лимит, `MAX_KEYS`, таймауты, семафор на 25 одновременных сканов | лимиты живут в памяти процесса: N реплик = N лимитов |
| Захват зависимости | `npm ci --ignore-scripts`, lock, `npm audit` | Actions запинены по SHA |
| Утечка секретов | секретов нет, `.env` в `.gitignore` | — |

---

## 15. Конфигурация и деплой

`PUBLIC_ORIGIN` проверяется на старте (`new URL` + схема) в `core/config.js`. Если не задан — используется `RENDER_EXTERNAL_URL`, который Render передаёт веб-сервису автоматически. Это делает blueprint zero-config, но привязывает CORS к `*.onrender.com`: при кастомном домене `PUBLIC_ORIGIN` нужно задать явно.

`render.yaml`: web-сервис, `NODE_ENV=production`, `TRUST_PROXY=1`, health-check `/healthz`, план `starter`, сборка `npm ci --ignore-scripts`. Graceful shutdown: `SIGTERM`/`SIGINT` → `server.close()` + `closeIdleConnections()`, ожидание до 40 с, затем `closeAllConnections()` и `exit(1)`. Render может ограничивать окно завершения — проверьте на своём плане.

---

*Документ описывает состояние кода на 06.11.2026, тег `v2.2.0`. Ссылки указывают на функции и маркеры, а не на номера строк. При изменении логики §5–§8 и §10 документ нужно перечитать.*
