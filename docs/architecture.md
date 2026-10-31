# Архитектура CyberCheck

Документ отвечает на вопрос «как это устроено и почему именно так». Он не заменяет `README.md` (запуск, переменные, деплой) и `.github/SECURITY.md` (порядок сообщения об уязвимостях).

**Кодовые ориентиры:** `src/server.js`, `src/checks.js`, `src/scoring.js`, `src/net-guard.js`, `public/assets/js/*`, `test/*.test.js` — около 1200 строк вместе с тестами и фронтендом.

> **Соглашение о ссылках.** Ссылки указывают на **функции и маркеры** в коде, а не на номера строк: номера устаревают от любой вставки, а имена — нет. Ищите `checkCooldown`, `isPublicIp`, `resolvePublicIps`, `calculateScore`, `checkOldTls` или маркеры `3. Сначала валидация`, `4. Лимит частоты`, `5. Логируем ПОСЛЕ валидации`.

---

## 1. Назначение и границы

**Что делает:** по запросу `hostname` проверяет доступность пяти портов (`80, 443, 22, 3306, 8080`), читает TLS-сертификат на найденном веб-порту, определяет версию TLS и поддержку TLS 1.0/1.1, наличие четырёх HTTP-заголовков и считает Risk Score. Возвращает JSON `{host, ports, ssl, headers, score, grade, findings}`.

**Чего не делает:**

* не эксплуатирует уязвимости и не аутентифицируется на цели;
* не аутентифицирует пользователей — API публичный;
* не хранит результаты (ни БД, ни файлов, ни кэша);
* не проверяет владение доменом (согласие — только фиксация намерения);
* не сканирует пути и нестандартные порты (`https://site:8443/admin` проверяется как `https://site/` на 80/443/8080);
* не разворачивает редиректы;
* не поддерживает IPv6-литералы — отклоняет их на валидации;
* не проверяет шифры и цепочку сертификатов (только leaf-сертификат и версию протокола).

Тело ответа не скачивается: `res.destroy()` вызывается сразу после получения заголовков в `checkHeaders()`.

---

## 2. Компоненты

```
┌──────────────────┐
│     Браузер      │  public/index.html
│    (vanilla)     │  assets/js/app.js → api.js → render-result.js
│                  │  fetch("/api/scan")
└────────┬─────────┘
         │ POST /api/scan {url, consent, consentTimestamp}
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Express (src/server.js)                                     │
│  helmet → cors → express.json(8kb) → express.static         │
│                              │                              │
│                    POST /api/scan                           │
│                    ├─ валидация URL (маркер «3.»)           │
│                    ├─ protocol / hostname / domainRegex      │
│                    ├─ rateKey + cooldown (in-memory Map)    │
│                    ├─ console.log (hostname, ip)            │
│                    ├─ resolvePublicIps(host)                │
│                    ├─ checkPort ×5 / checkSSL / checkHeaders│
│                    └─ buildReport() → calculateScore()      │
│                              ▼                              │
│                    res.json({ …, score, grade, findings })  │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
                  ┌──────────────────┐   ┌──────────────────┐
                  │ src/net-guard.js │   │ src/checks.js    │
                  │ resolvePublicIps │   │ порты / TLS /    │
                  │ isPublicIp       │   │ заголовки        │
                  └────────┬─────────┘   └────────┬─────────┘
                           │ dns.lookup(all)      │ TCP / TLS / HTTP
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
| `server.js` | HTTP-слой, конфиг, лимит, валидация URL, `buildReport`, 404 | сетевые проверки, расчёт оценки |
| `net-guard.js` | решение «можно ли подключаться к этому хосту» | подключение |
| `checks.js` | порты, TLS (включая `checkOldTls`), заголовки, retry | валидация ввода, оценка |
| `scoring.js` | Risk Score и находки по готовому отчёту | сеть, I/O, состояние |
| `public/assets/js/*` | UI, таймаут 45 с, рендер через DOM API, печать | решения о безопасности |

---

## 3. Путь запроса

| # | Шаг | Где искать | Что даёт |
|---|---|---|---|
| 1 | Валидация конфигурации (`PUBLIC_ORIGIN` / `RENDER_EXTERNAL_URL`) | `server.js` → маркер «1.» | парсинг URL + схема; иначе `exit(1)` |
| 2 | `TRUST_PROXY` | `server.js` → `app.set("trust proxy", …)` | модель доверия к `X-Forwarded-For` |
| 3 | Helmet + CSP | `server.js` → `helmet({ … })` | XSS-защита, запрет фреймов, `no-referrer` |
| 4 | CORS | `server.js` → `cors({ origin: [PUBLIC_ORIGIN] })` | только один origin |
| 5 | JSON 8 КБ | `server.js` → `express.json({ limit: "8kb" })` | 413 вместо стека |
| 6 | Статика | `server.js` → `express.static(…)` | `public/` |
| 7 | Валидация входа | маркер «3. Сначала валидация» | `url` строкой, ≤ 2048; `consent === true`; timestamp в окне 15 мин |
| 8 | `new URL()` + схема | `parsed.protocol` | только `http:`/`https:`; `ftp://` отклоняется |
| 9 | Hostname | `.toLowerCase().replace(/\.$/, "")`, длина ≤ 253, `net.isIP` + `domainRegex` | IDN/punycode, trailing dot, IPv4; IPv6-литералы — 400 |
| 10 | Лимит частоты | маркер «4. Лимит частоты» → `checkCooldown(rateKey(ip))` | 429 до сети |
| 11 | Лог | маркер «5. Логируем ПОСЛЕ валидации» | после проверок — log injection невозможен |
| 12 | `resolvePublicIps` | `net-guard.js` | решение об SSRF |
| 13 | Порты → TLS → заголовки | `Promise.all` + `checkSSL` / `checkHeaders` | скан |
| 14 | `buildReport` | `server.js` → `buildReport(host, ports, ssl, headers)` | единая сборка + `calculateScore` |
| 15 | Ответ / 404 / ошибка | `res.json`, error handler, JSON-404 | без внутренних деталей |

**Бюджет времени (худший сценарий):**

| Этап | Максимум |
|---|---|
| Порты (5 параллельно) | 3 с + 0,5 с + 3 с = **6,5 с** |
| TLS | main 5 с + `checkOldTls` 3 с = **8 с** |
| Заголовки | HTTPS 5 + HTTP 5 + 1 + HTTPS 5 + HTTP 5 = **21 с** |
| **Итого** | **≈ 35,5 с** |

Клиентский таймаут — **45 с** (`TIMEOUT_MS` в `api.js`). Graceful shutdown — **40 с** (`server.js`), но Render может прислать SIGKILL раньше; общего таймаута скана пока нет.

---

## 4. Модель доверия

| Субъект / данные | Доверяем? | Обоснование |
|---|---|---|
| `req.body` (url, consent, timestamp) | ❌ | валидируется; `consent` — только намерение |
| `req.ip` | ⚠️ условно | при `TRUST_PROXY=0` — адрес сокета; при `>0` — `X-Forwarded-For`, только за реальным прокси |
| DNS-ответ | ❌ | проверяются все адреса; смешанный ответ — отказ |
| `connectIp` | ✅ | подключаемся к проверенному IP, не к имени |
| Сертификат цели | ❌ | читается с `rejectUnauthorized:false`; валидность — по `authorizationError` |
| Заголовки цели | ❌ | извлекаются `Server` и факт наличия 4 заголовков; значения не интерпретируются как HTML/JS |
| `report` для скоринга | ❌ | `scoring.js` не ходит в сеть и не выполняет код |
| Конфигурация (env) | ✅ в пределах процесса | `PUBLIC_ORIGIN`/`RENDER_EXTERNAL_URL`, `TRUST_PROXY`, `DEMO_MODE`, `NODE_ENV`, `PORT` |

---

## 5. Ключевой инвариант SSRF-защиты

1. **Резолв:** `dns.lookup(hostname, { all: true })` — все адреса.
2. **Проверка всех:** `if (!ips.every(isPublicIp)) return []` — хотя бы один приватный → отказ целиком.
3. **Подключение по проверенному IP:** `connectIp = resolvedIps[0]`; hostname — только в `Host` и SNI.

**Почему закрыт DNS rebinding:** между проверкой и подключением нет повторного резолва. Даже если A-запись сменится, соединение пойдёт на проверенный IP.

**Классификация** — аллоулист `ipaddr.js.range() === "unicast"`. Блокируются private, loopback, link-local, CGNAT, ULA, multicast, 6to4, Teredo, NAT64, IPv4-mapped, `::/96`; нераспознанный ввод — fail closed.

**Чего схема не закрывает:** NAT64/DNS64 с нестандартным префиксом (нужен сетевой egress-фильтр) и публичные чужие цели (правовой, не технический вопрос).

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
lastScan: Map<key, timestamp>   TTL 10 с, чистка раз в 30 с, MAX_KEYS 10 000, LRU
```

Лимит списывается **после** валидации URL и hostname. Невалидные имена окно не занимают; невалидный IP попадает в общий бакет `"unknown"`; IPv6 нормализуется до `/64`, чтобы смена младших 64 бит не давала нового окна.

Что лимит **не** обещает:

* не защищает от `/48` или ботнета;
* не глобальный: N реплик = N лимитов;
* не ограничивает запросы, отвалившиеся на валидации;
* уязвим к неверному `TRUST_PROXY`;
* списывается до DNS-резолва (опечатка стоит 10 с).

Для публичного запуска нужен внешний лимит (`express-rate-limit` + Redis) и семафор.

---

## 8. Обработка ошибок и 404

Единый обработчик — `app.use((err, req, res, next) => …)` перед `/healthz`. Статус из `err.status`/`statusCode`, в лог — метод, путь и стек, наружу — `{ error: "…" }` без деталей. Работает независимо от `NODE_ENV`.

Неизвестные пути после `/healthz` отдают `404 { "error": "Не найдено" }` — включая отсутствующие статические файлы. Это осознанно: API-клиент всегда получает JSON.

Остаточный путь утечки — `next(err)` при `headersSent` → `finalhandler` (в dev умеет вернуть стек). Практически недостижимо, но `NODE_ENV=production` на проде всё ещё имеет смысл.

**Асинхронный обработчик.** Express 4 не ловит rejected promise. Все `await` находятся в `try/catch`, `req.body` всегда объект (body-parser strict), но это хрупко: новый `throw` до `try` уронит процесс. В v1.4.0 хендлер переезжает в `app.js`.

---

## 9. Фронтенд, CSP, a11y и печать

* `API_URL = "/api"` — относительный путь, работает за прокси и не конфликтует с `default-src 'self'`.
* Рендер — только `textContent` и DOM API (`createElement`, `append`); `innerHTML` отсутствует. В отчёт попадает `Server` чужого сервера — это данные третьей стороны.
* Обработчик формы вынесен из разметки (`addEventListener`), работает строгий `script-src 'self'` без `'unsafe-inline'`.
* `style-src 'self'`, инлайновых стилей нет.
* `X-Frame-Options: DENY` согласован с `frame-ancestors 'none'`.
* Клиентский таймаут 45 с через `AbortController`; `api.js` нормализует ответ, чтобы рендер не падал на неполном JSON.
* **A11y:** skip-link, `aria-describedby` у поля, `aria-invalid` при ошибке, `role="status"`, `dl`-семантика, focus на заголовке отчёта, чекбокс 24px.
* **Печать:** `document.title` = `CyberCheck_<host>_<локальная дата>`, host ≤ 60, `afterprint` сбрасывает title; `print.css` переопределяет токены, включая `--color-surface-raised` и `--color-warning`; находки читаемы с фонами.
* **OG:** `og:title`, `og:description`, `og:type`, `og:image` (абсолютный URL на GitHub), `twitter:card`. `canonical`/`og:url` отсутствуют — известный долг.

---

## 10. Скоринг (Risk Score)

`src/scoring.js` — чистая функция без I/O. Одинаковый `report` даёт одинаковые `score`, `grade`, `findings`.

### 10.1. Контракт

```js
calculateScore(report) → { score, grade, findings }

report = {
  host: string,                                  // не используется
  ports: [{ port: number, status: "open" }],
  ssl: { hasSSL: boolean, valid?: boolean, daysLeft?: number, supportsOldTls?: boolean },
  headers: { error?: true } | {
    hsts, csp, xframe, xcontent: boolean,
    server: string, protocol: "HTTP" | "HTTPS"
  }
}
```

`Finding`:

```js
{
  id: string,             // "no-csp", "old-tls", "port-3306", …
  title: string,
  desc: string,
  severity: "high" | "medium" | "low",
  weight: number,
  recommendation: string
}
```

`id` — часть контракта: по нему строятся фильтры и diff. Менять без версии схемы нельзя.

### 10.2. Веса и потолки

| Фактор | Баллы |
|---|---|
| Валидный TLS (`hasSSL && valid`) | 20 |
| `daysLeft > 30` | 5 |
| HSTS (только при валидном TLS) | 15 |
| CSP | 15 |
| `X-Frame-Options` | 10 |
| `X-Content-Type-Options` | 10 |
| `Server` скрыт | 5 |
| Нет открытых 22/3306 | 15 |
| Порт 8080 закрыт | 5 |
| **Поддержка TLS 1.0/1.1** | **−10** |

Сумма — 100. Потолки применяются после суммирования:

| Условие | `score = min(score, …)` |
|---|---|
| `headers.error` | 60 |
| `!ssl.hasSSL` | 30 |
| `ssl.hasSSL && !ssl.valid` | 40 |
| открыт 3306 | 70 |
| `ssl.supportsOldTls` | 85 |

Пороги: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E ≥ 20, F < 20.

### 10.3. Краевые случаи

* **`headers.error`** — баллы за HSTS/CSP/XFO/XCTO/`Server` не начисляются; находка `headers-unavailable`; фактический максимум при валидном TLS — 45 (20 + 5 + 20 за порты), потолок 60 — верхняя граница.
* **Нет TLS** — HSTS-баллы не начисляются (`h.hsts && hasSSL`); находка `no-hsts` не создаётся, потому что без HTTPS она была бы шумом. CSP/XFO/XCTO считаются, но потолок 30 даёт E.
* **TLS 1.0/1.1** — `supportsOldTls` отнимает 10 и включает потолок 85, поэтому A при старом TLS невозможен: максимум B.
* **Просроченный сертификат** — `hasSSL: true`, `valid: false` → `bad-ssl`, потолок 40 (D).
* **`daysLeft` отсутствует или не число** — 5 баллов не начисляются, находка не создаётся.
* **Порт 22/3306** — отдельная находка на каждый, `high`; 3306 включает потолок 70.
* **Неизвестный вход** — `ssl`/`headers`/`ports` отсутствуют → «нет TLS»/«ошибка заголовков»/«портов нет»; исключений нет.

### 10.4. Тесты

`test/scoring.test.js` — **11 тестов**:

| Тест | Проверяет |
|---|---|
| всё хорошо → A | 100, пустой `findings` |
| нет CSP → 85/B | точное значение |
| нет HSTS → 85/B | точное значение |
| нет XCTO → 90/A | граница A |
| просроченный SSL → ≤ 40 | потолок |
| нет HTTPS → ≤ 30 | потолок |
| `headers.error` → ≤ 60 + находка | потолок |
| открыт 3306 → ≤ 70 + `high` | потолок |
| `server: "не указан"` → 100/A | не раскрытие |
| HSTS без SSL → 20 | HSTS не считается |
| TLS 1.0/1.1 → 85/B | −10 + потолок 85 |

### 10.5. Известные отклонения

* **A при 90.** Порог A — 90, поэтому сайт без `X-Content-Type-Options` получает 90/A, хотя в отчёте рядом красное «НЕТ». Это осознанный компромисс калибровки; старый TLS специально ограничен 85, чтобы не давать A.
* **`headers.error` фактически ≤ 45**, а не 60: баллы за заголовки не начисляются. Потолок 60 — запас на будущее.
* **`supportsOldTls` — детект, не доказательство.** Ложное отрицание возможно на сборках с запретом TLS 1.0/1.1.

---

## 11. Что сервер хранит и логирует

| Данные | Где | Срок |
|---|---|---|
| IP клиента | `lastScan` (память) | ≤ 10 с |
| IP клиента | `console.log` | навсегда, без ротации |
| hostname цели | `console.log` | то же |
| Результаты скана | только HTTP-ответ | не сохраняются |
| Сертификаты, заголовки | только ответ | не сохраняются |
| Секреты | — | отсутствуют |

Ничего не пишется на диск. Единственное состояние — `Map` последних запросов. `/healthz` отдаёт `{ok, uptime}`.

---

## 12. Тестирование

Покрыто:

* `test/net-guard.test.js` — 3 теста: 20 адресов на блокировку (mapped, NAT64, `::/96`, `::7f00:1`), 4 на разрешение, 5 мусорных на fail-closed.
* `test/scoring.test.js` — 11 тестов (см. §10.4).
* `test/checks.test.js` — 2 теста `checkPort`: закрытый порт не считается открытым (`refused`/`closed`), открытый порт определяется (`open`).

Итого **16 тестов**; `npm test` запускает все три файла, CI — тот же набор.

Не покрыто:

| Что | Почему | Как закрыть |
|---|---|---|
| `resolvePublicIps` | `dns.lookup` вшит | инъекция резолвера |
| `rateKey`, `remember` | не экспортируются | вынести в модуль |
| HTTP-слой (400/404/429/CORS) | `server.js` делает `exit`/`listen` при импорте | `src/app.js` + supertest |
| `checkHeaders` retry | требует сети/сокетов | локальный сервер или инъекция |
| `checkOldTls`/`supportsOldTls` | требует TLS-стенда | `tls.createServer({minVersion:"TLSv1"})` |
| URL-валидация | в `server.js` | вынести `parseTarget()` |
| `buildReport`/404 | route-level | supertest |
| Рендер/печать | нет DOM-тестов | jsdom/happy-dom |

---

## 13. Технический долг

| Долг | Влияние |
|---|---|
| `server.js` делает `process.exit()` и `listen()` при импорте | HTTP-слой непокрываем |
| Конфигурация размазана по `server.js` | нет единой валидации env; `PORT` приведён к числу, но `3.5`/пустая строка обрабатываются неявно |
| Лимит после валидации | поток невалидных запросов не ограничен |
| Нет потолка одновременных сканов | исчерпание дескрипторов при abuse |
| Нет общего таймаута скана | худший скан ~35,5 с; shutdown 40 с, Render может убить раньше |
| `checkSSL`: `checkOldTls` вызывается после `socket.end()`, внешний таймаут 5 с остаётся активным | на медленном TLS возможен race: `resolve({hasSSL:false})` до ответа probe — ложный «нет SSL» |
| `checkOldTls` зависит от OpenSSL | ложные отрицания TLS 1.0/1.1; нет теста на стенде |
| Редиректы не разворачиваются | заголовки могут быть с 301-заглушки |
| Express 4 | не ловит rejected promise |
| Нет истории/БД | stateless, нет share/«до/после»/API-ключей |
| `og:image` на GitHub, нет `canonical`/`og:url` | превью зависит от GitHub |
| Нет политики приватности | 152-ФЗ, B2B-блокер |

---

## 14. Модель угроз (кратко)

| Угроза | Контроль | Остаток |
|---|---|---|
| SSRF к внутренней сети/metadata | резолв + проверка всех IP + подключение по IP | NAT64 с нестандартным префиксом |
| DNS rebinding | подключение по проверенному IP | — |
| XSS через данные цели | `textContent`/DOM API, строгий CSP | — |
| Утечка стека | error handler, JSON без деталей | `next(err)` при `headersSent` |
| Подмена `X-Forwarded-For` | `"unknown"`, `/64` | неверный `TRUST_PROXY` |
| Abuse сканера | CORS, лимит, согласие, DISCLAIMER | распределённый источник, нет verification |
| DoS на сервис | лимит, `MAX_KEYS`, таймауты | нет потолка параллельных сканов |
| Захват зависимости | `npm ci`, lock, `npm audit` | Actions по тегам |
| Утечка секретов | секретов нет, `.env` в `.gitignore` | — |

---

## 15. Конфигурация и деплой

`PUBLIC_ORIGIN` проверяется на старте (`new URL` + схема). Если не задан — используется `RENDER_EXTERNAL_URL`, который Render передаёт веб-сервису автоматически. Это делает blueprint zero-config, но привязывает CORS к `*.onrender.com`: при кастомном домене `PUBLIC_ORIGIN` нужно задать явно.

`render.yaml`: web-сервис, `NODE_ENV=production`, `TRUST_PROXY=1`, health-check `/healthz`, план `starter`. Graceful shutdown: `SIGTERM`/`SIGINT` → `server.close()` + `closeIdleConnections()`, ожидание до 40 с, затем `closeAllConnections()` и `exit(1)`. Render может ограничивать окно завершения — проверьте на своём плане.

---

*Документ описывает состояние кода на 31.10.2026, HEAD `82f4e0` (v1.2.0). Ссылки указывают на функции и маркеры, а не на номера строк. При изменении логики §5–§8 и §10 документ нужно перечитать.*
