# DISCLAIMER / ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ

**Версия:** v1.2.0 · **Дата:** 31 октября 2026

---

## English

This tool, **CyberCheck**, is provided **for authorized security testing only**.

### Allowed use

- Testing websites you **own** or operate.
- Testing deliberately vulnerable training applications (OWASP Juice Shop, DVWA, demo.testfire.net).
- Testing systems for which you have **explicit written permission** from the owner.
- Producing internal or client-facing reports about systems you are authorized to assess.

The software is distributed under the **MIT license**, which permits commercial use. Independently of the license, every scan must be authorized as described above and applicable law must be respected.

### Prohibited use

- Scanning third-party websites without permission.
- Any activity aimed at unauthorized access, data theft, denial of service, or any other illegal action.
- Using this tool to violate any local, national, or international law.
- Presenting a CyberCheck report as a full security audit, penetration test, or legal/insurance certification.

### What the scanner does

CyberCheck performs **passive, non-destructive checks**:

- TCP connection attempts to five ports (80, 443, 22, 3306, 8080), with one retry per port;
- one or more TLS handshakes to read the leaf certificate, determine the negotiated TLS version, and probe whether TLS 1.0/1.1 is accepted;
- one or more HTTP requests for response headers, with a retry if the first attempt fails.

It does **not** exploit vulnerabilities, authenticate, fuzz, brute-force, download page bodies, or modify the target.

### Reports and Risk Score

The Risk Score (0–100, A–F) is a **heuristic** based on a small set of observable factors. It is not a vulnerability assessment, not a compliance certificate, and not a substitute for a professional audit. A high score does not mean a system is secure; a low score does not prove it is compromised. Findings describe missing hardening measures, not confirmed exploitable vulnerabilities.

TLS 1.0/1.1 detection is best-effort: depending on the platform's OpenSSL policy, an old protocol may not be detected. A score of 100/A does not prove that the TLS configuration is complete.

### No warranty

The software is provided **"AS IS"**, without warranty of any kind, express or implied, including fitness for a particular purpose, accuracy of results, or uninterrupted operation.

### Limitation of liability

The authors assume **no liability** for any damage, legal consequences, or misuse arising from the use of this tool, including decisions made on the basis of its reports. **The user bears full responsibility** for their actions and for obtaining authorization.

### Data

Scan results are not stored by the service. The target hostname and the client IP address are written to the server log; there is no rotation or retention policy in v1.2.0. Do not scan systems whose hostnames or addresses you are not allowed to process.

### Legal notice

Unauthorized scanning of computer systems may constitute a criminal or administrative offense under:

- **Article 272 of the Criminal Code of the Russian Federation** ("Unlawful access to computer information").
- **Computer Fraud and Abuse Act (CFAA)** in the United States.
- Similar laws in other jurisdictions.

Laws differ by country; the operator of the service is responsible for compliance in the jurisdiction where it is offered.

---

## Русский

Инструмент **CyberCheck** предоставляется **исключительно для авторизованного тестирования безопасности**.

### Разрешено

- Проверка сайтов, которые **принадлежат вам** или находятся под вашим управлением.
- Тестирование учебных уязвимых приложений (OWASP Juice Shop, DVWA, demo.testfire.net).
- Проверка систем, на которые у вас есть **письменное разрешение** владельца.
- Подготовка внутренних и клиентских отчётов по системам, которые вы уполномочены проверять.

Программное обеспечение распространяется по **лицензии MIT**, которая допускает коммерческое использование. Независимо от лицензии, каждый скан должен быть авторизован, как описано выше, и соответствовать применимому законодательству.

### Запрещено

- Сканирование чужих сайтов без разрешения.
- Любые действия, направленные на неправомерный доступ, кражу данных, отказ в обслуживании и другие противоправные действия.
- Использование инструмента в нарушение законодательства.
- Выдача отчёта CyberCheck за полноценный аудит безопасности, пентест или юридическое/страховое заключение.

### Что делает сканер

CyberCheck выполняет **пассивные, неразрушающие проверки**:

- попытки TCP-соединения на пять портов (80, 443, 22, 3306, 8080), по одному retry на порт;
- одно или несколько TLS-рукопожатий: чтение leaf-сертификата, определение согласованной версии TLS и проверка поддержки TLS 1.0/1.1;
- один или несколько HTTP-запросов за заголовками ответа, с retry при ошибке.

Инструмент **не** эксплуатирует уязвимости, не аутентифицируется, не фаззит, не перебирает пароли, не скачивает тела страниц и не изменяет цель.

### Отчёты и Risk Score

Risk Score (0–100, A–F) — **эвристическая** оценка по небольшому набору наблюдаемых факторов. Это не оценка уязвимостей, не сертификат соответствия и не замена профессиональному аудиту. Высокий балл не означает, что система защищена; низкий балл не доказывает компрометацию. Находки описывают отсутствие мер защиты, а не подтверждённые эксплуатируемые уязвимости.

Детект TLS 1.0/1.1 — best effort: в зависимости от политики OpenSSL на платформе старый протокол может не определиться. Оценка 100/A не доказывает полноту TLS-конфигурации.

### Отсутствие гарантий

Программное обеспечение предоставляется **«как есть»**, без каких-либо гарантий, включая пригодность для конкретной цели, точность результатов и бесперебойную работу.

### Ограничение ответственности

Авторы **не несут ответственности** за любой ущерб, правовые последствия или неправомерное использование инструмента, в том числе за решения, принятые на основании его отчётов. **Вся ответственность лежит на пользователе**, включая получение разрешения на проверку.

### Данные

Результаты сканирований сервисом не сохраняются. Hostname цели и IP-адрес клиента записываются в серверный лог; ротации и срока хранения в v1.2.0 нет. Не сканируйте системы, hostname и адреса которых вы не вправе обрабатывать.

### Правовая информация

Несанкционированное сканирование компьютерных систем может являться уголовным или административным правонарушением в соответствии с:

- **статьёй 272 УК РФ** («Неправомерный доступ к компьютерной информации»);
- **Computer Fraud and Abuse Act (CFAA)** в США;
- аналогичными законами в других юрисдикциях.

Законодательство различается по странам; ответственность за соблюдение требований в юрисдикции, где предлагается сервис, несёт оператор.

---

**Проект:** CyberCheck · **Версия:** 1.2.0 · **Год:** 2026
