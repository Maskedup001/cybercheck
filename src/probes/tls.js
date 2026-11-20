const net = require("node:net");
const tls = require("node:tls");
const { sanitizeHeaderText } = require("./header-analysis");
const {
  isLiteralIp,
  stageDeadline,
  timeoutFor,
  hasBudget,
} = require("../utils/scan-helpers");

// Пауза перед повтором входит в бюджет этапа TLS, а не добавляется к нему.
const RETRY_DELAY_MS = 500;

// Проверка старых TLS — отдельное соединение с собственным бюджетом.
// 4 секунды покрывают медленный хендшейк, который раньше не укладывался в
// остаток этапа; общий дедлайн скана при этом остаётся жёстким.
const OLD_TLS_TIMEOUT_MS = 4000;
const OLD_TLS_MIN_MS = 1000;

// Попытка короче 50 мс не успевает даже на TCP-хендшейк.
const MIN_ATTEMPT_MS = 50;

// Проверяет, принимает ли сервер устаревшие версии TLS (1.0 / 1.1).
// timeoutMs — бюджет именно этой пробы (не остаток этапа: иначе медленный
// основной хендшейк оставлял проверке миллисекунды и она отдавала null).
//
// Возвращает true (старые протоколы принимаются), false (сервер их отверг)
// или null — «проверить не удалось»: отмена, нехватка бюджета, таймаут.
// null нельзя трактовать как false: «не успели» и «не поддерживает» — разные
// утверждения, и отчёт не должен выдавать одно за другое.
// Ошибка рукопожатия со старым протоколом — доказательство отказа сервера.
// Сетевой сбой — нет: до сервера могли не достучаться.
function classifyOldTlsError(error) {
  const code = error && typeof error === "object" ? error.code : null;
  const message =
    error && typeof error.message === "string" ? error.message : "";

  if (typeof code === "string") {
    // Alert от сервера: он ответил и явно отверг версию/шифр.
    if (/^ERR_SSL_(TLSV1|SSLV3)_ALERT_/.test(code)) return false;
    if (code === "ERR_SSL_VERSION_OR_CIPHER_MISMATCH") return false;
    // WRONG_VERSION_NUMBER и прочие ERR_SSL_* — не доказательство: возможно,
    // на порту вообще не TLS. Оставляем «не проверено».
  }
  if (code === "EPROTO") return false;
  if (/sslv[23] alert|tlsv1 alert|protocol version|wrong version number/i.test(message)) {
    return false;
  }

  return null;
}

function checkOldTls(connectIp, port, hostname, signal, timeoutMs) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve(null);

    // timeoutMs уже ограничен остатком бюджета этапа TLS.
    const budget = Number.isFinite(timeoutMs) ? timeoutMs : OLD_TLS_TIMEOUT_MS;
    if (budget < MIN_ATTEMPT_MS) return resolve(null);

    const servername = net.isIP(hostname) ? undefined : hostname;

    let settled = false;
    let onAbort = null;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (signal && onAbort) signal.removeEventListener("abort", onAbort);
      resolve(value);
    };

    let socket;
    try {
      socket = tls.connect(
        {
          host: connectIp,
          port,
          servername,
          rejectUnauthorized: false,
          minVersion: "TLSv1",
          maxVersion: "TLSv1.1",
          ciphers: "ALL:@SECLEVEL=0", // Максимальная совместимость для детекта старых шифров
          signal,
        },
        () => {
          finish(true); // Если подключился — значит, поддерживает старые TLS
          socket.destroy();
        },
      );
    } catch {
      // Соединение не удалось даже начать — это неизвестность, а не отказ
      // сервера от старых протоколов.
      return resolve(null);
    }

    // Обработчик ошибок вешаем до проверки abort: destroy() на уже
    // отменённом сигнале может породить error, который нельзя оставлять
    // без слушателя.
    //
    // false — только доказанный отказ сервера (TLS-alert/EPROTO). Сетевые
    // ошибки (ECONNREFUSED, ECONNRESET, ETIMEDOUT) ничего не говорят о
    // поддержке старых протоколов: раньше закрытый порт давал зелёное
    // «протоколы отключены», хотя соединения не было вовсе.
    socket.on("error", (error) => finish(classifyOldTlsError(error)));

    if (signal) {
      onAbort = () => {
        socket.destroy();
        finish(null);
      };
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        socket.destroy();
        return finish(null);
      }
    }

    socket.setTimeout(budget, () => {
      socket.destroy();
      finish(null);
    });
  });
}

// Проверяет SSL-сертификат на указанном порту.
// connectIp — IP для подключения, hostname — для SNI (только если это домен, не IP).
// rejectUnauthorized: false нужен, чтобы ПРОЧИТАТЬ информацию о невалидных
// сертификатах (просроченных, самоподписанных) — иначе соединение оборвётся.
async function checkSSL(
  connectIp,
  port,
  hostname,
  signal,
  retries = 1,
  timeoutMs = 5000,
  deadline = null,
) {
  if (!port) return { hasSSL: false };
  if (!isLiteralIp(connectIp)) {
    return { hasSSL: false, error: "INVALID_CONNECT_IP" };
  }
  // Отмена до начала работы — локальный отказ: код должен отличаться от
  // сетевой ошибки, иначе вызывающий не поймёт, что скан отменён.
  if (signal?.aborted) {
    return { hasSSL: false, error: "ABORTED" };
  }

  const stage = stageDeadline(timeoutMs, deadline);

  return new Promise((resolve) => {
    let retryTimer = null;
    const settle = (data) => {
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      resolve(data);
    };

    const attempt = (attemptsLeft) => {
      const attemptTimeout = timeoutFor(timeoutMs, stage);
      if (attemptTimeout < MIN_ATTEMPT_MS) {
        // Бюджета нет вовсе: соединение не начиналось, и это не ошибка
        // рукопожатия — такой же таймаут скана.
        return settle({ hasSSL: false, error: "TIMEOUT" });
      }

      let settled = false;
      let mainSucceeded = false;
      let attemptFailed = false;
      // Причина текущего сбоя: без этого все отказы выглядели одинаково,
      // и отчёт не мог отличить таймаут от ошибки рукопожатия.
      let timedOut = false;
      const finish = (data) => {
        if (settled) return;
        settled = true;
        settle(data);
      };
      const onError = () => {
        if (mainSucceeded || attemptFailed) return;
        attemptFailed = true;

        if (signal?.aborted) {
          return finish({ hasSSL: false, error: "ABORTED" });
        }

        const retryFits = hasBudget(stage, RETRY_DELAY_MS + MIN_ATTEMPT_MS);
        if (attemptsLeft > 0 && retryFits) {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            attempt(attemptsLeft - 1);
          }, RETRY_DELAY_MS);
        } else {
          finish({
            hasSSL: false,
            error: timedOut ? "TIMEOUT" : "HANDSHAKE_FAILED",
          });
        }
      };

      const servername = net.isIP(hostname) ? undefined : hostname;

      let socket;
      try {
        socket = tls.connect(
          {
            host: connectIp,
            port,
            servername,
            rejectUnauthorized: false,
            ciphers: "DEFAULT@SECLEVEL=0",
            signal,
            minVersion: "TLSv1",
          },
          async () => {
            mainSucceeded = true;
            socket.setTimeout(0);
            try {
              const cert = socket.getPeerCertificate();
              if (!cert || !cert.valid_to) {
                socket.end();
                // TLS поднялся, но сертификат не разобран: это ошибка проверки,
                // а не «SSL нет». Иначе отчёт печатал бы no-ssl и потолок 30.
                return finish({
                  hasSSL: false,
                  error: "CERT_PARSE_FAILED",
                });
              }

              // Node может оставить authorizationError undefined у валидного
              // сертификата: приводим «нет ошибки» к null, иначе valid ложно
              // станет false и сайт получит bad-ssl.
              const verifyError = socket.authorizationError || null;
              const tlsVersion = socket.getProtocol();
              // Браузеры не подключаются по TLS 1.0/1.1. Такой сервер нельзя
              // считать «валидным» только потому, что цепочка формально сошлась:
              // иначе scoring начислит 12 баллов за протокол, которым нельзя
              // воспользоваться.
              const modernTls =
                tlsVersion === "TLSv1.2" || tlsVersion === "TLSv1.3";
              const valid = verifyError === null && modernTls;
              const daysLeft = Math.floor(
                (new Date(cert.valid_to) - Date.now()) / 86400000,
              );
              socket.end();

              // Старые протоколы — отдельная проба со своим бюджетом. Раньше
              // она получала только остаток 5-секундного этапа: медленный
              // основной хендшейк оставлял <1 с, проба отдавала null, и оценка
              // скакала на 10 баллов между одинаковыми сканами. Теперь у
              // проверки свой бюджет, ограниченный только общим дедлайном.
              let supportsOldTls = null;
              let oldTlsBudget = OLD_TLS_TIMEOUT_MS;
              if (Number.isFinite(deadline)) {
                oldTlsBudget = Math.min(
                  oldTlsBudget,
                  Math.max(0, deadline - Date.now()),
                );
              }
              if (oldTlsBudget >= OLD_TLS_MIN_MS) {
                try {
                  const oldTls = await checkOldTls(
                    connectIp,
                    port,
                    hostname,
                    signal,
                    oldTlsBudget,
                  );
                  if (typeof oldTls === "boolean") supportsOldTls = oldTls;
                } catch (e) {}
              }

              finish({
                hasSSL: true,
                valid,
                verifyError,
                daysLeft,
                validTo: cert.valid_to,
                validToISO: (() => {
                  if (!cert.valid_to) return null;
                  const d = new Date(cert.valid_to);
                  return Number.isNaN(d.getTime()) ? null : d.toISOString();
                })(),
                issuer:
                  sanitizeHeaderText(
                    cert.issuer?.O || cert.issuer?.CN || "неизвестен",
                  ) || "неизвестен",
                tlsVersion,
                supportsOldTls,
              });
            } catch (e) {
              socket.end();
              finish({ hasSSL: false, error: "CERT_PARSE_FAILED" });
            }
          },
        );
      } catch (error) {
        // Если соединение упало синхронно, возвращаем безопасный результат,
        // чтобы не ломать весь отчет.
        return finish({
          hasSSL: false,
          error: "HANDSHAKE_FAILED",
          errorCode: error.code || null,
        });
      }

      socket.on("error", onError);
      socket.setTimeout(attemptTimeout, () => {
        timedOut = true;
        socket.destroy();
        onError();
      });
    };
    attempt(retries);
  });
}

module.exports = { checkSSL, checkOldTls };
