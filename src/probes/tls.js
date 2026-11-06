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

// Проверка старых TLS — отдельное соединение. Если на неё осталось меньше
// секунды, результат всё равно недостоверен, а бюджет этапа будет съеден.
const OLD_TLS_TIMEOUT_MS = 3000;
const OLD_TLS_MIN_MS = 1000;

// Попытка короче 50 мс не успевает даже на TCP-хендшейк.
const MIN_ATTEMPT_MS = 50;

// Проверяет, принимает ли сервер устаревшие версии TLS (1.0 / 1.1).
// timeoutMs — остаток бюджета этапа TLS, а не фиксированные 3 секунды.
function checkOldTls(connectIp, port, hostname, signal, timeoutMs) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve(false);

    // timeoutMs уже ограничен остатком бюджета этапа TLS.
    const budget = Number.isFinite(timeoutMs) ? timeoutMs : OLD_TLS_TIMEOUT_MS;
    if (budget < MIN_ATTEMPT_MS) return resolve(false);

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
      return resolve(false);
    }

    // Обработчик ошибок вешаем до проверки abort: destroy() на уже
    // отменённом сигнале может породить error, который нельзя оставлять
    // без слушателя.
    socket.on("error", () => finish(false));

    if (signal) {
      onAbort = () => {
        socket.destroy();
        finish(false);
      };
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        socket.destroy();
        return finish(false);
      }
    }

    socket.setTimeout(budget, () => {
      socket.destroy();
      finish(false);
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
        return settle({ hasSSL: false, error: "HANDSHAKE_FAILED" });
      }

      let settled = false;
      let mainSucceeded = false;
      let attemptFailed = false;
      const finish = (data) => {
        if (settled) return;
        settled = true;
        settle(data);
      };
      const onError = () => {
        if (mainSucceeded || attemptFailed) return;
        attemptFailed = true;

        if (signal?.aborted) {
          return finish({ hasSSL: false, error: "HANDSHAKE_FAILED" });
        }

        const retryFits = hasBudget(
          stage,
          RETRY_DELAY_MS + MIN_ATTEMPT_MS,
        );
        if (attemptsLeft > 0 && retryFits) {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            attempt(attemptsLeft - 1);
          }, RETRY_DELAY_MS);
        } else {
          finish({ hasSSL: false, error: "HANDSHAKE_FAILED" });
        }
      };

      const servername = net.isIP(hostname) ? undefined : hostname;
      const socket = tls.connect(
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

            // Старые протоколы проверяются только на остаток бюджета этапа:
            // иначе успешный хендшейк добавлял к этапу фиксированные 3 с.
            let supportsOldTls = false;
            if (hasBudget(stage, OLD_TLS_MIN_MS)) {
              try {
                supportsOldTls = await checkOldTls(
                  connectIp,
                  port,
                  hostname,
                  signal,
                  timeoutFor(OLD_TLS_TIMEOUT_MS, stage),
                );
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

      socket.on("error", onError);
      socket.setTimeout(attemptTimeout, () => {
        socket.destroy();
        onError();
      });
    };
    attempt(retries);
  });
}

module.exports = { checkSSL, checkOldTls };
