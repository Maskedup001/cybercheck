const net = require("node:net");
const {
  isLiteralIp,
  stageDeadline,
  timeoutFor,
  hasBudget,
} = require("../utils/scan-helpers");

// Паузы между попытками. Они входят в бюджет этапа, а не добавляются к нему.
const RETRY_DELAY_MS = 500;

// Попытка короче 50 мс не успевает даже на TCP-хендшейк: считаем, что
// времени не осталось, и не открываем сокет.
const MIN_ATTEMPT_MS = 50;

// Проверяет, открыт ли указанный порт.
// connectIp — уже проверенный IP-адрес (не hostname!), это важно для SSRF-защиты.
// timeoutMs — бюджет всего этапа (все попытки вместе), deadline — дедлайн
// скана.
//
// Статусы:
//   open     — TCP-соединение установилось;
//   refused  — RST (ECONNREFUSED): доказано, что слушателя на порту нет;
//   filtered — таймаут/DROP или сетевая ошибка (EACCES, EHOSTUNREACH,
//              ETIMEDOUT, ECONNRESET): состояние порта неизвестно, пакет мог
//              отбросить firewall;
//   closed   — только локальный отказ до сети (невалидный IP, отмена signal,
//              исчерпанный бюджет). Про удалённый хост это ничего не говорит.
function checkPort(
  connectIp,
  port,
  timeoutMs = 3000,
  retries = 1,
  signal,
  deadline = null,
) {
  if (!isLiteralIp(connectIp)) {
    return Promise.resolve({ port, status: "closed" });
  }

  const stage = stageDeadline(timeoutMs, deadline);

  return new Promise((resolve) => {
    // Таймер ретрая храним, чтобы снять его при завершении: иначе после
    // отмены или дедлайна он мог бы запустить лишнюю попытку и подержать
    // процесс.
    let retryTimer = null;
    const settle = (result) => {
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      resolve(result);
    };

    const attempt = (attemptsLeft) => {
      if (signal?.aborted) return settle({ port, status: "closed" });

      // Остаток бюджета этапа считаем перед каждой попыткой: ретрай не
      // должен получать свежие 3 секунды после того, как первая попытка
      // уже израсходовала бюджет.
      const attemptTimeout = timeoutFor(timeoutMs, stage);
      if (attemptTimeout < MIN_ATTEMPT_MS) {
        return settle({ port, status: "closed" });
      }

      const socket = new net.Socket();
      let status = "closed";
      // Быстрый сбой (не таймаут) иногда проходит со второй попытки;
      // таймаут уже израсходовал бюджет попытки, и повтор только отнимет
      // время у следующих портов.
      let retryableFailure = false;

      const onAbort = () => {
        socket.destroy();
        settle({ port, status: "closed" });
      };
      if (signal) signal.addEventListener("abort", onAbort, { once: true });

      socket.setTimeout(attemptTimeout);
      socket.on("connect", () => {
        status = "open";
        socket.destroy();
      });
      socket.on("timeout", () => {
        status = "filtered";
        retryableFailure = false;
        socket.destroy();
      });
      socket.on("error", (err) => {
        // При явном отказе ретрай бессмыслен: RST уже доказал отсутствие
        // слушателя. Любая другая ошибка — неизвестность, но быстрая:
        // повторить её имеет смысл, если на ретрай остался бюджет.
        if (err.code === "ECONNREFUSED") {
          status = "refused";
        } else {
          status = "filtered";
          retryableFailure = true;
        }
      });
      socket.on("close", () => {
        if (signal) signal.removeEventListener("abort", onAbort);
        if (signal?.aborted) return;

        // Ретрай имеет смысл только для быстрого сбоя (отказ, сброс) и
        // только если на него вместе с паузой остался бюджет.
        const retryFits = hasBudget(
          stage,
          RETRY_DELAY_MS + MIN_ATTEMPT_MS,
        );
        if (retryableFailure && attemptsLeft > 0 && retryFits) {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            attempt(attemptsLeft - 1);
          }, RETRY_DELAY_MS);
        } else {
          settle({ port, status });
        }
      });
      socket.connect(port, connectIp);
    };
    attempt(retries);
  });
}

module.exports = { checkPort, MIN_ATTEMPT_MS, RETRY_DELAY_MS };
