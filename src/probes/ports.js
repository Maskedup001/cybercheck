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
// скана. Если соединение установилось — порт открыт. Таймаут или ошибка —
// порт закрыт.
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
      socket.on("timeout", () => socket.destroy());
      socket.on("error", (err) => {
        // При явном отказе ретрай бессмыслен
        if (err.code === "ECONNREFUSED") status = "refused";
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
        if (status === "closed" && attemptsLeft > 0 && retryFits) {
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
