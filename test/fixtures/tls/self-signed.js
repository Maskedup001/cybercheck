// Самоподписанный сертификат для тестов TLS.
//
// OpenSSL в тестовом окружении недоступен, а `tls.createServer` нужен
// настоящий ключ и сертификат. Поэтому минимальный X.509 (v1, CN=localhost)
// собирается вручную из DER-примитивов и подписывается через crypto.sign.
// Сгенерированная пара кэшируется: генерация RSA-2048 не бесплатная, а
// сертификат нужен двум-трём тестам.

const crypto = require("node:crypto");

const OID_COMMON_NAME = "2.5.4.3";
const OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
const NULL_VALUE = Buffer.from([0x05, 0x00]);

// Длина в DER: короткая форма до 127 байт, дальше — с префиксом 0x80|n.
function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);

  const bytes = [];
  let rest = length;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

// Универсальный TLV: тег, длина, содержимое.
function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function sequence(...parts) {
  return tlv(0x30, Buffer.concat(parts));
}

function set(...parts) {
  return tlv(0x31, Buffer.concat(parts));
}

function integer(value) {
  const bytes = [];
  let rest = value;
  do {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  } while (rest > 0);

  // Старший бит означает отрицательное число — добавляем ведущий ноль.
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

function oid(dotted) {
  const parts = dotted.split(".").map(Number);
  const bytes = [parts[0] * 40 + parts[1]];

  for (const part of parts.slice(2)) {
    const chunk = [];
    let rest = part;
    do {
      chunk.unshift(rest & 0x7f);
      rest = Math.floor(rest / 128);
    } while (rest > 0);

    for (let index = 0; index < chunk.length - 1; index += 1) {
      chunk[index] |= 0x80;
    }
    bytes.push(...chunk);
  }

  return tlv(0x06, Buffer.from(bytes));
}

function utf8String(value) {
  return tlv(0x0c, Buffer.from(value, "utf8"));
}

function utcTime(value) {
  return tlv(0x17, Buffer.from(value, "ascii"));
}

function bitString(value) {
  // Нулевой байт — «лишних бит нет».
  return tlv(0x03, Buffer.concat([Buffer.from([0]), value]));
}

function commonNameName(value) {
  return sequence(set(sequence(oid(OID_COMMON_NAME), utf8String(value))));
}

function pem(label, der) {
  const base64 = der.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----\n`;
}

function createSelfSignedCertificate() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  const signatureAlgorithm = sequence(oid(OID_SHA256_WITH_RSA), NULL_VALUE);
  const issuer = commonNameName("localhost");

  const tbsCertificate = sequence(
    integer(1), // serialNumber
    signatureAlgorithm,
    issuer,
    // validity: 2025-01-01 — 2039-01-01 (UTCTime, до 2050)
    sequence(utcTime("250101000000Z"), utcTime("390101000000Z")),
    commonNameName("localhost"),
    publicKey.export({ type: "spki", format: "der" }),
  );

  const signature = crypto.sign("sha256", tbsCertificate, privateKey);
  const certificate = sequence(
    tbsCertificate,
    signatureAlgorithm,
    bitString(signature),
  );

  return {
    key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    cert: pem("CERTIFICATE", certificate),
  };
}

let cached = null;

function selfSignedCertificate() {
  if (!cached) cached = createSelfSignedCertificate();
  return cached;
}

module.exports = { selfSignedCertificate };
