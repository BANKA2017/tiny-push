//https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
const base64_to_buffer = function (base64) {
  let binaryString = atob(base64);
  let bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};
//https://stackoverflow.com/questions/56846930/how-to-convert-raw-representations-of-ecdh-key-pair-into-a-json-web-key
const hex_to_uintarray = (hex) => {
  const a = [];
  for (let i = 0, len = hex.length; i < len; i += 2) {
    a.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(a);
};
const buffer_to_base64 = (buf) => {
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (var i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
};
const base64_to_base64url = (base64) =>
  base64.replaceAll("/", "_").replaceAll("+", "-").replaceAll("=", "");
const base64url_to_base64 = (base64url) =>
  base64url.replaceAll("_", "/").replaceAll("-", "+");
//https://stackoverflow.co=/questions/40031688/javascript-arraybuffer-to-hex
const buffer_to_hex = function (buffer) {
  // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
};
//https://gist.github.com/72lions/4528834
const concatBuffer = function (...buffer) {
  const length = buffer.reduce((acc, cur) => acc + cur.byteLength, 0);
  let tmp = new Uint8Array(length);
  buffer.reduce((acc, cur) => {
    tmp.set(new Uint8Array(cur), acc);
    return acc + cur.byteLength;
  }, 0);
  return tmp.buffer;
};
const deriveSecretKey = function (privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: publicKey,
    },
    privateKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
};
const hmac_sha_256 = async function (key, data) {
  const keyData = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  return crypto.subtle.sign("HMAC", keyData, data);
};
const hkdf = async function (salt, ikm, info, length) {
  let key = await hmac_sha_256(salt, ikm);
  let signature = await hmac_sha_256(
    key,
    concatBuffer(info, new Uint8Array([1]).buffer)
  );
  return signature.slice(0, length);
};
const importECCKey = function (jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "ECDH",
      namedCurve: jwk.crv,
    },
    true,
    jwk.key_ops
  );
};
// note: eccKeyData is the subscriber's key object
const getAESGCMNonceAndCekAndContent = async function (
  publicKey,
  salt_,
  eccKeyData,
  auth,
  publicKeyBuffer
) {
  // Convert subscription public key into a buffer.
  const publishPublicKey = base64_to_buffer(base64url_to_base64(publicKey));
  const pubDH = await crypto.subtle.importKey(
    "raw",
    publishPublicKey,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );
  const ecdh_secret_handle = await deriveSecretKey(eccKeyData, pubDH);

  const ecdh_secret = await crypto.subtle.exportKey("raw", ecdh_secret_handle);
  //console.log(eccKeyData, base64_to_buffer(base64url_to_base64(cryptoKey.dh)), buffer_to_hex(ecdh_secret))
  // context
  // https://web.dev/articles/push-notifications-web-push-protocol#context
  const keyLabel = new TextEncoder("utf-8").encode("P-256\0");

  const publishPublicKeyLength = new Uint8Array(2);
  publishPublicKeyLength[0] = 0;
  publishPublicKeyLength[1] = publishPublicKey.byteLength;

  const subscriptionPublicKeyLength = new Uint8Array(2);
  subscriptionPublicKeyLength[0] = 0;
  subscriptionPublicKeyLength[1] = publicKeyBuffer.byteLength;

  const contextBuffer = concatBuffer(
    keyLabel.buffer,
    subscriptionPublicKeyLength.buffer,
    publicKeyBuffer,
    publishPublicKeyLength.buffer,
    publishPublicKey
  );
  const auth_secret = base64_to_buffer(base64url_to_base64(auth));
  const salt = base64_to_buffer(base64url_to_base64(salt_));

  const authEncBuff = new TextEncoder("utf-8").encode(
    "Content-Encoding: auth\0"
  );
  const prk = await hkdf(auth_secret, ecdh_secret, authEncBuff, 32);

  const nonceEncBuffer = new TextEncoder("utf-8").encode(
    "Content-Encoding: nonce\0"
  );
  const nonceInfo = concatBuffer(nonceEncBuffer, contextBuffer);

  const cekEncBuffer = new TextEncoder("utf-8").encode(
    "Content-Encoding: aesgcm\0"
  );
  const cekInfo = concatBuffer(cekEncBuffer, contextBuffer);

  // The nonce should be 12 bytes long
  const nonce = await hkdf(salt, prk, nonceInfo, 12);

  // The CEK should be 16 bytes long
  const contentEncryptionKey = await hkdf(salt, prk, cekInfo, 16);
  return { nonce, cek: contentEncryptionKey, content: contextBuffer };
};
const getAES128GCMNonceAndCekAndContent = async function (
  publicKey,
  salt_,
  eccKeyData,
  auth,
  publicKeyBuffer
) {
  // Convert subscription public key into a buffer.
  const publishPublicKey = base64_to_buffer(base64url_to_base64(publicKey));
  const pubDH = await crypto.subtle.importKey(
    "raw",
    publishPublicKey,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );
  const ecdh_secret_handle = await deriveSecretKey(eccKeyData, pubDH);

  const ecdh_secret = await crypto.subtle.exportKey("raw", ecdh_secret_handle);

  const auth_secret = base64_to_buffer(base64url_to_base64(auth));
  const salt = base64_to_buffer(base64url_to_base64(salt_));

  const key_info = concatBuffer(
    new TextEncoder("utf-8").encode("WebPush: info\0"),
    publicKeyBuffer,
    publishPublicKey
  );

  const PRK_key = await hmac_sha_256(auth_secret, ecdh_secret);

  let IKM = await hmac_sha_256(
    PRK_key,
    concatBuffer(key_info, new Uint8Array([1]).buffer)
  );
  let PRK = await hmac_sha_256(salt, IKM);
  let cek_info = new TextEncoder("utf-8").encode(
    "Content-Encoding: aes128gcm\0"
  );
  let contentEncryptionKey = (
    await hmac_sha_256(PRK, concatBuffer(cek_info, new Uint8Array([1]).buffer))
  ).slice(0, 16);
  let nonce_info = new TextEncoder("utf-8").encode("Content-Encoding: nonce\0");
  let nonce = (
    await hmac_sha_256(
      PRK,
      concatBuffer(nonce_info, new Uint8Array([1]).buffer)
    )
  ).slice(0, 12);

  return { nonce, cek: contentEncryptionKey, content: key_info };
};
const getNonce = function (nonce, offset) {
  if (offset > 0) {
    nonce = new Uint8Array(nonce);
    return nonce.map((byte, index) => {
      if (index < 6) {
        return byte;
      } else {
        return byte ^ ((offset / Math.pow(256, 12 - 1 - index)) & 0xff);
      }
    });
  }
  return nonce;
};
const splitData = function (data, size) {
  const result = [];
  for (let i = 0; i < data.byteLength; i += size) {
    result.push(data.slice(i, i + size));
  }
  return result;
};
// TODO padding
const encrypt = async function (
  nonce,
  contentEncryptionKey,
  dataBuffer,
  rs = 0,
  encoding = "aesgcm"
) {
  const cek = await crypto.subtle.importKey(
    "raw",
    contentEncryptionKey,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: getNonce(nonce, 0) },
    cek,
    concatBuffer(new Uint8Array(2).fill(0).buffer, dataBuffer)
  );
  return { data, padding: { length: 0 } };
};
const decrypt = async function (
  nonce,
  contentEncryptionKey,
  dataBuffer,
  rs = 0,
  encoding = "aesgcm"
) {
  const cek = await crypto.subtle.importKey(
    "raw",
    contentEncryptionKey,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );

  let bufferChunk = [];
  if (rs < 18) {
    bufferChunk.push(dataBuffer);
  } else {
    bufferChunk.push(...splitData(dataBuffer, rs));
  }

  const decodedChunk = await Promise.all(
    bufferChunk.map(async (chunk, index) => {
      let decodedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: getNonce(nonce, index) },
        cek,
        chunk
      );
      let paddingLength = 0;
      if (encoding === "aes128gcm") {
        let i = decodedBuffer.byteLength - 1;
        let tmpDecodedBuffer = new Uint8Array(decodedBuffer);
        while (tmpDecodedBuffer[i--] === 0) {
          paddingLength++;
        }
        decodedBuffer = decodedBuffer.slice(
          0,
          decodedBuffer.byteLength - paddingLength - 1
        );
      } else {
        paddingLength = new DataView(decodedBuffer.slice(0, 2)).getUint8();
        decodedBuffer = decodedBuffer.slice(2 + paddingLength);
      }

      //const padding = decodedBuffer.slice(2, 2 + paddingLength)
      return { data: decodedBuffer, padding: { length: paddingLength } };
    })
  );
  //console.log(decodedChunk)
  //console.log({ data: concatBuffer(...decodedChunk.map(chunk => chunk.data)), padding: { length: decodedChunk[0].padding.length }, chunk: decodedChunk })
  return {
    data: concatBuffer(...decodedChunk.map((chunk) => chunk.data)),
    padding: { length: decodedChunk[0].padding.length },
    chunk: decodedChunk,
  };
};
const decryptMessage = async function (eventMessage) {
  const { data: message, key: eccKeyData, public_key, auth } = eventMessage;
  const encoding = message.headers.encoding;

  let dh,
    salt,
    rs,
    messageData,
    nonce,
    contentEncryptionKey,
    contextBuffer,
    text;

  if (encoding === "aesgcm") {
    const cryptoKey = Object.fromEntries(
      message.headers.crypto_key.split(";").map((key) => key.split("="))
    );
    const encryption = Object.fromEntries(
      message.headers.encryption.split(";").map((key) => key.split("="))
    );
    dh = cryptoKey.dh;
    salt = encryption.salt;
    rs = encryption?.rs !== undefined ? encryption.rs : 0;
    messageData = base64_to_buffer(base64url_to_base64(message.data));

    const tmp = await getAESGCMNonceAndCekAndContent(
      dh,
      salt,
      eccKeyData,
      auth,
      public_key
    );
    nonce = tmp.nonce;
    contentEncryptionKey = tmp.cek;
    contextBuffer = tmp.content;

    text = (
      await decrypt(nonce, contentEncryptionKey, messageData, rs, "aesgcm")
    ).data;
  } else if (encoding === "aes128gcm") {
    const messageDataBuffer = base64_to_buffer(
      base64url_to_base64(message.data)
    );
    salt = base64_to_base64url(
      buffer_to_base64(messageDataBuffer.slice(0, 16))
    );
    //idlen = new DataView(messageData.slice(20, 21)).getUint8()// 65
    dh = base64_to_base64url(buffer_to_base64(messageDataBuffer.slice(21, 86)));
    rs = new DataView(messageDataBuffer.slice(16, 20)).getUint32();
    messageData = messageDataBuffer.slice(86);

    const tmp = await getAES128GCMNonceAndCekAndContent(
      dh,
      salt,
      eccKeyData,
      auth,
      public_key
    );
    nonce = tmp.nonce;
    contentEncryptionKey = tmp.cek;
    contextBuffer = tmp.content;

    text = (
      await decrypt(nonce, contentEncryptionKey, messageData, rs, "aes128gcm")
    ).data;
  } else {
    console.log("Unsupported encoding");
    return {
      data: "",
      original_data: message,
      key_pair: eccKeyData,
      key_data: eccKeyData,
      auth: auth,
      dh,
      salt,
      context: "",
      nonce: "",
      content_encryption_key: "",
      encoding,
      timestamp: Date.now(),
    };
  }

  //console.log(nonce, contentEncryptionKey, messageData)

  return {
    data: new TextDecoder("utf-8").decode(text),
    original_data: message,
    key_pair: eccKeyData,
    key_data: eccKeyData,
    auth: auth,
    dh,
    salt,
    context: base64_to_base64url(buffer_to_base64(contextBuffer)),
    nonce: buffer_to_base64(nonce),
    content_encryption_key: buffer_to_base64(contentEncryptionKey),
    encoding,
    timestamp: Date.now(),
  };
};
