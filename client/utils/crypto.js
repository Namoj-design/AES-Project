// client/utils/crypto.js
// Exports: genECDH, exportPublicKeyBase64, importPublicKeyBase64,
// deriveAesKeyFromECDH, encryptAesGcmBase64, decryptAesGcmBase64

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** generate an ECDH P-256 keypair (extractable=false for private) */
export async function genECDH() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true, // public extractable so we can export; private remains extractable true for demo (set false in prod)
    ["deriveKey", "deriveBits"]
  );
}

/** export CryptoKey public part to base64 (raw) */
export async function exportPublicKeyBase64(pubKey) {
  const raw = await crypto.subtle.exportKey("raw", pubKey); // ArrayBuffer
  return arrayBufferToBase64(raw);
}

/** import raw public key (base64) */
export async function importPublicKeyBase64(b64) {
  const raw = base64ToArrayBuffer(b64);
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

/**
 * derive AES-GCM 256-bit key from myPrivateKey and peerPublicKey.
 * Steps:
 *  1. deriveBits(ECDH) -> raw shared secret (256 bits)
 *  2. compute deterministic salt (optional) or use empty salt; here we use HKDF with salt = SHA-256(sorted(pubA||pubB))
 *  3. import shared bits as HKDF key material and derive AES-GCM key
 */
export async function deriveAesKeyFromECDH(myPrivateKey, peerPublicKey, myPublicRaw, peerPublicRaw) {
  // 1) derive raw shared bits - 256 bits
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    myPrivateKey,
    256
  ); // ArrayBuffer

  // 2) deterministic salt: SHA-256(concat(min(pubA,pubB), max(...)))
  // both parties must compute same salt without further exchange.
  const a = new Uint8Array(myPublicRaw);
  const b = new Uint8Array(peerPublicRaw);
  const concat = compareUint8Arrays(a, b) <= 0 ? concatUint8(a, b) : concatUint8(b, a);
  const salt = await crypto.subtle.digest("SHA-256", concat);

  // 3) HKDF: import sharedBits as raw key, derive AES-GCM 256 key
  const hkKey = await crypto.subtle.importKey("raw", sharedBits, { name: "HKDF" }, false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt,
      info: encoder.encode("CipherChat AES-GCM key")
    },
    hkKey,
    { name: "AES-GCM", length: 256 },
    false, // not extractable
    ["encrypt", "decrypt"]
  );
  return aesKey;
}

/** AES-GCM encrypt -> returns { iv: base64, ct: base64 } where ct includes auth tag */
export async function encryptAesGcmBase64(aesKey, plaintext, aad = undefined) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV (recommended)
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad ? encoder.encode(aad) : undefined, tagLength: 128 },
    aesKey,
    encoder.encode(plaintext)
  );
  return {
    iv: arrayBufferToBase64(iv.buffer),
    ct: arrayBufferToBase64(ctBuf)
  };
}

/** AES-GCM decrypt with base64 inputs */
export async function decryptAesGcmBase64(aesKey, ivB64, ctB64, aad = undefined) {
  const iv = base64ToArrayBuffer(ivB64);
  const ct = base64ToArrayBuffer(ctB64);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv), additionalData: aad ? encoder.encode(aad) : undefined, tagLength: 128 },
    aesKey,
    ct
  );
  return decoder.decode(plainBuf);
}

/* ----------------- helpers ----------------- */

export function arrayBufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
export function base64ToArrayBuffer(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}
function compareUint8Arrays(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}
function concatUint8(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out.buffer;
}