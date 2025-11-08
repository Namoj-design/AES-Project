// client/utils/crypto.js
// Core cryptographic primitives for CipherChat
// ECDH (P-256) → HKDF-SHA256 → AES-GCM(256)

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Enable console logging for debugging
const DEBUG = false;
const debug = (...a) => { if (DEBUG) console.log('[crypto]', ...a); };

/* -------------------------------------------------------------
   ECDH key generation and import/export
------------------------------------------------------------- */

/** Generate a new ECDH key pair using P-256 curve */
export async function genECDH() {
  try {
    debug('Generating ECDH keypair...');
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
    debug('ECDH keypair generated.');
    return keyPair;
  } catch (err) {
    console.error('genECDH failed:', err);
    throw err;
  }
}

/** Export ECDH public key as Base64 (raw format) */
export async function exportPublicKeyBase64(pubKey) {
  const raw = await crypto.subtle.exportKey("raw", pubKey);
  return arrayBufferToBase64(raw);
}

/** Import ECDH public key from Base64 (raw) */
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

/* -------------------------------------------------------------
   AES key derivation from ECDH shared secret
------------------------------------------------------------- */

/**
 * Derive a 256-bit AES-GCM key using ECDH and HKDF.
 * Both peers derive the same key without exchanging it.
 */
export async function deriveAesKeyFromECDH(myPrivate, peerPublic, myPubRaw, peerPubRaw) {
  try {
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: peerPublic },
      myPrivate,
      256
    );

    // Deterministic salt from both public keys
    const a = new Uint8Array(myPubRaw);
    const b = new Uint8Array(peerPubRaw);
    const concat = compareUint8Arrays(a, b) <= 0 ? concatUint8(a, b) : concatUint8(b, a);
    const salt = await crypto.subtle.digest("SHA-256", concat);

    // HKDF → AES-GCM(256)
    const hkKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: encoder.encode("CipherChat AES-GCM key")
      },
      hkKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    debug('Derived AES-GCM key.');
    return aesKey;
  } catch (err) {
    console.error('deriveAesKeyFromECDH failed:', err);
    throw err;
  }
}

/* -------------------------------------------------------------
   AES-GCM encryption/decryption
------------------------------------------------------------- */

/** AES-GCM encrypt → returns {iv, ct} (both Base64) */
export async function encryptAesGcmBase64(aesKey, plaintext, aad = null) {
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const algo = { name: "AES-GCM", iv, tagLength: 128 };
    if (aad) algo.additionalData = encoder.encode(aad);

    const ctBuf = await crypto.subtle.encrypt(algo, aesKey, encoder.encode(plaintext));
    return {
      iv: arrayBufferToBase64(iv.buffer),
      ct: arrayBufferToBase64(ctBuf)
    };
  } catch (err) {
    console.error('encryptAesGcmBase64 failed:', err);
    throw err;
  }
}

/** AES-GCM decrypt with base64 inputs */
export async function decryptAesGcmBase64(aesKey, ivB64, ctB64, aad = null) {
  try {
    const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
    const ct = base64ToArrayBuffer(ctB64);
    const algo = { name: "AES-GCM", iv, tagLength: 128 };
    if (aad) algo.additionalData = encoder.encode(aad);

    const plainBuf = await crypto.subtle.decrypt(algo, aesKey, ct);
    return decoder.decode(plainBuf);
  } catch (err) {
    console.error('decryptAesGcmBase64 failed:', err);
    throw err;
  }
}

/* -------------------------------------------------------------
   Helpers: Base64 & Uint8 utils
------------------------------------------------------------- */

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