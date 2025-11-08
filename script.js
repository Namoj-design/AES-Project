// Utility helpers
const enc = new TextEncoder();
const dec = new TextDecoder();

const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
const log = msg => {
  const logBox = document.getElementById('log');
  logBox.textContent += msg + "\n";
  logBox.scrollTop = logBox.scrollHeight;
};

// Global states
let aliceKeys, aliceAES, bobKeys, bobAES;

// === WebCrypto core ===
async function genECDH() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
}

async function exportPub(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return toB64(raw);
}

async function importPub(b64) {
  const raw = fromB64(b64).buffer;
  return crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

async function deriveAESGCMKey(priv, pub) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: pub },
    priv,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function randomIV() {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return iv;
}

async function aesGcmEncrypt(key, plaintext, aad = '') {
  const iv = randomIV();
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad), tagLength: 128 },
    key,
    enc.encode(plaintext)
  );
  return { iv: toB64(iv.buffer), ct: toB64(cipher) };
}

async function aesGcmDecrypt(key, ivB64, ctB64, aad = '') {
  const iv = fromB64(ivB64);
  const cipher = fromB64(ctB64);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(aad), tagLength: 128 },
    key,
    cipher.buffer
  );
  return dec.decode(plain);
}

// === ALICE ===
document.getElementById('alice-gen').onclick = async () => {
  aliceKeys = await genECDH();
  const pub = await exportPub(aliceKeys.publicKey);
  document.getElementById('alice-pub').value = pub;
  log('[Alice] Keypair generated.');
  document.getElementById('alice-status').textContent = 'Public key ready.';
};

document.getElementById('alice-derive').onclick = async () => {
  const peer = document.getElementById('alice-peer').value.trim();
  if (!peer) return alert('Paste Bob public key first.');
  const peerKey = await importPub(peer);
  aliceAES = await deriveAESGCMKey(aliceKeys.privateKey, peerKey);
  document.getElementById('alice-status').textContent = 'Shared AES key derived.';
  log('[Alice] Derived AES key.');
};

document.getElementById('alice-encrypt').onclick = async () => {
  if (!aliceAES) return alert('Derive AES key first.');
  const msg = document.getElementById('alice-plaintext').value;
  const { iv, ct } = await aesGcmEncrypt(aliceAES, msg, 'alice-msg');
  document.getElementById('alice-ciphertext').value = iv + '|' + ct;
  log('[Alice] Encrypted message ready.');
};

// === BOB ===
document.getElementById('bob-gen').onclick = async () => {
  bobKeys = await genECDH();
  const pub = await exportPub(bobKeys.publicKey);
  document.getElementById('bob-pub').value = pub;
  log('[Bob] Keypair generated.');
  document.getElementById('bob-status').textContent = 'Public key ready.';
};

document.getElementById('bob-derive').onclick = async () => {
  const peer = document.getElementById('bob-peer').value.trim();
  if (!peer) return alert('Paste Alice public key first.');
  const peerKey = await importPub(peer);
  bobAES = await deriveAESGCMKey(bobKeys.privateKey, peerKey);
  document.getElementById('bob-status').textContent = 'Shared AES key derived.';
  log('[Bob] Derived AES key.');
};

document.getElementById('bob-decrypt').onclick = async () => {
  if (!bobAES) return alert('Derive AES key first.');
  const blob = document.getElementById('bob-recv').value.trim();
  const [iv, ct] = blob.split('|');
  if (!iv || !ct) return alert('Invalid ciphertext format.');
  try {
    const msg = await aesGcmDecrypt(bobAES, iv, ct, 'alice-msg');
    document.getElementById('bob-plaintext').value = msg;
    log('[Bob] Decrypted message: ' + msg);
  } catch (err) {
    alert('Decryption failed: ' + err.message);
    log('[Bob] Auth/decrypt error.');
  }
};