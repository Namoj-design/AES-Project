// --- Utility helpers ---
const enc = new TextEncoder();
const dec = new TextDecoder();

const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

const log = (...args) => {
  const el = document.getElementById("log");
  el.textContent += args.join(" ") + "\n";
  el.scrollTop = el.scrollHeight;
};

// --- Crypto helpers ---
async function genECDH() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
}
async function exportPub(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return toB64(raw);
}
async function importPub(b64) {
  const raw = fromB64(b64).buffer;
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
}
async function deriveAESGCMKey(priv, pub) {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: pub },
    priv,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
function randomIV() {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return iv;
}
async function aesGcmEncrypt(key, plaintext, aad) {
  const iv = randomIV();
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad ? enc.encode(aad) : undefined, tagLength: 128 },
    key,
    enc.encode(plaintext)
  );
  return { iv: toB64(iv.buffer), ct: toB64(ct) };
}
async function aesGcmDecrypt(key, ivB64, ctB64, aad) {
  const iv = fromB64(ivB64);
  const ct = fromB64(ctB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad ? enc.encode(aad) : undefined, tagLength: 128 },
    key,
    ct.buffer
  );
  return dec.decode(pt);
}

// --- State ---
let aliceKeys = null, aliceAES = null;
let bobKeys = null, bobAES = null;

// --- Alice ---
document.getElementById("alice-gen").onclick = async () => {
  aliceKeys = await genECDH();
  const pub = await exportPub(aliceKeys.publicKey);
  document.getElementById("alice-pub").value = pub;
  log("[Alice] Keypair generated.");
  document.getElementById("alice-status").textContent = "Keypair ready. Share with Bob.";
};

document.getElementById("alice-derive").onclick = async () => {
  try {
    if (!aliceKeys) throw new Error("Generate Alice keys first.");
    const peerB64 = document.getElementById("alice-peer").value.trim();
    if (!peerB64) throw new Error("Paste Bob's public key.");
    const peerKey = await importPub(peerB64);
    aliceAES = await deriveAESGCMKey(aliceKeys.privateKey, peerKey);
    document.getElementById("alice-status").textContent = "AES key derived (Alice).";
    log("[Alice] Derived AES key from ECDH.");
  } catch (e) { alert(e.message); }
};

document.getElementById("alice-encrypt").onclick = async () => {
  try {
    if (!aliceAES) throw new Error("Derive Alice AES key first.");
    const pt = document.getElementById("alice-plaintext").value || "";
    const { iv, ct } = await aesGcmEncrypt(aliceAES, pt, "alice|msg");
    document.getElementById("alice-ciphertext").value = iv + "|" + ct;
    log("[Alice] Encrypted message ready.");
  } catch (e) { alert(e.message); }
};

// --- Bob ---
document.getElementById("bob-gen").onclick = async () => {
  bobKeys = await genECDH();
  const pub = await exportPub(bobKeys.publicKey);
  document.getElementById("bob-pub").value = pub;
  log("[Bob] Keypair generated.");
  document.getElementById("bob-status").textContent = "Keypair ready. Share with Alice.";
};

document.getElementById("bob-derive").onclick = async () => {
  try {
    if (!bobKeys) throw new Error("Generate Bob keys first.");
    const peerB64 = document.getElementById("bob-peer").value.trim();
    if (!peerB64) throw new Error("Paste Alice's public key.");
    const peerKey = await importPub(peerB64);
    bobAES = await deriveAESGCMKey(bobKeys.privateKey, peerKey);
    document.getElementById("bob-status").textContent = "AES key derived (Bob).";
    log("[Bob] Derived AES key from ECDH.");
  } catch (e) { alert(e.message); }
};

document.getElementById("bob-decrypt").onclick = async () => {
  try {
    if (!bobAES) throw new Error("Derive Bob AES key first.");
    const blob = document.getElementById("bob-recv").value.trim();
    if (!blob) throw new Error("Paste ciphertext (iv|ct).");
    const [ivB64, ctB64] = blob.split("|");
    const pt = await aesGcmDecrypt(bobAES, ivB64, ctB64, "alice|msg");
    document.getElementById("bob-plaintext").value = pt;
    log("[Bob] Decrypted message:", pt);
  } catch (e) {
    log("[Bob] Decrypt error:", e.message);
    alert("Decrypt failed: " + e.message);
  }
};

// Quick select on click
["alice-pub", "bob-pub"].forEach(id => {
  document.getElementById(id).onclick = function() { this.select(); };
});