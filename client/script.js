const logBox = document.getElementById("log");
const log = msg => {
  const time = new Date().toLocaleTimeString();
  logBox.innerHTML += `[${time}] ${msg}\n`;
  logBox.scrollTop = logBox.scrollHeight;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let aesKey = null;
let iv = null;

// --- Generate AES Key ---
async function generateAESKey() {
  aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  log("✅ AES-256 key generated successfully.");
}

// --- Encrypt Message ---
async function encryptMessage() {
  const text = document.getElementById("plaintext").value;
  if (!text) return alert("Enter plaintext first!");
  if (!aesKey) return alert("Generate the AES key first!");

  iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = encoder.encode(text);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoded
  );

  const ctBase64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  document.getElementById("ciphertext").value = ctBase64;
  document.getElementById("iv-display").value = Array.from(iv).map(x => x.toString(16).padStart(2, "0")).join(" ");

  log(`🔐 Encrypted "${text}" with AES-GCM.`);
  log(`IV: [${Array.from(iv).map(x => x.toString(16).padStart(2, '0')).join(' ')}]`);
  log(`Ciphertext length: ${ciphertext.byteLength} bytes`);
}

// --- Decrypt Message ---
async function decryptMessage() {
  if (!aesKey) return alert("Generate AES key first!");
  if (!iv) return alert("No IV found. Encrypt something first!");

  const ctBase64 = document.getElementById("ciphertext").value.trim();
  if (!ctBase64) return alert("No ciphertext to decrypt!");

  const bytes = Uint8Array.from(atob(ctBase64), c => c.charCodeAt(0));
  try {
    const plainBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      bytes
    );
    const decryptedText = decoder.decode(plainBuffer);
    document.getElementById("decrypted").value = decryptedText;
    log(`✅ Decrypted successfully. Message: "${decryptedText}"`);
  } catch (err) {
    log(`❌ Decryption failed: ${err.message}`);
    alert("Decryption failed (possible IV/key mismatch).");
  }
}

// --- Bind Buttons ---
document.getElementById("generate-key").addEventListener("click", generateAESKey);
document.getElementById("encrypt-btn").addEventListener("click", encryptMessage);
document.getElementById("decrypt-btn").addEventListener("click", decryptMessage);