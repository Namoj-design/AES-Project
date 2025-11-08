/* script.js
   Client-side logic for secure chat:
   - Connects to relay WebSocket server (ws://localhost:8080)
   - Generates ECDH P-256 keypair, exports public key (raw)
   - Broadcasts public key (base64). On receiving peer pubkey, both sides:
       * import peer pubkey
       * derive ECDH shared secret (deriveBits)
       * compute deterministic salt = SHA-256(min(pubA,pubB)||max(...))
       * import shared as HKDF base key and derive AES-GCM-256 via HKDF-SHA256
   - AES-GCM used with random 12-byte IV per message; ciphertext base64 encoded
   - Server relays messages only (does not decrypt)
*/

const WS_URL = (location.hostname === 'localhost' ? 'ws://localhost:8080' : 'wss://' + location.host + ':8080');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const $ = id => document.getElementById(id);
const nameInput = $('name');
const connectBtn = $('connect');
const genKeyBtn = $('genKey');
const sendPubBtn = $('sendPub');
const statusEl = $('status');
const messages = $('messages');
const logEl = $('log');
const msgIn = $('message');
const sendBtn = $('send');

// state
let ws = null;
let myKeys = null;      // { publicKey, privateKey } CryptoKeys
let myPubRaw = null;    // ArrayBuffer of exported raw public key
let peerPubRaw = null;  // ArrayBuffer of peer raw public key
let aesKey = null;      // CryptoKey AES-GCM

// Logging
function log(s) {
  const t = new Date().toLocaleTimeString();
  logEl.textContent += `[${t}] ${s}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

// UI helpers
function appendMessage(who, text, cls = 'peer') {
  const node = document.createElement('div');
  node.className = 'msg ' + (cls === 'me' ? 'me' : 'peer');
  node.innerHTML = `<div class="meta">${who}</div><div class="body">${escapeHtml(text)}</div>`;
  messages.appendChild(node);
  messages.scrollTop = messages.scrollHeight;
}
function escapeHtml(s) {
  return s.replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// WebSocket connect/disconnect
connectBtn.onclick = () => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.close();
    connectBtn.textContent = 'Connect';
    statusEl.textContent = 'Disconnected';
    log('Disconnected from relay.');
    return;
  }

  ws = new WebSocket(WS_URL);
  ws.onopen = () => {
    connectBtn.textContent = 'Disconnect';
    statusEl.textContent = 'Connected to relay';
    log('Connected to relay server: ' + WS_URL);
    genKeyBtn.disabled = false;
    sendPubBtn.disabled = true;
  };
  ws.onmessage = async (ev) => {
    try {
      const msg = JSON.parse(ev.data);
      await handleMessage(msg);
    } catch (e) {
      console.warn('Bad message', e);
    }
  };
  ws.onclose = () => {
    statusEl.textContent = 'Disconnected';
    connectBtn.textContent = 'Connect';
    genKeyBtn.disabled = true;
    sendPubBtn.disabled = true;
    sendBtn.disabled = true;
    log('Relay connection closed.');
  };
  ws.onerror = (e) => {
    console.error('WS error', e);
    log('WebSocket error: ' + (e.message || 'unknown'));
  };
};

// generate ECDH keypair (P-256)
genKeyBtn.onclick = async () => {
  try {
    myKeys = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    myPubRaw = await crypto.subtle.exportKey('raw', myKeys.publicKey); // ArrayBuffer
    sendPubBtn.disabled = false;
    log('ECDH keypair generated (P-256).');
    statusEl.textContent = 'Keypair ready. Send public key to peer.';
  } catch (e) {
    console.error(e);
    log('Key generation failed: ' + e.message);
  }
};

// send our public key (base64) to relay
sendPubBtn.onclick = () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) return alert('Connect to relay first.');
  if (!myPubRaw) return alert('Generate keypair first.');
  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(myPubRaw)));
  ws.send(JSON.stringify({ type: 'pubkey', pub: pubB64, name: nameInput.value || 'anon' }));
  log('Sent public key (broadcast).');
  sendPubBtn.disabled = true;
};

// handle incoming server messages
async function handleMessage(msg) {
  if (!msg.type) return;
  if (msg.type === 'pubkey') {
    // Received a peer public key
    if (!peerPubRaw) {
      peerPubRaw = base64ToArrayBuffer(msg.pub);
      log(`Received peer public key (from ${msg.name || 'peer'})`);
      await deriveSharedKeyIfReady();
    } else {
      // Received new pubkey -> replace and re-derive
      peerPubRaw = base64ToArrayBuffer(msg.pub);
      log('Updated peer public key; re-deriving shared key.');
      await deriveSharedKeyIfReady();
    }
    return;
  }

  if (msg.type === 'cipher') {
    // decrypted at client using derived AES key
    if (!aesKey) {
      log('Received ciphertext but AES key not ready yet.');
      return;
    }
    try {
      const pt = await decryptMessage(msg.iv, msg.ct);
      appendMessage(msg.from || 'peer', pt, 'peer');
      log('Decrypted incoming message.');
    } catch (e) {
      log('Failed to decrypt incoming message: ' + (e.message || e));
    }
    return;
  }

  if (msg.type === 'hello') {
    log(`Peer presence: ${msg.name || 'peer'}`);
  }
}

// attempt derive AES key if both sides have key material
async function deriveSharedKeyIfReady() {
  if (!myPubRaw || !peerPubRaw || !myKeys) return;

  try {
    // Import peer public key
    const peerPub = await crypto.subtle.importKey('raw', peerPubRaw, { name:'ECDH', namedCurve:'P-256' }, true, []);

    // Derive raw shared secret bits (here 256 bits)
    const sharedBits = await crypto.subtle.deriveBits({ name:'ECDH', public: peerPub }, myKeys.privateKey, 256);

    // Compute deterministic salt = SHA-256(min(pubA,pubB) || max(pubA,pubB))
    const a = new Uint8Array(myPubRaw);
    const b = new Uint8Array(peerPubRaw);
    // lexicographic min/max
    const abConcat = (compareArrays(a,b) <= 0) ? concatUint8(a,b) : concatUint8(b,a);
    const saltBuf = await crypto.subtle.digest('SHA-256', abConcat);

    // Import shared bits as raw key for HKDF
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, { name:'HKDF' }, false, ['deriveKey']);

    // Derive AES-GCM 256-bit key via HKDF-SHA256
    aesKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: saltBuf,
        info: encoder.encode('ECDH AES-GCM key') // context
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    log('Derived AES-GCM (256) shared key via HKDF-SHA256.');
    statusEl.textContent = 'Shared symmetric key ready.';
    sendBtn.disabled = false;
  } catch (e) {
    console.error(e);
    log('Error deriving shared key: ' + e.message);
  }
}

// helpers: arraybuffer <-> base64
function base64ToArrayBuffer(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}
function arrayBufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function compareArrays(a,b) {
  // lexicographic compare
  const n = Math.min(a.length, b.length);
  for (let i=0;i<n;i++){
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}
function concatUint8(a,b) {
  const c = new Uint8Array(a.length + b.length);
  c.set(a,0);
  c.set(b,a.length);
  return c.buffer;
}

// encrypt and send message
sendBtn.onclick = async () => {
  const text = msgIn.value.trim();
  if (!text) return;
  if (!aesKey) return alert('Shared AES key not ready. Ensure both peers exchanged public keys.');

  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctBuf = await crypto.subtle.encrypt(
      { name:'AES-GCM', iv, additionalData: encoder.encode('chat-aad'), tagLength: 128 },
      aesKey,
      encoder.encode(text)
    );

    // send base64 iv and ct
    const ivB64 = arrayBufferToBase64(iv.buffer);
    const ctB64 = arrayBufferToBase64(ctBuf);

    const payload = { type: 'cipher', from: nameInput.value || 'anon', iv: ivB64, ct: ctB64 };
    ws.send(JSON.stringify(payload));
    appendMessage('You', text, 'me');
    log('Sent encrypted message (relayed).');
    msgIn.value = '';
  } catch (e) {
    console.error(e);
    log('Encryption/sending failed: ' + e.message);
  }
};

// decrypt message
async function decryptMessage(ivB64, ctB64) {
  const iv = base64ToArrayBuffer(ivB64);
  const ct = base64ToArrayBuffer(ctB64);
  const plainBuf = await crypto.subtle.decrypt(
    { name:'AES-GCM', iv: new Uint8Array(iv), additionalData: encoder.encode('chat-aad'), tagLength: 128 },
    aesKey,
    ct
  );
  return decoder.decode(plainBuf);
}

// small "hello" broadcast at connect
function broadcastHello() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type:'hello', name: nameInput.value || 'anon' }));
  }
}

// auto send pubkey on enter key for message
msgIn.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendBtn.click();
  }
});

// After connection, send presence
setInterval(() => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    // keep-alive small ping optionally
  }
}, 30000);

// expose global small debug helpers (console)
window._debug = { base64ToArrayBuffer, arrayBufferToBase64 };

// when connected, send presence
connectBtn.addEventListener('click', () => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    // was disconnect => handled in onclose
  } else {
    // connect will be created; on open we call broadcastHello from onopen
    // but we can schedule a small wait and call hello
    setTimeout(() => broadcastHello(), 300);
  }
});