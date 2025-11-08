// client/script.js
import * as C from './utils/crypto.js';
import * as UI from './utils/ui.js';

const leftGenBtn = document.getElementById('left-gen');
const leftSendPubBtn = document.getElementById('left-sendpub');
const leftPubTa = document.getElementById('left-pub');
const leftPeerTa = document.getElementById('left-peer');
const leftDeriveBtn = document.getElementById('left-derive');
const leftStatus = document.getElementById('left-status');
const leftChat = document.getElementById('left-chat');
const leftInput = document.getElementById('left-input');
const leftSend = document.getElementById('left-send');

const rightGenBtn = document.getElementById('right-gen');
const rightSendPubBtn = document.getElementById('right-sendpub');
const rightPubTa = document.getElementById('right-pub');
const rightPeerTa = document.getElementById('right-peer');
const rightDeriveBtn = document.getElementById('right-derive');
const rightStatus = document.getElementById('right-status');
const rightChat = document.getElementById('right-chat');
const rightInput = document.getElementById('right-input');
const rightSend = document.getElementById('right-send');

const wsUrlInput = document.getElementById('ws-url');
const wsConnectBtn = document.getElementById('ws-connect');
const wsStatus = document.getElementById('ws-status');
const logPre = document.getElementById('log');

let ws = null;

// state objects
const left = { keys: null, pubRaw: null, aes: null };
const right = { keys: null, pubRaw: null, aes: null };

// ------- helpers -------
function toB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function fromB64ToBuf(s) { return C.base64ToArrayBuffer(s); }
function log(...args) { UI.logToConsole(logPre, ...args); }

// ------- WebSocket relay handling -------
wsConnectBtn.onclick = () => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.close();
    return;
  }
  const url = wsUrlInput.value.trim();
  ws = new WebSocket(url);
  ws.onopen = () => { wsStatus.textContent = 'connected'; log('WS connected to', url); };
  ws.onclose = () => { wsStatus.textContent = 'disconnected'; log('WS disconnected'); };
  ws.onerror = (e) => { log('WS error', e.message || e); };
  ws.onmessage = async (ev) => {
    try {
      const m = JSON.parse(ev.data);
      await handleIncomingRelay(m);
    } catch (e) { log('Bad WS message', e); }
  };
};

// minimal protocol: { type: 'pubkey'|'cipher', side:'left'|'right', pub:..., iv:..., ct:... }
async function handleIncomingRelay(msg) {
  if (msg.type === 'pubkey') {
    log('relay: pubkey from', msg.side);
    if (msg.side === 'left') {
      // left public key arrived at this client => populate left pub area only if empty
      if (!leftPubTa.value) leftPubTa.value = msg.pub;
      // if other side is remote, we broadcast accordingly
    } else if (msg.side === 'right') {
      if (!rightPubTa.value) rightPubTa.value = msg.pub;
    }
  } else if (msg.type === 'cipher') {
    // deliver ciphertext to appropriate panel
    const target = msg.target === 'left' ? left : right;
    // append placeholder 'encrypted received', then attempt decrypt if key ready
    if (msg.target === 'left') {
      UI.appendBubble(leftChat, '(encrypted msg received)', 'right');
      if (left.aes) {
        try {
          const pt = await C.decryptAesGcmBase64(left.aes, msg.iv, msg.ct);
          UI.appendBubble(leftChat, pt, 'right');
          log('left decrypted a message');
        } catch (e) { log('left decrypt failed', e.message); }
      } else {
        log('left has no AES key yet');
      }
    } else {
      UI.appendBubble(rightChat, '(encrypted msg received)', 'left');
      if (right.aes) {
        try {
          const pt = await C.decryptAesGcmBase64(right.aes, msg.iv, msg.ct);
          UI.appendBubble(rightChat, pt, 'left');
          log('right decrypted a message');
        } catch (e) { log('right decrypt failed', e.message); }
      } else {
        log('right has no AES key yet');
      }
    }
  }
}

// send helper
function sendRelay(obj) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    log('WS not connected — cannot send to relay. Use local transfer (copy/paste) or connect.');
    return;
  }
  ws.send(JSON.stringify(obj));
}

// ------- left side operations -------
leftGenBtn.onclick = async () => {
  left.keys = await C.genECDH();
  const raw = await crypto.subtle.exportKey('raw', left.keys.publicKey);
  left.pubRaw = new Uint8Array(raw);
  leftPubTa.value = C.arrayBufferToBase64(raw);
  leftSendPubBtn.disabled = false;
  log('Left keypair generated.');
  leftStatus.textContent = 'Keypair ready';
};

leftSendPubBtn.onclick = () => {
  if (!leftPubTa.value) return;
  sendRelay({ type: 'pubkey', side: 'left', pub: leftPubTa.value });
  log('Broadcasted left public key to relay.');
};

leftDeriveBtn.onclick = async () => {
  try {
    if (!left.keys) throw new Error('left keys missing');
    const peerB64 = leftPeerTa.value.trim();
    if (!peerB64) throw new Error('paste peer public key in left-peer');
    const peerPub = await C.importPublicKeyBase64(peerB64);
    const peerRaw = C.base64ToArrayBuffer(peerB64);
    left.aes = await C.deriveAesKeyFromECDH(left.keys.privateKey, peerPub, left.pubRaw.buffer, peerRaw);
    leftStatus.textContent = 'AES key derived';
    leftSend.disabled = false;
    log('Left derived AES key (HKDF over ECDH).');
  } catch (e) {
    log('Left derive error:', e.message);
  }
};

leftSend.onclick = async () => {
  if (!left.aes) return alert('Left must derive AES key first');
  const msg = leftInput.value.trim();
  if (!msg) return;
  const { iv, ct } = await C.encryptAesGcmBase64(left.aes, msg);
  // local UI: show plaintext bubble on left chat
  UI.appendBubble(leftChat, msg, 'left');
  // send ciphertext to relay (target right)
  sendRelay({ type: 'cipher', from: 'left', target: 'right', iv, ct });
  leftInput.value = '';
  log('Left sent encrypted message (relay).');
};

// ------- right side operations -------
rightGenBtn.onclick = async () => {
  right.keys = await C.genECDH();
  const raw = await crypto.subtle.exportKey('raw', right.keys.publicKey);
  right.pubRaw = new Uint8Array(raw);
  rightPubTa.value = C.arrayBufferToBase64(raw);
  rightSendPubBtn.disabled = false;
  log('Right keypair generated.');
  rightStatus.textContent = 'Keypair ready';
};

rightSendPubBtn.onclick = () => {
  if (!rightPubTa.value) return;
  sendRelay({ type: 'pubkey', side: 'right', pub: rightPubTa.value });
  log('Broadcasted right public key to relay.');
};

rightDeriveBtn.onclick = async () => {
  try {
    if (!right.keys) throw new Error('right keys missing');
    const peerB64 = rightPeerTa.value.trim();
    if (!peerB64) throw new Error('paste peer public key in right-peer');
    const peerPub = await C.importPublicKeyBase64(peerB64);
    const peerRaw = C.base64ToArrayBuffer(peerB64);
    right.aes = await C.deriveAesKeyFromECDH(right.keys.privateKey, peerPub, right.pubRaw.buffer, peerRaw);
    rightStatus.textContent = 'AES key derived';
    rightSend.disabled = false;
    log('Right derived AES key (HKDF over ECDH).');
  } catch (e) {
    log('Right derive error:', e.message);
  }
};

rightSend.onclick = async () => {
  if (!right.aes) return alert('Right must derive AES key first');
  const msg = rightInput.value.trim();
  if (!msg) return;
  const { iv, ct } = await C.encryptAesGcmBase64(right.aes, msg);
  UI.appendBubble(rightChat, msg, 'left'); // right->left bubble UI (shows on right panel aligned left)
  sendRelay({ type: 'cipher', from: 'right', target: 'left', iv, ct });
  rightInput.value = '';
  log('Right sent encrypted message (relay).');
};

// small UI features: clicking public key selects text for copy
[leftPubTa, rightPubTa].forEach(el => el.addEventListener('click', () => el.select()));