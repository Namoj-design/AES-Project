// client/script.js
// Main glue for CipherChat: ECDH + HKDF -> AES-GCM chat with WebSocket relay
// Defensive: detailed logs, try/catch, graceful fallback if optional modules missing.

// Imports (must exist)
import * as C from './utils/crypto.js';
import * as UI from './utils/ui.js';

//
// Helpers for DOM elements - returns null if element not present
//
const $ = id => document.getElementById(id) || null;

// Left (Sita) elements
const leftGenBtn = $('left-gen');
const leftSendPubBtn = $('left-sendpub');
const leftPubTa = $('left-pub');
const leftPeerTa = $('left-peer');
const leftDeriveBtn = $('left-derive');
const leftStatus = $('left-status');
const leftChat = $('left-chat');
const leftInput = $('left-input');
const leftSend = $('left-send');

// Right (Ram) elements
const rightGenBtn = $('right-gen');
const rightSendPubBtn = $('right-sendpub');
const rightPubTa = $('right-pub');
const rightPeerTa = $('right-peer');
const rightDeriveBtn = $('right-derive');
const rightStatus = $('right-status');
const rightChat = $('right-chat');
const rightInput = $('right-input');
const rightSend = $('right-send');

// WebSocket & log
const wsUrlInput = $('ws-url');
const wsConnectBtn = $('ws-connect');
const wsStatus = $('ws-status');
const logPre = $('log');

// Optional blockchain buttons (may not exist)
const leftConnectMeta = $('left-connect-metamask');
const leftRegisterBtn = $('left-register-key');
const leftVerifyBtn = $('left-verify-peer');

const rightConnectMeta = $('right-connect-metamask');
const rightRegisterBtn = $('right-register-key');
const rightVerifyBtn = $('right-verify-peer');

// State
let ws = null;
let KeyRegistry = null; // dynamic import when needed
let wallet = { left: null, right: null }; // store connected wallet addresses if any

const left = { keys: null, pubRaw: null, aes: null };
const right = { keys: null, pubRaw: null, aes: null };

// Safe logging wrapper
function log(...parts) {
  try {
    if (logPre) UI.logToConsole(logPre, ...parts);
  } catch {}
  console.log(...parts);
}

// Utility to safely select text areas (if present)
[leftPubTa, rightPubTa].forEach(el => {
  if (el) el.addEventListener('click', () => el.select());
});

// ---------------------- WebSocket relay ----------------------
function ensureWsConnected() {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    log('WebSocket not connected.');
    return false;
  }
  return true;
}

wsConnectBtn?.addEventListener('click', () => {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.close();
      return;
    }
    const url = (wsUrlInput && wsUrlInput.value) ? wsUrlInput.value.trim() : 'ws://localhost:8080';
    ws = new WebSocket(url);

    ws.onopen = () => {
      if (wsStatus) wsStatus.textContent = 'connected';
      log('WS connected to', url);
    };

    ws.onclose = () => {
      if (wsStatus) wsStatus.textContent = 'disconnected';
      log('WS disconnected');
    };

    ws.onerror = (e) => log('WS error', e?.message || e);

    ws.onmessage = async (ev) => {
      try {
        const m = JSON.parse(ev.data);
        await handleIncomingRelay(m);
      } catch (err) {
        log('Bad WS message or parse error:', err?.message || err);
      }
    };
  } catch (err) {
    log('Failed to connect WS:', err?.message || err);
    alert('WebSocket connect failed: ' + (err?.message || err));
  }
});

// Simple send helper
function sendRelay(obj) {
  if (!ensureWsConnected()) {
    log('Cannot send: WebSocket not connected.');
    alert('WebSocket relay is not connected. Click Connect or use copy/paste fallback.');
    return;
  }
  try {
    ws.send(JSON.stringify(obj));
  } catch (err) {
    log('Failed to send via relay:', err?.message || err);
  }
}

// Handle messages from relay
async function handleIncomingRelay(msg) {
  try {
    if (!msg || !msg.type) return;
    if (msg.type === 'pubkey') {
      log('relay: pubkey from', msg.side);
      if (msg.side === 'left' && leftPubTa && !leftPubTa.value) leftPubTa.value = msg.pub;
      if (msg.side === 'right' && rightPubTa && !rightPubTa.value) rightPubTa.value = msg.pub;
      return;
    }
    if (msg.type === 'cipher') {
      // target indicates which panel should receive
      const targetSide = msg.target;
      log('relay: cipher for', targetSide);
      if (targetSide === 'left') {
        // left receives
        if (leftChat) UI.appendBubble(leftChat, '(encrypted received)', 'right');
        if (left.aes) {
          try {
            const pt = await C.decryptAesGcmBase64(left.aes, msg.iv, msg.ct);
            if (leftChat) UI.appendBubble(leftChat, pt, 'right');
            log('Left decrypted a message');
          } catch (e) {
            log('Left decrypt failed:', e?.message || e);
          }
        } else {
          log('Left AES key not ready');
        }
      } else if (targetSide === 'right') {
        if (rightChat) UI.appendBubble(rightChat, '(encrypted received)', 'left');
        if (right.aes) {
          try {
            const pt = await C.decryptAesGcmBase64(right.aes, msg.iv, msg.ct);
            if (rightChat) UI.appendBubble(rightChat, pt, 'left');
            log('Right decrypted a message');
          } catch (e) {
            log('Right decrypt failed:', e?.message || e);
          }
        } else {
          log('Right AES key not ready');
        }
      }
      return;
    }
    // other message types
    log('relay: unknown message type', msg.type);
  } catch (err) {
    log('handleIncomingRelay error:', err?.message || err);
  }
}

// ---------------------- Left (Sita) actions ----------------------
if (leftGenBtn) leftGenBtn.addEventListener('click', async () => {
  try {
    log('Generating left (Sita) ECDH keypair...');
    left.keys = await C.genECDH();
    const raw = await crypto.subtle.exportKey('raw', left.keys.publicKey);
    left.pubRaw = new Uint8Array(raw);
    if (leftPubTa) leftPubTa.value = C.arrayBufferToBase64(raw);
    if (leftSendPubBtn) leftSendPubBtn.disabled = false;
    if (leftStatus) leftStatus.textContent = 'Keypair ready';
    log('Left keypair generated.');
  } catch (err) {
    log('Left keypair generation failed:', err?.message || err);
    alert('Generate keypair failed: ' + (err?.message || err));
  }
});

if (leftSendPubBtn) leftSendPubBtn.addEventListener('click', () => {
  try {
    if (!leftPubTa || !leftPubTa.value) { alert('Left public key missing. Generate first.'); return; }
    sendRelay({ type: 'pubkey', side: 'left', pub: leftPubTa.value });
    log('Left public key broadcast to relay.');
  } catch (err) {
    log('leftSendPub error:', err?.message || err);
  }
});

if (leftDeriveBtn) leftDeriveBtn.addEventListener('click', async () => {
  try {
    if (!left.keys) { alert('Left keys missing. Generate keypair first.'); return; }
    const peerB64 = leftPeerTa?.value?.trim();
    if (!peerB64) { alert('Paste peer public key into left-peer first.'); return; }
    const peerPub = await C.importPublicKeyBase64(peerB64);
    const peerRaw = C.base64ToArrayBuffer(peerB64);
    left.aes = await C.deriveAesKeyFromECDH(left.keys.privateKey, peerPub, left.pubRaw.buffer, peerRaw);
    if (leftStatus) leftStatus.textContent = 'AES key derived';
    if (leftSend) leftSend.disabled = false;
    log('Left derived AES key successfully.');
  } catch (err) {
    log('Left derive failure:', err?.message || err);
    alert('Derive AES key failed: ' + (err?.message || err));
  }
});

if (leftSend) leftSend.addEventListener('click', async () => {
  try {
    if (!left.aes) { alert('Left must derive AES key first'); return; }
    const msg = leftInput?.value?.trim();
    if (!msg) return;
    const { iv, ct } = await C.encryptAesGcmBase64(left.aes, msg);
    if (leftChat) UI.appendBubble(leftChat, msg, 'left');
    // send ciphertext to relay (target right)
    sendRelay({ type: 'cipher', from: 'left', target: 'right', iv, ct });
    if (leftInput) leftInput.value = '';
    log('Left sent encrypted message (relay).');
  } catch (err) {
    log('Left send failed:', err?.message || err);
    alert('Send failed: ' + (err?.message || err));
  }
});

// ---------------------- Right (Ram) actions ----------------------
if (rightGenBtn) rightGenBtn.addEventListener('click', async () => {
  try {
    log('Generating right (Ram) ECDH keypair...');
    right.keys = await C.genECDH();
    const raw = await crypto.subtle.exportKey('raw', right.keys.publicKey);
    right.pubRaw = new Uint8Array(raw);
    if (rightPubTa) rightPubTa.value = C.arrayBufferToBase64(raw);
    if (rightSendPubBtn) rightSendPubBtn.disabled = false;
    if (rightStatus) rightStatus.textContent = 'Keypair ready';
    log('Right keypair generated.');
  } catch (err) {
    log('Right keypair generation failed:', err?.message || err);
    alert('Generate keypair failed: ' + (err?.message || err));
  }
});

if (rightSendPubBtn) rightSendPubBtn.addEventListener('click', () => {
  try {
    if (!rightPubTa || !rightPubTa.value) { alert('Right public key missing. Generate first.'); return; }
    sendRelay({ type: 'pubkey', side: 'right', pub: rightPubTa.value });
    log('Right public key broadcast to relay.');
  } catch (err) {
    log('rightSendPub error:', err?.message || err);
  }
});

if (rightDeriveBtn) rightDeriveBtn.addEventListener('click', async () => {
  try {
    if (!right.keys) { alert('Right keys missing. Generate keypair first.'); return; }
    const peerB64 = rightPeerTa?.value?.trim();
    if (!peerB64) { alert('Paste peer public key into right-peer first.'); return; }
    const peerPub = await C.importPublicKeyBase64(peerB64);
    const peerRaw = C.base64ToArrayBuffer(peerB64);
    right.aes = await C.deriveAesKeyFromECDH(right.keys.privateKey, peerPub, right.pubRaw.buffer, peerRaw);
    if (rightStatus) rightStatus.textContent = 'AES key derived';
    if (rightSend) rightSend.disabled = false;
    log('Right derived AES key successfully.');
  } catch (err) {
    log('Right derive failure:', err?.message || err);
    alert('Derive AES key failed: ' + (err?.message || err));
  }
});

if (rightSend) rightSend.addEventListener('click', async () => {
  try {
    if (!right.aes) { alert('Right must derive AES key first'); return; }
    const msg = rightInput?.value?.trim();
    if (!msg) return;
    const { iv, ct } = await C.encryptAesGcmBase64(right.aes, msg);
    if (rightChat) UI.appendBubble(rightChat, msg, 'left');
    sendRelay({ type: 'cipher', from: 'right', target: 'left', iv, ct });
    if (rightInput) rightInput.value = '';
    log('Right sent encrypted message (relay).');
  } catch (err) {
    log('Right send failed:', err?.message || err);
    alert('Send failed: ' + (err?.message || err));
  }
});

// ---------------------- MetaMask & Key Registry (optional) ----------------------
// Dynamic import helper for blockchain module
async function ensureKeyRegistry() {
  if (KeyRegistry) return KeyRegistry;
  try {
    // try relative path; adjust path if your structure differs
    KeyRegistry = await import('../blockchain/keyregistry.js');
    log('KeyRegistry module loaded.');
    return KeyRegistry;
  } catch (err) {
    log('KeyRegistry module not available:', err?.message || err);
    KeyRegistry = null;
    return null;
  }
}

// MetaMask connection (shared helper)
async function connectMetaMask() {
  try {
    if (!window.ethereum) throw new Error('MetaMask not found in browser.');
    await window.ethereum.request({ method: 'eth_requestAccounts' });
    const accounts = await window.ethereum.request({ method: 'eth_accounts' });
    if (!accounts || accounts.length === 0) throw new Error('No MetaMask accounts available.');
    return accounts[0];
  } catch (err) {
    log('MetaMask connect failed:', err?.message || err);
    throw err;
  }
}

// Left MetaMask connect/register/verify
if (leftConnectMeta) leftConnectMeta.addEventListener('click', async () => {
  try {
    const addr = await connectMetaMask();
    wallet.left = addr;
    log('Left connected MetaMask:', addr);
    alert('Left connected: ' + addr);
  } catch (err) {
    alert('MetaMask connect failed: ' + (err?.message || err));
  }
});

if (leftRegisterBtn) leftRegisterBtn.addEventListener('click', async () => {
  try {
    if (!leftPubTa || !leftPubTa.value) { alert('Left public key missing. Generate keypair and export first.'); return; }
    const kr = await ensureKeyRegistry();
    if (!kr || !kr.registerECDHKey) { alert('KeyRegistry not available. Implement blockchain/keyregistry.js'); return; }
    // connect metamask if not connected
    if (!wallet.left) {
      try { wallet.left = await connectMetaMask(); } catch (err) { throw err; }
    }
    await kr.registerECDHKey(leftPubTa.value);
    log('Left public key registered on-chain.');
    alert('Left key registered on-chain.');
  } catch (err) {
    log('Left register failed:', err?.message || err);
    alert('Register failed: ' + (err?.message || err));
  }
});

if (leftVerifyBtn) leftVerifyBtn.addEventListener('click', async () => {
  try {
    const kr = await ensureKeyRegistry();
    if (!kr || !kr.verifyOnChainKey) { alert('KeyRegistry verify not available.'); return; }
    const peerAddr = prompt('Enter peer (right) Ethereum address to verify:');
    if (!peerAddr) return;
    if (!leftPeerTa || !leftPeerTa.value) { alert('Paste peer public key in left-peer first.'); return; }
    const verified = await kr.verifyOnChainKey(leftPeerTa.value, peerAddr);
    alert(verified ? '✅ Peer key verified on-chain' : '❌ Peer key NOT verified or not registered');
    log('Left verify result for', peerAddr, verified);
  } catch (err) {
    log('Left verify error:', err?.message || err);
    alert('Verify failed: ' + (err?.message || err));
  }
});

// Right MetaMask connect/register/verify
if (rightConnectMeta) rightConnectMeta.addEventListener('click', async () => {
  try {
    const addr = await connectMetaMask();
    wallet.right = addr;
    log('Right connected MetaMask:', addr);
    alert('Right connected: ' + addr);
  } catch (err) {
    alert('MetaMask connect failed: ' + (err?.message || err));
  }
});

if (rightRegisterBtn) rightRegisterBtn.addEventListener('click', async () => {
  try {
    if (!rightPubTa || !rightPubTa.value) { alert('Right public key missing. Generate keypair and export first.'); return; }
    const kr = await ensureKeyRegistry();
    if (!kr || !kr.registerECDHKey) { alert('KeyRegistry not available. Implement blockchain/keyregistry.js'); return; }
    if (!wallet.right) {
      try { wallet.right = await connectMetaMask(); } catch (err) { throw err; }
    }
    await kr.registerECDHKey(rightPubTa.value);
    log('Right public key registered on-chain.');
    alert('Right key registered on-chain.');
  } catch (err) {
    log('Right register failed:', err?.message || err);
    alert('Register failed: ' + (err?.message || err));
  }
});

if (rightVerifyBtn) rightVerifyBtn.addEventListener('click', async () => {
  try {
    const kr = await ensureKeyRegistry();
    if (!kr || !kr.verifyOnChainKey) { alert('KeyRegistry verify not available.'); return; }
    const peerAddr = prompt('Enter peer (left) Ethereum address to verify:');
    if (!peerAddr) return;
    if (!rightPeerTa || !rightPeerTa.value) { alert('Paste peer public key in right-peer first.'); return; }
    const verified = await kr.verifyOnChainKey(rightPeerTa.value, peerAddr);
    alert(verified ? '✅ Peer key verified on-chain' : '❌ Peer key NOT verified or not registered');
    log('Right verify result for', peerAddr, verified);
  } catch (err) {
    log('Right verify error:', err?.message || err);
    alert('Verify failed: ' + (err?.message || err));
  }
});

// ---------------------- Defensive startup checks ----------------------
(function initialChecks() {
  try {
    // check WebCrypto availability
    if (!window.crypto || !crypto.subtle) {
      alert('Web Crypto API not available in this browser. Use Chrome/Firefox and load via http://localhost');
      log('Web Crypto not available.');
    }
    // log presence of key functions
    log('Crypto helpers present:', typeof C.genECDH === 'function', typeof C.deriveAesKeyFromECDH === 'function');
  } catch (err) {
    console.warn('initialChecks error', err);
  }
})();

// ---------------------- End of script ----------------------
log('CipherChat script loaded. UI ready.');