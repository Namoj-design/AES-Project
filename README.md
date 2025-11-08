# 🔐 CipherChat — AES-GCM + ECDH Secure Messaging Demo

**CipherChat** is a browser-based cryptographic chat simulator that demonstrates **AES-GCM (Advanced Encryption Standard)** encryption combined with **ECDH (Elliptic Curve Diffie–Hellman)** key exchange.  
It visually showcases how **Alice** and **Bob** can securely exchange messages through a **relay server**, encrypt and decrypt them in real-time, all inside a modern animated Matrix-style UI.

---

## 🚀 Features

- 🔑 **Asymmetric Key Generation (ECDH P-256)**
- 🧮 **AES-GCM-256 Encryption/Decryption**
- 🔗 **WebSocket Relay Server** for message exchange
- 💬 **Dual-User Interface:** `Alice.html` and `Bob.html`
- 🌙 **Dark/Light Theme Toggle**
- 🟩 **Matrix Binary Rain Background Animation**
- 🧠 **Activity Log Console** to visualize every cryptographic step

---

## 🧩 Technology Stack

| Component | Description |
|------------|-------------|
| **Frontend** | HTML5, CSS3, JavaScript (ES Modules) |
| **Crypto API** | [WebCrypto Subtle API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) |
| **Encryption** | AES-GCM-256 |
| **Key Exchange** | ECDH using Curve P-256 |
| **Backend (Relay)** | Node.js + WebSocket (`ws` library) |
| **Style Theme** | Matrix-style cyber aesthetic with binary rain animation |

---

## 🏗️ Project Structure
