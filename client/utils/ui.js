// client/utils/ui.js
// Basic UI helpers for CipherChat

/** Append a chat bubble to a message area */
export function appendBubble(containerEl, text, side = "left") {
    if (!containerEl) return;
    const b = document.createElement("div");
    b.className = `bubble ${side}`;
    b.textContent = text;
    containerEl.appendChild(b);
    containerEl.scrollTop = containerEl.scrollHeight;
  }
  
  /** Set small status text (below buttons) */
  export function setStatus(el, text) {
    if (el) el.textContent = text;
  }
  
  /** Append a log message (timestamped) to console area */
  export function logToConsole(preEl, ...parts) {
    if (!preEl) return;
    const time = new Date().toLocaleTimeString();
    preEl.textContent += `[${time}] ${parts.join(" ")}\n`;
    preEl.scrollTop = preEl.scrollHeight;
  }