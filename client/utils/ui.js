// client/utils/ui.js
export function appendBubble(containerEl, text, side = "left") {
    const b = document.createElement("div");
    b.className = `bubble ${side}`;
    b.textContent = text;
    containerEl.appendChild(b);
    containerEl.scrollTop = containerEl.scrollHeight;
  }
  
  export function setStatus(el, text) {
    el.textContent = text;
  }
  
  export function logToConsole(preEl, ...parts) {
    const time = new Date().toLocaleTimeString();
    preEl.textContent += `[${time}] ${parts.join(" ")}\n`;
    preEl.scrollTop = preEl.scrollHeight;
  }