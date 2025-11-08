// server/server.js
// Simple WebSocket relay server — relays JSON messages to all other clients.
// Usage: cd server && npm install && node server.js

const WebSocket = require('ws');

const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
const wss = new WebSocket.Server({ port: PORT });

console.log(`CipherChat relay listening on ws://localhost:${PORT}`);

wss.on('connection', (ws, req) => {
  console.log('Client connected. Active clients:', wss.clients.size);

  ws.on('message', (msg) => {
    // Expect JSON text — broadcast to other clients
    let obj;
    try {
      obj = JSON.parse(msg.toString());
    } catch (e) {
      console.warn('Received non-JSON message, ignoring.');
      return;
    }

    // Validate minimal shape
    if (!obj.type) return;

    // Broadcast to other clients
    wss.clients.forEach((client) => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        try {
          client.send(JSON.stringify(obj));
        } catch (err) {
          // ignore per-client send errors
        }
      }
    });
  });

  ws.on('close', () => {
    console.log('Client disconnected. Active clients:', wss.clients.size);
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err);
  });
});