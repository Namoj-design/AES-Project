// relay-server.js
import { WebSocketServer } from 'ws';

const PORT = 8080;
const wss = new WebSocketServer({ port: PORT });

console.log(`✅ Relay WebSocket Server running at ws://localhost:${PORT}`);

wss.on('connection', (ws, req) => {
  const clientIP = req.socket.remoteAddress;
  console.log(`🔗 Client connected: ${clientIP}`);

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (!data || typeof data !== 'object') throw new Error('Invalid message format');

      // Add timestamp if not present
      if (!data.timestamp) data.timestamp = new Date().toISOString();

      console.log(`📨 Message from ${data.from || 'unknown'} → ${data.target || 'broadcast'} (${data.type})`);

      // Broadcast to all other clients
      wss.clients.forEach((client) => {
        if (client !== ws && client.readyState === 1) {
          client.send(JSON.stringify(data));
        }
      });
    } catch (err) {
      console.error('❌ Error parsing message:', err.message);
    }
  });

  ws.on('close', () => {
    console.log(`❎ Client disconnected: ${clientIP}`);
  });

  ws.on('error', (err) => {
    console.error(`⚠️ WebSocket error from ${clientIP}:`, err.message);
  });
});

// Graceful shutdown on Ctrl+C
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down relay server...');
  wss.close(() => {
    console.log('✅ Server closed cleanly.');
    process.exit(0);
  });
});