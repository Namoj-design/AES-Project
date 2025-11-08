// relay-server.js
import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 8080 });
console.log('✅ Relay WebSocket server running at ws://localhost:8080');

wss.on('connection', ws => {
  ws.on('message', msg => {
    try {
      const data = JSON.parse(msg);
      // broadcast to all clients except sender
      wss.clients.forEach(client => {
        if (client !== ws && client.readyState === 1) {
          client.send(JSON.stringify(data));
        }
      });
    } catch (e) {
      console.error('Bad WS message', e.message);
    }
  });
});