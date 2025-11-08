const WebSocket = require('ws');

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
const wss = new WebSocket.Server({ port: PORT });

console.log(`WebSocket relay running on ws://localhost:${PORT}`);

wss.on('connection', (ws, req) => {
  const peer = req.socket.remoteAddress + ':' + req.socket.remotePort;
  console.log('Client connected:', peer, ' total:', wss.clients.size);

  ws.on('message', (data) => {
    // Expect JSON string
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (err) {
      console.warn('Received non-JSON or malformed message, ignoring.');
      return;
    }

    // Add small validation: message must have a `type` field
    if (!msg.type) return;

    // Broadcast message to all other clients
    wss.clients.forEach((client) => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        try {
          client.send(JSON.stringify(msg));
        } catch (err) {
          // ignore send errors per client
        }
      }
    });
  });

  ws.on('close', () => {
    console.log('Client disconnected:', peer, ' total:', wss.clients.size);
  });

  ws.on('error', (err) => {
    console.error('WebSocket error', err);
  });
});