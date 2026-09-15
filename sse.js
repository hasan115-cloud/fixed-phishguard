// Server-Sent Events (SSE) Real-Time Broadcast Hub

const clients = new Set();

export function sseHandler(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  res.write(': connected\n\n');

  const client = { id: Date.now() + Math.random(), res };
  clients.add(client);

  // Keep-alive heartbeat comment every 20 seconds
  const pingInterval = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch {
      clearInterval(pingInterval);
      clients.delete(client);
    }
  }, 20000);

  req.on('close', () => {
    clearInterval(pingInterval);
    clients.delete(client);
  });
}

export function broadcast(eventType, data) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of clients) {
    try {
      client.res.write(payload);
    } catch (e) {
      clients.delete(client);
    }
  }
}
