const http = require('http');

const payload = `data: ${'A'.repeat(150 * 1024)}\n\n`;

http.createServer((req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.end(payload);
}).listen(8081, () => console.log(`Mega SSE upstream listening on 8081 (${payload.length} bytes)`));
