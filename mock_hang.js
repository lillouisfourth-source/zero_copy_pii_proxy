const http = require('http');

http.createServer((req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.write('{');
  setInterval(() => {}, 60_000);
}).listen(8081, () => console.log('Hanging SSE upstream listening on 8081'));
