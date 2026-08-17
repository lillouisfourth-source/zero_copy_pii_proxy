const http = require('http');
http.createServer((req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  // Send a chunk immediately, then keep the connection alive for 2 seconds to simulate generation
  res.write('data: {"choices":[{"delta":{"content":"mock"}}]}\n\n');
  setTimeout(() => res.end(), 2000);
}).listen(8081, () => console.log('Mock SSE upstream running on 8081'));
