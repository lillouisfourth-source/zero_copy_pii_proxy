const http = require('http');

const payload = Buffer.from(`data: ${'A'.repeat(150 * 1024)}\n\n`);

http.createServer((req, res) => {
  let offset = 0;
  const chunkSize = 1024;
  req.on('close', () => console.log(`client closed after ${offset} of ${payload.length} bytes`));
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  const sendChunk = () => {
    if (offset >= payload.length) {
      res.end();
      console.log(`completed ${payload.length} bytes`);
      return;
    }
    const end = Math.min(offset + chunkSize, payload.length);
    res.write(payload.subarray(offset, end));
    offset = end;
    setTimeout(sendChunk, 10);
  };
  sendChunk();
}).listen(8081, () => console.log(`Mega SSE upstream listening on 8081 (${payload.length} bytes)`));
