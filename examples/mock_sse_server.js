const http = require('http');
const port = process.env.MOCK_PORT || 4000;

http.createServer((req, res) => {
  if (req.method === 'POST' && req.url && req.url.startsWith('/v1')) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });

    // Example SSE chunks that include PII (phone number) to test redaction
    const chunks = [
      'data: {"choices":[{"delta":{"content":"A haiku about data privacy:"}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"My phone is 555-123-4567 and should be redacted"}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"Keep secrets safe."}}]}\n\n',
      'data: [DONE]\n\n',
    ];

    let i = 0;
    const iv = setInterval(() => {
      if (i >= chunks.length) {
        clearInterval(iv);
        res.end();
        return;
      }
      res.write(chunks[i]);
      i++;
    }, 400);

    return;
  }

  res.writeHead(404);
  res.end('Not Found');
}).listen(port, () => console.log(`Mock SSE server listening on http://localhost:${port}`));
