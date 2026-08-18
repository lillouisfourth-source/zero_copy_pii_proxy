const http = require('http');

const data = JSON.stringify({
  model: 'gpt-3.5-turbo',
  messages: [{ role: 'user', content: 'My phone number is 555-123-4567. Please redact.' }],
  stream: true,
});

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/v1/chat/completions',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(data),
    'Authorization': 'Bearer test-proxy-key',
  },
};

const req = http.request(options, (res) => {
  console.log('STATUS', res.statusCode);
  console.log('HEADERS', res.headers);
  res.setEncoding('utf8');
  res.on('data', (chunk) => {
    // Print raw SSE chunks as they arrive
    console.log('RAW_CHUNK', chunk);
  });
  res.on('end', () => {
    console.log('END OF STREAM');
  });
});

req.on('error', (e) => {
  console.error(`problem with request: ${e.message}`);
});

req.write(data);
req.end();
