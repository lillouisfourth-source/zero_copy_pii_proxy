const http = require('http');

const request = http.request({
  host: '127.0.0.1',
  port: 3000,
  path: '/v1/chat/completions',
  method: 'POST',
  headers: {
    Authorization: 'Bearer test_key',
    'Content-Type': 'application/json',
  },
}, (response) => {
  let chunks = 0;
  response.on('data', () => {
    chunks += 1;
    console.log(`received chunk ${chunks}`);
    if (chunks === 10) {
      console.log('destroying client socket after 10 chunks');
      response.destroy();
      request.destroy();
    }
  });
  response.on('close', () => {
    console.log(`client response closed after ${chunks} chunks`);
  });
});

request.on('error', (error) => console.log(`client error: ${error.code || error.message}`));
request.end(JSON.stringify({ model: 'disconnect-test', messages: [], stream: true }));