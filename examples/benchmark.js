// Benchmarking script for zero_copy_pii_proxy
// Usage: npm install -g autocannon   OR   npm install autocannon

const autocannon = require('autocannon');

const PROXY_URL = process.env.BENCH_URL || 'http://localhost:3000/v1/chat/completions';
const PROXY_KEY = process.env.PROXY_API_KEY || 'test-proxy-key';

const body = JSON.stringify({
  model: 'gpt-3.5-turbo',
  messages: [{ role: 'user', content: 'Benchmarking request: please respond quickly.' }],
  stream: false,
});

const instance = autocannon({
  url: PROXY_URL,
  connections: parseInt(process.env.BENCH_CONNECTIONS || '50', 10), // concurrent connections
  duration: parseInt(process.env.BENCH_DURATION || '20', 10), // seconds
  pipelining: 1,
  headers: {
    'content-type': 'application/json',
    'authorization': 'Bearer ' + (process.env.OPENAI_API_KEY || 'test-proxy-key'),
    'x-proxy-key': PROXY_KEY,
  },
  method: 'POST',
  body,
}, finished);

function finished(err, res) {
  if (err) {
    console.error('Benchmark error:', err);
    process.exit(1);
  }
  console.log('\n--- Benchmark Summary ---');
  console.log(`URL: ${PROXY_URL}`);
  console.log(`Connections: ${res.connections}`);
  console.log(`Duration (s): ${res.duration}`);
  console.log(`Requests: ${res.requests.total}`);
  console.log(`RPS (avg): ${res.requests.mean.toFixed(2)}`);
  console.log(`Latency P50: ${res.latency.p50} ms`);
  console.log(`Latency P99: ${res.latency.p99} ms`);
  console.log(`Errors: ${res.errors}`);
  console.log('-------------------------\n');
}

process.on('SIGINT', function() {
  instance.stop();
});

