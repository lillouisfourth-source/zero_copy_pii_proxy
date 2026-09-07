import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 100,
  iterations: 1000,
  maxDuration: '5m',
};

export default function () {
  const url = __ENV.TARGET_URL || 'http://localhost:3000/v1/chat/completions';
  const payload = JSON.stringify({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'Explain quantum computing briefly.' }],
    stream: true,
  });
  const response = http.post(url, payload, {
    timeout: '2s',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer test_key',
    },
  });

  check(response, {
    'is status 200': (result) => result.status === 200,
  });
}
