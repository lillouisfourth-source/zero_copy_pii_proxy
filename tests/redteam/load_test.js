import http from 'k6/http';
import { check } from 'k6';

export const options = {
  thresholds: {
    checks: ['rate == 1.0'],
  },
  scenarios: {
    default: {
      executor: 'shared-iterations',
      vus: 100,
      iterations: 100000,
      maxDuration: '30m',
    },
  },
};

export default function () {
  const url = __ENV.TARGET_URL || 'http://localhost:3000/v1/chat/completions';
  const payload = JSON.stringify({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'Explain quantum computing in detail.' }],
    stream: true,
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test_key', 
    },
  };

  const res = http.post(url, payload, params);
  
  check(res, {
    'is status 200': (r) => r.status === 200,
  });
  
}
