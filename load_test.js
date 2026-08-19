import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 100,
  duration: '30s',
  maxDuration: '30m',
};

export default function () {
  const url = 'http://localhost:3000/v1/chat/completions';
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
