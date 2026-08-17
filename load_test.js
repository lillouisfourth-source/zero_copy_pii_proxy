import http from 'k6/http';
import { check } from 'k6';
import { sleep } from 'k6';

export let options = {
  vus: 100,
  duration: '30s',
};

const url = 'http://localhost:3000/v1/chat/completions';

export default function () {
  const payload = JSON.stringify({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: 'Please summarize the following text: The quick brown fox jumps over the lazy dog.' }],
    stream: true
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${__ENV.OPENAI_API_KEY}`,
    },
    timeout: '120s'
  };

  const res = http.post(url, payload, params);
  check(res, { 'status is 200 or 206': (r) => r.status === 200 || r.status === 206 });
  sleep(1);
}
