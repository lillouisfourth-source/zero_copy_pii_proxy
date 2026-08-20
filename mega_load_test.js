import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    mega_payload: {
      executor: 'shared-iterations',
      vus: 100,
      iterations: 5000,
      maxDuration: '30m',
    },
  },
};

export default function () {
  const response = http.post(
    'http://localhost:3000/v1/chat/completions',
    JSON.stringify({
      model: 'mega-test',
      messages: [{ role: 'user', content: 'payload test' }],
      stream: true,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test_key',
      },
    },
  );

  check(response, {
    'mega payload status 200': (value) => value.status === 200,
  });
}
