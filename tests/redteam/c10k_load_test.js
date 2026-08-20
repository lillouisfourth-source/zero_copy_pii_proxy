import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    c10k: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 5000 },
        { duration: '30s', target: 5000 },
      ],
      gracefulRampDown: '0s',
    },
  },
};

export default function () {
  const response = http.post(
    'http://localhost:3000/v1/chat/completions',
    JSON.stringify({ model: 'hang-test', messages: [], stream: true }),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer test_key',
      },
    },
  );

  check(response, {
    'hang request accepted': (value) => value.status === 200,
  });
}