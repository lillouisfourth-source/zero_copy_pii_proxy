import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 50,
  duration: '10s',
  thresholds: {
    http_req_duration: ['p(95)<50'],
  },
};

export default function () {
  const payload = JSON.stringify({ text: "Hello, please contact me at enterprise-buyer@example.com or call 555-0199." });
  const params = { headers: { 'Content-Type': 'application/json' } };
  const res = http.post('http://127.0.0.1:8080/stream', payload, params);

  check(res, {
    'is status 200': (r) => r.status === 200,
  });
}
