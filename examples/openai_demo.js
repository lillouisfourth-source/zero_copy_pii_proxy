import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: 'sk-mock-proxy-key',
  baseURL: 'http://127.0.0.1:8080/v1',
});

const response = await client.chat.completions.create({
  model: 'gpt-4o-mini',
  messages: [
    {
      role: 'user',
      content:
        'Please redact this PII from the message before sending it upstream: ' +
        'My SSN is 123-45-6789 and my phone number is (555) 019-2000. Please keep the rest of the context intact.',
    },
  ],
  temperature: 0,
});

console.log('OpenAI-compatible request via zero-copy proxy succeeded.');
console.log(JSON.stringify(response, null, 2));
