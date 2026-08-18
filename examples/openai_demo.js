import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || 'sk-mock-proxy-key',
  baseURL: 'https://zero-copy-pii-proxy.fly.dev/v1',
  defaultHeaders: {
    'x-proxy-key': process.env.PROXY_API_KEY,
  },
});

async function main() {
  try {
    const stream = await client.chat.completions.create({
      model: process.env.AI_MODEL || 'gpt-3.5-turbo',
      messages: [
        { role: 'user', content: 'My name is John Doe and my phone number is 555-123-4567. Write a haiku about data privacy.' },
      ],
      stream: true,
    });

    for await (const part of stream) {
      // Stream parts may be objects or strings depending on SDK; stringify for visibility
      console.log('STREAM_PART', JSON.stringify(part));
    }

    console.log('OpenAI-compatible request via zero-copy proxy succeeded.');
  } catch (err) {
    console.error('Demo failed:', err);
    process.exitCode = 1;
  }
}

main();
