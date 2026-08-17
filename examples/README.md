# OpenAI proxy demo

This example shows how an existing OpenAI-compatible client can route calls through the zero-copy PII proxy without changing the application semantics.

## Run it

1. Start the proxy locally with Docker Compose.
2. Install the OpenAI SDK if needed:
   npm install openai
3. Run the demo:
   node examples/openai_demo.js

## Why it matters

A company can keep using the same OpenAI SDK, same model names, and same application logic while the proxy strips or redacts sensitive fields before traffic reaches the upstream LLM provider.

This lets teams secure GenAI traffic with minimal application churn and no custom protocol rewrites.
