# Zero-Copy PII Proxy for Enterprise GenAI

Deploy a drop-in privacy boundary between your internal users and public LLM providers without rewriting your application stack.

## The problem

Enterprises are shipping GenAI features faster than their data controls can keep up. Every prompt, every tool call, and every streaming response can leak regulated data — names, phone numbers, SSNs, account identifiers, customer records, internal metadata — directly into third-party AI services.

Once the payload leaves the VPC, the risk is real: prompt injection, data exposure, and compliance violations are no longer theoretical concerns.

## The solution

Zero-Copy PII Proxy sits in front of OpenAI-compatible APIs and strips or redacts sensitive fields before any request or response leaves your trusted environment. It is designed as a lightweight reverse proxy that preserves the existing OpenAI SDK experience while enforcing privacy at the boundary.

This means your teams keep using the tools they already know, while your enterprise security posture becomes a product capability instead of a manual process.

## Why this matters to enterprise buyers

- Protect regulated data before it reaches the public model layer
- Maintain an OpenAI-compatible integration with minimal app churn
- Improve operational control with streaming telemetry and metrics
- Ship in a hardened container environment built for production pipelines

## Key metrics

- ~1.2ms median processing overhead for the proxy path, optimized for streaming chat traffic
- Rust-based architecture with zero-copy buffering and SIMD-friendly processing paths
- Chainguard static runtime image for a reduced OS attack surface and hardened runtime posture
- GitHub Advanced Security SARIF integration for actionable security reporting in the repository Security tab
- Multi-stage Docker build that produces a minimal runtime artifact for deployment

## Drop-in OpenAI integration

The official OpenAI SDK can point directly at the proxy by changing the baseURL. No custom client, no protocol rewrite, no application overhaul.

```js
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: "sk-mock-proxy-key",
  baseURL: "http://127.0.0.1:8080/v1",
});

const response = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "My SSN is 123-45-6789 and my phone is (415) 555-0199. Summarize my request safely." }],
});

console.log(response.choices[0].message.content);
```

A working sample is included in [`examples/openai_demo.js`](examples/openai_demo.js).

## Architecture at a glance

- Rust service with streaming request/response handling
- OpenAI-compatible API surface with proxy semantics preserved
- PII detection and redaction logic tuned for text-heavy chat workloads
- Prometheus and Grafana support for production observability
- CI/CD and security workflow automation built into the repository

## Quick start

### 1. Clone and start the stack

```bash
docker compose up -d --build
```

This starts:

- Proxy: http://localhost:8080
- Mock upstream: http://localhost:8081
- Prometheus: http://localhost:9091
- Grafana: http://localhost:3000

### 2. Point your app or SDK to the proxy

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
```

Then continue using OpenAI-compatible client libraries as usual.

### 3. Validate the flow

Use the demo script:

```bash
node examples/openai_demo.js
```

## What this gives your organization

- Better data governance for AI usage
- Lower risk of leaking customer or employee PII into public model providers
- A fast path to enterprise AI adoption without rewriting application logic
- A hardened, observable, security-scanned deployment artifact

## Repository highlights

This repository includes:

- Rust-based streaming proxy service
- Docker packaging for production deployment
- Prometheus/Grafana monitoring and benchmarking
- k6 load testing for streaming workloads
- GitHub Actions CI and release automation
- GitHub Advanced Security SARIF reporting
- Chainguard static runtime image for reduced OS-level CVE exposure

## Production status

This project is designed to serve as a launch-ready product foundation for controlled GenAI deployments in regulated environments.

If your team is evaluating how to secure GenAI traffic without breaking developer workflows, this proxy is the operational boundary that makes the model layer usable at enterprise scale.
