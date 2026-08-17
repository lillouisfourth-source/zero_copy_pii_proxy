#!/bin/bash
# Ensure OPENAI_API_KEY is set in your environment before running

curl -N -X POST http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "Please repeat the following phrase exactly as written, word for word: \"My secret password is ssn123\""
      }
    ],
    "stream": true
  }'
