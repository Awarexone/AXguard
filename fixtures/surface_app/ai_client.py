"""AI provider client stub for surface inventory."""

from __future__ import annotations

import openai
from anthropic import Anthropic

# Placeholder — surface engine must redact.
OPENAI_API_KEY = "REDACTED_TEST_ONLY"
ANTHROPIC_API_KEY = "REDACTED_TEST_ONLY"


def chat_openai(prompt: str) -> str:
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content or ""


def chat_anthropic(prompt: str) -> str:
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model="claude-3-5-haiku-latest",
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )
    return str(msg.content)
