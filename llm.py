"""Provider-agnostic LLM layer — Bring Your Own LLM (BYO-LLM).

CerberusAI's reasoning runs through whatever model the enterprise has already
approved: Anthropic, OpenAI, Azure OpenAI (the M365 / Copilot path), Google Gemini,
DeepSeek, or any OpenAI-compatible endpoint (self-hosted, gateway, etc.). The agent
calls this module only — it never touches a provider SDK directly. Powered by LiteLLM.

Honesty note baked into the product's own docs: routing through a PRIVATE deployment
(Azure-in-tenant / self-hosted / gateway) keeps data in the customer's environment;
routing through a public SaaS API (OpenAI/Gemini/DeepSeek) still sends alert text to
that third party — just one the customer already approved.
"""

from __future__ import annotations

import json

import litellm

from config import load_config

litellm.drop_params = True   # silently ignore params a given provider doesn't accept
litellm.suppress_debug_info = True

_DEFAULT_MODELS = {
    "anthropic": "claude-opus-5",
    "openai": "gpt-4o",
    "azure": "gpt-4o",
    "gemini": "gemini-1.5-pro",
    "deepseek": "deepseek-chat",
    "custom": "gpt-4o",
}


def _saved_ai() -> dict:
    """Read the AI provider config the wizard saved. Backward-compatible with the
    older config that only stored an Anthropic key."""
    cfg = load_config()
    ai = cfg.get("ai")
    if ai:
        return ai
    key = cfg.get("anthropic_api_key")
    return {"provider": "anthropic",
            "model": cfg.get("model") or "claude-opus-5",
            "api_key": key}


def resolve(ai: dict) -> tuple[str, dict]:
    """Map an AI config -> (LiteLLM model string, extra kwargs) for that provider."""
    provider = (ai.get("provider") or "anthropic").lower()
    model = ai.get("model") or _DEFAULT_MODELS.get(provider, "gpt-4o")
    endpoint = ai.get("endpoint")
    kw: dict = {}
    if ai.get("api_key"):
        kw["api_key"] = ai["api_key"]

    if provider == "anthropic":
        m = f"anthropic/{model}"
    elif provider == "openai":
        m = model if "/" in model else f"openai/{model}"
    elif provider == "azure":                     # Microsoft / Copilot enterprises
        m = f"azure/{model}"                       # model = the Azure *deployment* name
        if endpoint:
            kw["api_base"] = endpoint
        kw["api_version"] = ai.get("api_version") or "2024-06-01"
    elif provider == "gemini":
        m = f"gemini/{model}"
    elif provider == "deepseek":
        m = f"deepseek/{model}"
    else:                                          # custom OpenAI-compatible endpoint
        m = f"openai/{model}"
        if endpoint:
            kw["api_base"] = endpoint
    return m, kw


async def acompletion(messages, tools=None, tool_choice=None, max_tokens=4096, ai=None):
    """One chat completion (OpenAI-shaped) against the configured provider."""
    model, kw = resolve(ai or _saved_ai())
    return await litellm.acompletion(
        model=model, messages=messages, tools=tools, tool_choice=tool_choice,
        max_tokens=max_tokens, **kw,
    )


def _strip_fences(t: str) -> str:
    t = (t or "").strip()
    if t.startswith("```"):
        t = t[3:]
        if t[:4].lower() == "json":
            t = t[4:]
        if "```" in t:
            t = t[: t.rindex("```")]
    return t.strip()


async def complete_structured(messages, pydantic_model, max_tokens=4096, ai=None):
    """Return a validated Pydantic object from ANY provider via prompt-guided JSON.

    We ask for JSON matching the model's schema, parse, validate, and retry once with
    the validation error. This is portable — it needs no provider-specific structured-
    output feature, so it works the same on Claude, GPT, Gemini, DeepSeek, etc."""
    schema = json.dumps(pydantic_model.model_json_schema())
    msgs = list(messages) + [{
        "role": "user",
        "content": ("Respond with ONLY a single valid JSON object — no prose, no "
                    f"markdown fences — matching this JSON schema:\n{schema}"),
    }]
    ai = ai or _saved_ai()
    last_err = None
    for _ in range(2):
        resp = await acompletion(msgs, max_tokens=max_tokens, ai=ai)
        text = _strip_fences(resp.choices[0].message.content or "")
        try:
            return pydantic_model(**json.loads(text))
        except Exception as e:  # invalid JSON or schema violation
            last_err = e
            msgs = msgs + [
                {"role": "assistant", "content": text},
                {"role": "user", "content": f"That was invalid ({e}). Return corrected JSON only."},
            ]
    raise ValueError(f"Model did not return valid structured output: {last_err}")


async def test_llm(ai: dict | None = None) -> tuple[bool, str]:
    """Cheap round-trip used by the setup wizard's 'Verify' button."""
    ai = ai or _saved_ai()
    model, kw = resolve(ai)
    try:
        await litellm.acompletion(
            model=model, messages=[{"role": "user", "content": "Reply with the single word OK."}],
            max_tokens=8, **kw,
        )
        return True, f"Connected to {ai.get('provider')} · {model.split('/')[-1]}."
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def model_label() -> str:
    ai = _saved_ai()
    return f"{ai.get('provider')}:{ai.get('model')}"
