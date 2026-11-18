"""Upstream prompt-cache probe through agent-lb (operator-run; spends real quota).

Sends the same ~20k-token prompt REPEATS times per variant (fresh random prefix
per variant, so nothing is cached beforehand) and prints prompt/cached tokens:

  client  : request as a generic OpenAI client would send it (no Codex headers)
  codex   : identical body, plus the Codex CLI fingerprint codex-lb used to send
            (User-Agent codex_cli_rs/..., originator, version)
  inst    : identical body plus a per-run installation id, sent like Codex CLI
            and codex-lb do (client_metadata + x-codex-installation-id header)
  codex+inst : both of the above
  hint    : x-codex-routing-hint: model=<MODEL> (what Codex CLI and codex-lb send)
  codex+hint : Codex fingerprint plus the routing hint
Select with VARIANTS=client,codex,inst,codex+inst,hint,codex+hint (default: all).

If "codex" hits the cache consistently and "client" does not, the client
fingerprint is what decides cache affinity upstream.

Usage (WSL):  API_KEY=sk-clb-... python3 -I tools/cache_probe.py
Env: ENDPOINT (chat|responses, default chat), BASE_URL (default http://tailscale-codex-lb:2455), MODEL (default
gpt-5.4-mini), REPEATS (default 4), CODEX_VERSION (default 0.169.0).
Cost: about 2 * REPEATS * 20k input tokens. Never prints the key.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid

BASE_URL = os.environ.get("BASE_URL", "http://tailscale-codex-lb:2455").rstrip("/")
MODEL = os.environ.get("MODEL", "gpt-5.4-mini")
REPEATS = int(os.environ.get("REPEATS", "4"))
CODEX_VERSION = os.environ.get("CODEX_VERSION", "0.169.0")
ENDPOINT = os.environ.get("ENDPOINT", "chat")  # chat: /v1/chat/completions, responses: /v1/responses
API_KEY = os.environ["API_KEY"]

CODEX_HEADERS = {
    "User-Agent": f"codex_cli_rs/{CODEX_VERSION} (Linux; x86_64) xterm-256color",
    "originator": "codex_cli_rs",
    "version": CODEX_VERSION,
}


def body(nonce: str, installation_id: str | None = None) -> bytes:
    filler = " ".join(f"Reference line {i}: the quick brown fox jumps over the lazy dog." for i in range(1700))
    extra = {"client_metadata": {"x-codex-installation-id": installation_id}} if installation_id else {}
    system = f"Probe {nonce}. You answer with one word.\n{filler}"
    if ENDPOINT == "responses":
        return json.dumps(
            {
                **extra,
                "model": MODEL,
                "reasoning": {"effort": "low"},
                "instructions": system,
                "input": [{"role": "user", "content": "Reply with the single word OK."}],
                "stream": False,
            }
        ).encode()
    return json.dumps(
        {
            **extra,
            "model": MODEL,
            "reasoning_effort": "low",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": "Reply with the single word OK."},
            ],
        }
    ).encode()


def send(payload: bytes, extra: dict[str, str]) -> tuple[int, int, float]:
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json", **extra}
    if "User-Agent" not in extra:
        headers["User-Agent"] = "cache-probe/1.0"
    path = "/v1/responses" if ENDPOINT == "responses" else "/v1/chat/completions"
    request = urllib.request.Request(f"{BASE_URL}{path}", data=payload, headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            usage = json.load(response).get("usage") or {}
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:500]}") from None
    if ENDPOINT == "responses":
        details = usage.get("input_tokens_details") or {}
        return usage.get("input_tokens", 0), details.get("cached_tokens", 0) or 0, time.monotonic() - started
    details = usage.get("prompt_tokens_details") or {}
    return usage.get("prompt_tokens", 0), details.get("cached_tokens", 0) or 0, time.monotonic() - started


def main() -> None:
    variants = {
        "client": (False, {}),
        "codex": (False, CODEX_HEADERS),
        "inst": (True, {}),
        "codex+inst": (True, CODEX_HEADERS),
        "hint": (False, {"x-codex-routing-hint": f"model={MODEL}"}),
        "codex+hint": (False, {**CODEX_HEADERS, "x-codex-routing-hint": f"model={MODEL}"}),
    }
    selected = os.environ.get("VARIANTS", ",".join(variants)).split(",")
    for variant in selected:
        with_installation, headers = variants[variant]
        installation_id = str(uuid.uuid4()) if with_installation else None
        extra = {**headers, "x-codex-installation-id": installation_id} if installation_id else headers
        payload = body(uuid.uuid4().hex, installation_id)
        hits = 0
        for attempt in range(1, REPEATS + 1):
            prompt, cached, seconds = send(payload, extra)
            hits += attempt > 1 and cached > prompt // 2
            print(f"{variant:10s} #{attempt}  prompt={prompt:6d}  cached={cached:6d}  ({seconds:4.1f}s)", flush=True)
            time.sleep(2)
        print(f"{variant:10s} repeat hits: {hits}/{REPEATS - 1}\n", flush=True)


if __name__ == "__main__":
    main()
