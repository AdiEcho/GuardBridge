# GuardBridge

Turn any OpenAI-compatible chat LLM into a Qwen3Guard-compatible safety classifier — as a drop-in proxy for sub2api's prompt audit.

GuardBridge accepts the same `POST /v1/chat/completions` call that sub2api's Guard node would otherwise send to Qwen3Guard, classifies the prompt with **any** chat model you choose (Opus, Fable, GPT, DeepSeek, …), and replies with the strict two-line plaintext that sub2api's `ParseQwen3Guard` expects:

```
Safety: Unsafe
Categories: Jailbreak
```

One sentence: `generic chat LLM → (system prompt + JSON verdict) → strict Qwen3Guard plaintext`.

## How it works

```
sub2api Guard node
  │  POST /v1/chat/completions          (messages=[{role:user,...}], max_tokens=64, …)
  ▼
GuardBridge
  │  1. take the LAST role=user message only (assistant/system/tool ignored)
  │  2. wrap it with GuardBridge's own system prompt (YAML-replaceable)
  │  3. POST /v1/chat/completions to your upstream model (temperature=0,
  │     GuardBridge's own max_tokens, seed optional)
  │  4. parse the model reply:
  │        JSON {"safety":"…","categories":[…]} first,
  │        else legal two-line plaintext fallback,
  │        else fail closed
  │  5. respond with exactly two canonical lines
  ▼
sub2api parses "Safety:" / "Categories:" — no sub2api code changes
```

The inbound `max_tokens=64` only bounds the short two-line reply; it is **never** forwarded upstream (that would truncate the JSON verdict).

## Quick start

```sh
make build
cp config.example.yaml config.yaml   # edit upstream.base_url / api_key / model
./guardbridge -config config.yaml
```

In sub2api, point the Guard node's Base URL at GuardBridge (e.g. `http://127.0.0.1:8080`) and pick any model name — the audit result comes from your configured upstream model, not this field.

## Configuration

See `config.example.yaml`. Key fields:

| Field | Meaning |
|-------|---------|
| `listen` | Listen address; keep loopback unless `inbound_token` is set |
| `inbound_token` | Optional bearer token for inbound requests; empty = no auth |
| `upstream.base_url` | OpenAI-compatible endpoint; trailing `/v1` optional |
| `upstream.model` | Model used for verdicts |
| `upstream.timeout_ms` | Upstream call timeout (100–30000) |
| `upstream.max_tokens` | Generation budget for the verdict (never the inbound 64) |
| `upstream.seed` | Optional sampling seed; `null` omits it |
| `system_prompt` | Replaces the built-in bilingual prompt; restart to apply |

**Timeout chain:** sub2api's Guard node applies its own timeout (default 3000 ms, max 30000 ms) as both header and total deadline. Set the sub2api endpoint timeout *above* GuardBridge's `upstream.timeout_ms` — otherwise the caller cuts off first and slow audits surface as 503s on the sub2api side.

## Fail-closed semantics

GuardBridge never forges a verdict. Nothing is rendered as `Safe` or `Unsafe` unless a real parse succeeded.

| Upstream condition | GuardBridge response | sub2api classification |
|--------------------|----------------------|------------------------|
| Timeout / network error | 504 | unavailable, retryable |
| Non-2xx from upstream | 502 | unavailable, retryable |
| 2xx but unparseable content | 502 `invalid_guard_output` | unavailable, retryable |
| No user text in inbound request | 400 `no_user_content` | — |
| `stream: true` inbound | 400 `stream_not_supported` | — |

The 502-on-invalid choice (vs 200 + unparseable body) is deliberate: sub2api classifies 5xx as `ErrorCodeUnavailable` with bounded retries (5s/30s/2m backoff), while 2xx + bad content is terminal `invalid` with no retry. Since verdict quality is deterministic at temperature 0, we prefer surfacing the failure as unavailable so sub2api can fail over to other endpoints rather than silently dropping the audit.

Logs contain request ids, statuses, parse path, and the safety label on success — never prompts, API keys, or auth headers.

## Contract notes

- **Probe compatibility:** sub2api's endpoint probe does `GET /v1/models`; GuardBridge returns 404 there, which makes the probe fall back to a real `Scan("Hello")` — i.e. the probe exercises the full pipeline. If `/v1/models` is ever added, it must list the configured upstream model to keep that behavior honest.
- **Categories:** the nine official Qwen3Guard labels, comma-space joined; empty set renders `None`. Output is canonical labels only — unknown categories never appear in a 2xx body.
- **Prompt-only:** v1 audits the last `user` message only. Response moderation (`Refusal:`) and stream-level moderation are non-goals.

## Trust model (known limitation)

GuardBridge is exactly as injection-resistant as the upstream model plus your system prompt. A user prompt that *itself contains* a complete valid two-line verdict can be echoed verbatim by the model and will legitimately parse. The JSON-first pipeline and strict schema reduce accidental acceptance, but do not eliminate deliberate echo attacks. Choose a strong upstream model and treat GuardBridge as a translator, not a sandbox.

## Development

```sh
make build   # → ./guardbridge
make test    # go test ./... (mock upstreams only, no network)
make vet
```

Test suite: ported `ParseQwen3Guard` golden cases, JSON/plaintext dual-path parsing, renderer round-trips (all nine categories), Scan-shaped protocol probe against a mock upstream, fail-closed matrix, and canary-based leak checks for prompts and API keys.

## License

See [LICENSE](LICENSE).
