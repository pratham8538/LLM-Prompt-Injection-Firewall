# LLM Prompt Injection Firewall — Stages 1–7

## Files
- `detector.py`      — Stage 1/7: core detection engine, output scanning, encoding/homoglyph defenses
- `test_detector.py` — Stage 1: scripted test harness
- `api.py`           — Stage 2/4/5/6/7: full API surface (below)
- `test_client.html` — Stage 3: browser test console for `/api/analyze`
- `llm_provider.py`  — Stage 4/7: provider adapters (Gemini, OpenAI, Claude, mock, mock_leaky)
- `storage.py`       — Stage 5/6/7: SQLite logging, settings, rule-weight overrides, review insights
- `dashboard.html`   — Stage 6: admin dashboard

## Setup

```
pip install fastapi uvicorn requests --break-system-packages
```

Environment variables (all optional):
```
GEMINI_API_KEY=...        # use real Gemini
OPENAI_API_KEY=...        # use real OpenAI
ANTHROPIC_API_KEY=...     # use real Claude
LLM_PROVIDER=mock_leaky   # force a specific provider; mock_leaky always
                           # returns a "leaked" response, for testing the
                           # output-scan path without a live LLM
ADMIN_API_KEY=...         # protects /api/logs, /api/statistics,
                           # /api/settings, /api/rules/*, review endpoints.
                           # Unset = unauthenticated (fine for local dev;
                           # the API prints a warning on startup).
```
With no key set at all, `/api/chat` uses `MockProvider` — full pipeline
still testable end-to-end.

## Run

```
python3 test_detector.py                        # scripted detection tests
uvicorn api:app --reload --port 8000             # start the API
```

Open `test_client.html` or `dashboard.html` directly in a browser — both
are static files with an editable "API" field (defaults to
`http://localhost:8000`). If `ADMIN_API_KEY` is set, `dashboard.html`
will need that key wired in to reach the admin endpoints (it currently
assumes dev mode / no auth — add an `X-API-Key` header in its fetch
calls if you turn auth on).

## API summary

| Method | Path | Stage | Purpose |
|---|---|---|---|
| POST | `/api/analyze` | 2 | Analyze a prompt, no LLM call |
| POST | `/api/chat` | 4/7 | Analyze → forward to LLM if not blocked → scan the response |
| GET | `/api/logs` | 5 | Recent security events *(admin)* |
| GET | `/api/statistics` | 5 | Dashboard summary *(admin)* |
| GET/PUT | `/api/settings` | 6 | Risk thresholds *(admin)* |
| PATCH | `/api/logs/{id}/review` | 6 | Mark event legitimate / actual_attack *(admin)* |
| GET | `/api/learning/insights` | 7 | Suggested rule-weight changes from review labels *(admin)* |
| GET/PUT | `/api/rules/weights` | 7 | Read/apply rule-weight overrides *(admin)* |

## Stage 7 — what was added and how it was verified

**Output scanning.** `scan_output()` checks the LLM's *response*, not just
the prompt — compliance-confirmation phrases ("Sure, I'll ignore my
guidelines...") and, if you pass `system_prompt_fingerprint` in the
`/api/chat` request, n-gram overlap against your real system prompt (kept
in-memory only, never logged). Verified live with `LLM_PROVIDER=mock_leaky`:
the response was withheld (`llm_response: null`, `output_flagged: true`)
even though the input side had allowed the request.

**Multi-provider.** `llm_provider.py` now has `GeminiProvider`,
`OpenAIProvider`, and `ClaudeProvider`, all implementing the same
`LLMProvider.generate()` interface — `api.py` never imports a vendor SDK
directly. Selection is `LLM_PROVIDER` env var, or auto-detected from
whichever `*_API_KEY` is set.

**Encoding/obfuscation upgrades.** Added ROT13 decode-and-rescan,
URL-encoding detection (both contiguous `%XX` blobs and scattered tokens),
and homoglyph normalization (Cyrillic/Greek lookalike letters folded to
Latin before matching). Verified: a fully ROT13-encoded version of the
canonical attack now correctly scores 75/HIGH/BLOCK (previously landed at
60/MEDIUM/WARN — the payload-severity scaling fix in `analyze_prompt` is
what closed that gap).

**Learning mode.** `GET /api/learning/insights` aggregates your dashboard
review labels (Legit / Attack) per detection category and suggests a new
weight — categories reviewed "legitimate" ≥3 times get a suggested
decrease, proportional to how often they were wrong; "actual_attack"-heavy
categories get a small increase. Nothing changes automatically — an admin
applies suggestions via `PUT /api/rules/weights`. Verified live: after
marking 4 `role_hijack` events "legitimate," the insight endpoint
suggested dropping that category's weight from 45→10; applying it dropped
a live test prompt's score from 45 (WARN) to 10 (ALLOW).

**Admin auth.** All dashboard-facing endpoints now require `X-API-Key`
when `ADMIN_API_KEY` is set. `/api/analyze` and `/api/chat` stay open,
since those are meant to be called by client applications directly.
Verified: unauthenticated request → 401, correct key → 200.

## What's still not here
Real ML-based scoring (this is a transparent heuristic, not a trained
model), rate limiting, per-application policy overrides, and a UI for
managing provider API keys — all reasonable next steps but out of scope
for a project-blueprint-driven build.
