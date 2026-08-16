"""
LLM Prompt Injection Firewall — API
=====================================

Stage 2: POST /api/analyze          — detection only, no LLM call
Stage 4: POST /api/chat             — analyze, then forward to LLM if allowed
Stage 5: GET  /api/logs             — recent security events
         GET  /api/statistics       — dashboard summary stats
Stage 6: GET/PUT /api/settings      — admin-configurable thresholds
         PATCH /api/logs/{id}/review — mark an event legitimate / actual attack

Run:
    uvicorn api:app --reload --port 8000

Gemini calls only work with network access + GEMINI_API_KEY set; without
a key, /api/chat automatically falls back to a mock provider so the full
pipeline is still testable end-to-end (see llm_provider.py).
"""

from __future__ import annotations

import os

# pyrefly: ignore [missing-import]
from fastapi import Depends, FastAPI, Header, HTTPException
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field

import storage
from detector import DEFAULT_RULE_WEIGHTS, analyze_prompt, scan_output
from llm_provider import get_provider

app = FastAPI(
    title="LLM Prompt Injection Firewall",
    description="Detection API + LLM-forwarding + logging + admin endpoints",
    version="0.7.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    storage.init_db()


def _active_thresholds() -> dict:
    raw = storage.get_settings()
    # storage stores lists [low, high]; detector wants tuples
    return {k: tuple(v) for k, v in raw.items()}


def _active_rule_weights() -> dict:
    overrides = storage.get_rule_weights()
    return overrides if overrides else DEFAULT_RULE_WEIGHTS


# ---------------------------------------------------------------------------
# Stage 7 — admin authentication
# ---------------------------------------------------------------------------
#
# Protects the dashboard-facing endpoints (logs, statistics, settings,
# review). /api/analyze and /api/chat stay open, since those are the ones
# calling applications are meant to hit directly.
#
# Set ADMIN_API_KEY to enable enforcement. If unset, auth is a no-op —
# convenient for local dev, but the API prints a one-time startup warning
# so this isn't silently insecure in a real deployment.

ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

if not ADMIN_API_KEY:
    print(
        "[firewall] WARNING: ADMIN_API_KEY is not set — admin endpoints "
        "(/api/logs, /api/statistics, /api/settings, review) are UNAUTHENTICATED. "
        "Set ADMIN_API_KEY before exposing this outside local dev."
    )


def require_admin(x_api_key: str | None = Header(default=None)) -> None:
    if ADMIN_API_KEY is None:
        return  # dev mode, no key configured
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


# ---------------------------------------------------------------------------
# Stage 2 — /api/analyze
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)
    application_id: str | None = None


class AnalyzeResponse(BaseModel):
    threat_score: int
    risk_level: str
    action: str
    detections: list[str]
    decoded_content_flagged: bool
    event_id: str


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    result = analyze_prompt(req.prompt, thresholds=_active_thresholds(), rule_weights=_active_rule_weights())
    event_id = storage.log_event(
        prompt=req.prompt,
        threat_score=result.score,
        risk_level=result.risk,
        action=result.action,
        detections=result.detections,
        endpoint="/api/analyze",
        application_id=req.application_id,
    )
    return AnalyzeResponse(
        threat_score=result.score,
        risk_level=result.risk,
        action=result.action,
        detections=result.detections,
        decoded_content_flagged=result.decoded_content_flagged,
        event_id=event_id,
    )


# ---------------------------------------------------------------------------
# Stage 4 + 7 — /api/chat  (analyze -> forward to LLM if not blocked
#                            -> scan the LLM's response before returning it)
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)
    application_id: str | None = None
    system_prompt_fingerprint: str | None = Field(
        default=None,
        description="Optional: the app's real system prompt, used only in-memory "
        "to detect verbatim leakage in the LLM's response. Never logged.",
    )


class ChatResponse(BaseModel):
    threat_score: int
    risk_level: str
    action: str
    detections: list[str]
    event_id: str
    llm_response: str | None = None
    blocked_reason: str | None = None
    output_flagged: bool = False
    output_categories: list[str] = []


@app.post("/api/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    result = analyze_prompt(req.prompt, thresholds=_active_thresholds(), rule_weights=_active_rule_weights())
    event_id = storage.log_event(
        prompt=req.prompt,
        threat_score=result.score,
        risk_level=result.risk,
        action=result.action,
        detections=result.detections,
        endpoint="/api/chat",
        application_id=req.application_id,
    )

    if result.action == "BLOCK":
        # The core security boundary: the LLM provider is never called
        # for a blocked request.
        return ChatResponse(
            threat_score=result.score,
            risk_level=result.risk,
            action=result.action,
            detections=result.detections,
            event_id=event_id,
            llm_response=None,
            blocked_reason="Request blocked by firewall before reaching the LLM.",
        )

    # ALLOW and WARN both forward to the LLM. WARN is logged/visible in the
    # dashboard for review, but doesn't hard-fail the request — matching
    # the doc's "WARN / SANITIZE" policy without a sanitizer built yet.
    provider = get_provider()
    try:
        llm_text = provider.generate(req.prompt)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"LLM provider error: {exc}") from exc

    # Output scanning (Stage 7): check the response itself before it goes
    # back to the user. A confirmed leak/jailbreak-success gets withheld
    # rather than passed through, even though the input side allowed it.
    output_scan = scan_output(llm_text, req.system_prompt_fingerprint)
    if output_scan.flagged:
        storage.log_event(
            prompt=f"[OUTPUT SCAN FLAGGED] {llm_text}",
            threat_score=100,
            risk_level="HIGH",
            action="BLOCK",
            detections=output_scan.categories,
            endpoint="/api/chat:output",
            application_id=req.application_id,
        )
        return ChatResponse(
            threat_score=result.score,
            risk_level=result.risk,
            action=result.action,
            detections=result.detections,
            event_id=event_id,
            llm_response=None,
            blocked_reason="LLM response withheld: output scan flagged a likely leak or jailbreak success.",
            output_flagged=True,
            output_categories=output_scan.categories,
        )

    return ChatResponse(
        threat_score=result.score,
        risk_level=result.risk,
        action=result.action,
        detections=result.detections,
        event_id=event_id,
        llm_response=llm_text,
        blocked_reason=None,
        output_flagged=False,
        output_categories=[],
    )


# ---------------------------------------------------------------------------
# Stage 5 — logs + statistics (admin-protected)
# ---------------------------------------------------------------------------

@app.get("/api/logs", dependencies=[Depends(require_admin)])
def logs(limit: int = 50, offset: int = 0) -> list[dict]:
    return storage.get_events(limit=limit, offset=offset)


@app.get("/api/statistics", dependencies=[Depends(require_admin)])
def statistics() -> dict:
    return storage.get_statistics()


# ---------------------------------------------------------------------------
# Stage 6 — admin settings + false-positive review (admin-protected)
# ---------------------------------------------------------------------------

class SettingsPayload(BaseModel):
    LOW: list[int]
    MEDIUM: list[int]
    HIGH: list[int]


@app.get("/api/settings", dependencies=[Depends(require_admin)])
def get_settings() -> dict:
    return storage.get_settings()


@app.put("/api/settings", dependencies=[Depends(require_admin)])
def put_settings(payload: SettingsPayload) -> dict:
    thresholds = {"LOW": payload.LOW, "MEDIUM": payload.MEDIUM, "HIGH": payload.HIGH}
    for level, val in thresholds.items():
        if len(val) != 2:
            raise HTTPException(400, f"{level}: threshold list must contain exactly 2 integers [low, high]")
        lo, hi = val
        if not (0 <= lo <= 100 and 0 <= hi <= 100):
            raise HTTPException(400, f"{level}: values must be between 0 and 100")
        if lo > hi:
            raise HTTPException(400, f"{level}: low must be <= high")
    return storage.update_settings(thresholds)


class ReviewPayload(BaseModel):
    label: str  # "legitimate" or "actual_attack"


@app.patch("/api/logs/{event_id}/review", dependencies=[Depends(require_admin)])
def review_event(event_id: str, payload: ReviewPayload) -> dict:
    if payload.label not in ("legitimate", "actual_attack"):
        raise HTTPException(400, "label must be 'legitimate' or 'actual_attack'")
    ok = storage.set_review_label(event_id, payload.label)
    if not ok:
        raise HTTPException(404, "event not found")
    return {"id": event_id, "review_label": payload.label}


# ---------------------------------------------------------------------------
# Stage 7 — learning mode (admin-protected)
# ---------------------------------------------------------------------------
#
# Not full ML — a transparent, auditable heuristic over the review labels
# the admin has already been assigning from the dashboard (Stage 6):
#
#   - A category that keeps showing up on events marked "legitimate"
#     (false positives) gets a suggested weight DECREASE, proportional to
#     how often it was wrong.
#   - A category that's mostly confirmed "actual_attack" gets a small
#     suggested INCREASE, capped at 100.
#   - Categories with fewer than MIN_SAMPLES reviews are left alone —
#     not enough evidence to move a production security control.
#
# Suggestions are just that: GET /api/learning/insights never changes
# scoring by itself. An admin has to explicitly PUT /api/rules/weights
# to apply them (or their own hand-picked numbers).

MIN_SAMPLES_FOR_SUGGESTION = 3


def _suggest_weight(current_weight: int, legit: int, attack: int) -> int:
    total = legit + attack
    if total < MIN_SAMPLES_FOR_SUGGESTION:
        return current_weight
    legit_ratio = legit / total
    if legit_ratio >= 0.5:
        # Frequently a false positive: pull the weight down, floor at 10
        # so the category still logs but stops driving BLOCK on its own.
        return max(10, round(current_weight * (1 - legit_ratio)))
    # Mostly confirmed attacks: nudge up a little, capped at 100.
    return min(100, current_weight + 5)


@app.get("/api/learning/insights", dependencies=[Depends(require_admin)])
def learning_insights() -> dict:
    tally = storage.get_review_insights()
    current_weights = _active_rule_weights()

    insights = []
    for category, base_weight in current_weights.items():
        counts = tally.get(category, {"legitimate": 0, "actual_attack": 0})
        legit, attack = counts.get("legitimate", 0), counts.get("actual_attack", 0)
        suggested = _suggest_weight(base_weight, legit, attack)
        insights.append({
            "category": category,
            "current_weight": base_weight,
            "legitimate_reviews": legit,
            "actual_attack_reviews": attack,
            "sample_size": legit + attack,
            "suggested_weight": suggested,
            "has_suggestion": suggested != base_weight,
        })

    return {"min_samples_required": MIN_SAMPLES_FOR_SUGGESTION, "insights": insights}


class RuleWeightsPayload(BaseModel):
    weights: dict[str, int]


@app.put("/api/rules/weights", dependencies=[Depends(require_admin)])
def put_rule_weights(payload: RuleWeightsPayload) -> dict:
    for category, weight in payload.weights.items():
        if category not in DEFAULT_RULE_WEIGHTS:
            raise HTTPException(400, f"Unknown rule category: {category}")
        if not (0 <= weight <= 100):
            raise HTTPException(400, f"{category}: weight must be 0-100")
    # Merge with existing overrides rather than requiring the full set
    # every time, so a single-category tweak doesn't reset the rest.
    merged = dict(_active_rule_weights())
    merged.update(payload.weights)
    return storage.update_rule_weights(merged)


@app.get("/api/rules/weights", dependencies=[Depends(require_admin)])
def get_rule_weights() -> dict:
    return _active_rule_weights()
