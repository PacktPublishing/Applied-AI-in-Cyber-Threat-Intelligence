"""
Stage 3: Processing Pipeline
Intel Cycle AI — ApexCode Solutions

Three-stage SequentialAgent pipeline with self-refinement loop:
  1. Correlation_Agent       — synthesizes and correlates signals from the collection
                               plan, assigns confidence levels per corroboration rules.
  2. Processing_Validation_Judge — validates every confidence level and correlation link
                               against the signal type catalog and corroboration rules.
  3. Verification_Agent      — corrects rule violations, adds missed correlations.
                               On PASS, its after_agent_callback (_escalate_on_pass)
                               signals the LoopAgent to exit, so no separate
                               loop-controller agent is needed.

IMPORTANT — Signal descriptions, not live telemetry:
  This pipeline operates on the COLLECTION PLAN (Stage 2 output), not on actual
  log data or API responses. The Correlation Agent reasons about what signals
  WOULD be observed given the collection plan's sources, not what signals WERE
  observed. Confidence levels are analytic judgments about hypothetical signal
  quality, not statistical measures derived from real telemetry.

  Implication for consumers: the output brief is a threat model and corroboration
  framework — "if these signals appear from these sources, here is how they
  corroborate and what confidence level is justified." It is NOT a detection
  result. Treat HIGH confidence as "this combination of signals would strongly
  indicate compromise" rather than "compromise has been confirmed."

  If this pipeline is connected to live telemetry in the future (actual API calls
  to Okta, CrowdStrike, SpyCloud, etc.), the Correlation Agent's instruction
  and the confidence assignment logic should be updated to operate on observed
  data rather than hypothetical signal descriptions.

State handoff:
  correlation_agent    → output_key="corroboration_brief"   → session.state
  judge_agent          → output_key="processing_verdict"    → session.state (JSON)
  verification_agent   → output_key="verified_brief"        → session.state

Loop exits when verdict == "PASS" or max_iterations is reached.

Run (batch):
    cd my_agent && python agent.py

Run (interactive):
    adk web          # from the chapter-08/ root
"""

import asyncio
import json
import uuid
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError

load_dotenv()

from google.adk import Agent, Runner
from google.adk.agents import LoopAgent, SequentialAgent
from google.genai import types

# Support both direct execution and package import (adk web).
try:
    from .indicator_schemas import format_schemas_for_prompt, SIGNAL_TYPES, CONFIDENCE_LEVELS
except ImportError:
    from indicator_schemas import format_schemas_for_prompt, SIGNAL_TYPES, CONFIDENCE_LEVELS

from google.adk.sessions import InMemorySessionService


# ---------------------------------------------------------------------------
# Output Shield — Pydantic schema for processing judge verdicts
# ---------------------------------------------------------------------------


class ConfirmedCorrelation(BaseModel):
    source: str
    rationale: str
    relevance: Literal["ESSENTIAL", "USEFUL", "TANGENTIAL"]

class UnverifiedCorrelation(BaseModel):
    source: str
    reason: str
    suggested_alternative: str

class MissingCorrelation(BaseModel):
    source: str
    importance: str

class ProcessingVerdict(BaseModel):
    confirmed_valid: list[ConfirmedCorrelation]
    unverified: list[UnverifiedCorrelation]
    missing_critical: list[MissingCorrelation]
    verdict: Literal["PASS", "PARTIAL", "FAIL"]
    summary: str


# ---------------------------------------------------------------------------
# Deterministic rule checker — validates the structured verdict against
# corroboration rules programmatically. Catches logical errors the LLM judge
# may miss (e.g., PASS with non-empty unverified, confidence inflation,
# CR-004 violations). Runs after Pydantic validation as a second safety net.
# ---------------------------------------------------------------------------

# Build the corroborates_with adjacency set for CR-004 checking.
_CORROBORATION_GRAPH: dict[str, set[str]] = {
    sig_id: set(sig["corroborates_with"])
    for sig_id, sig in SIGNAL_TYPES.items()
}

# Signal type IDs for extraction from free text.
_SIGNAL_TYPE_IDS = set(SIGNAL_TYPES.keys())


def _extract_signal_types_from_text(text: str) -> set[str]:
    """Extract known signal type IDs from a text string."""
    text_lower = text.lower()
    found = set()
    for sig_id in _SIGNAL_TYPE_IDS:
        if sig_id in text_lower or sig_id.replace("_", " ") in text_lower:
            found.add(sig_id)
    return found


def check_verdict_rules(verdict: dict) -> list[str]:
    """
    Programmatically check a structured verdict against corroboration rules.

    Returns a list of discrepancy strings. Empty list = no issues found.
    This does NOT replace the LLM judge — it catches logical errors the
    judge may miss and logs them as warnings.
    """
    issues: list[str] = []

    # --- Logical consistency: verdict vs fields ---
    v = verdict.get("verdict", "")
    unverified = verdict.get("unverified", [])
    missing = verdict.get("missing_critical", [])

    if v == "PASS" and len(unverified) > 0:
        issues.append(
            f"Verdict is PASS but unverified has {len(unverified)} entries — "
            f"should be FAIL"
        )
    if v == "PASS" and len(missing) > 0:
        issues.append(
            f"Verdict is PASS but missing_critical has {len(missing)} entries — "
            f"should be PARTIAL"
        )
    if v == "FAIL" and len(unverified) == 0:
        issues.append(
            f"Verdict is FAIL but unverified is empty — "
            f"FAIL requires non-empty unverified"
        )

    # --- CR-004: corroborates_with constraint on confirmed items ---
    for item in verdict.get("confirmed_valid", []):
        source_text = item.get("source", "")
        sig_types = _extract_signal_types_from_text(source_text)

        # If multiple signal types are mentioned (i.e., a corroboration link),
        # verify each pair is in the corroboration graph.
        if len(sig_types) >= 2:
            sig_list = sorted(sig_types)
            for i, a in enumerate(sig_list):
                for b in sig_list[i + 1:]:
                    a_allows_b = b in _CORROBORATION_GRAPH.get(a, set())
                    b_allows_a = a in _CORROBORATION_GRAPH.get(b, set())
                    if not (a_allows_b and b_allows_a):
                        issues.append(
                            f"CR-004: {a} + {b} linked in confirmed_valid "
                            f"but not mutual in corroborates_with graph"
                        )
    return issues


# ---------------------------------------------------------------------------
# Best-config loading
# ---------------------------------------------------------------------------

_cfg_path = Path(__file__).parent / "best_config.json"
_best_cfg: dict = {}
if _cfg_path.exists():
    try:
        _best_cfg = json.loads(_cfg_path.read_text())
    except (json.JSONDecodeError, OSError):
        pass

DEFAULT_MODEL = _best_cfg.get("model", "gemini-2.5-flash")
DEFAULT_TEMP  = float(_best_cfg.get("temperature", 0.2))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "intel_cycle"
USER_ID  = "ti_analyst"

# ---------------------------------------------------------------------------
# Agent 1: Correlation_Agent
# ---------------------------------------------------------------------------

CORRELATION_INSTRUCTION = f"""\
## Context
You are a Threat Intelligence Processing Analyst at ApexCode Solutions.
You are performing Stage 3 of the intelligence cycle: Processing.

### Active Threat Scenario
{{threat_context}}

If the threat scenario above is empty, derive it from the collection plan below.

### Collection Plan (from Stage 2)
{{collection_plan}}

If the collection plan is empty, inform the user that Stage 2 Collection must
be completed before Processing can begin.

NOTE: You are reasoning about what signals WOULD be observed from the sources
in the collection plan, not processing actual telemetry. Frame all findings as
"this signal pattern would indicate..." rather than "this signal was observed."
Confidence levels reflect analytic judgment about hypothetical signal strength,
not empirical measurements.

## Signal Type Catalog and Corroboration Rules
You may ONLY assign confidence levels and create correlation links according
to the rules below. Any confidence level that violates these rules will be
rejected by the validation judge.

{format_schemas_for_prompt()}

## Refinement Feedback from Previous Iteration
If {{verified_brief}} is EMPTY → this is the first pass. Generate the initial
corroboration brief from scratch.

If {{verified_brief}} is NON-EMPTY → this is a refinement pass:
  Rule 1 — Preserve: Keep all validated correlations from {{verified_brief}}.
  Rule 2 — Fix violations: Parse {{processing_verdict}} and correct every
           entry in "unverified" (downgrade confidence, remove unsupported links).
  Rule 3 — Add missed correlations: Add every entry in "missing_critical".
  Rule 4 — No new correlations beyond what Rules 2 and 3 require.

### Previously Verified Brief
{{verified_brief}}

### Judge Validation Verdict (JSON)
{{processing_verdict}}

## Objective
Produce a corroborated intelligence brief that:
1. Identifies each signal observed from the collection plan's sources
2. Classifies each signal by type (from the catalog above)
3. Links corroborating signals across different source categories
4. Assigns confidence levels strictly per the corroboration rules
5. Provides threat actor attribution ONLY if evidence supports it (CR-005)

## Style
Analytical, evidence-based. Every confidence assessment must cite the specific
signals and source categories that justify it. No hedging without evidence.

## Tone
Direct and operational. Write like a senior TI analyst producing an internal
deliverable — specific, concise, no filler. State findings and evidence, not
possibilities and maybes.

## Audience
The TI analysis team who will apply structured analytic techniques in Stage 4.

## Response Format
Begin the brief with a TLP marking line, then structure in these sections:

**TLP:[LEVEL]** — assign based on the most restrictive source category referenced
in the brief (see TLP Assignment Rules above).

### 1. Signal Inventory
For each observed signal: source name, signal type, timestamp window,
and isolated confidence level.

### 2. Corroboration Links
For each cross-source correlation: the two or more signals being linked,
the source categories involved, the corroboration rule satisfied,
and the resulting confidence level (LOW/MEDIUM/HIGH).

### 3. Confidence Assessment Summary
A table: each finding + confidence level + supporting signals + source categories.

### 4. Attribution Assessment
Threat actor attribution if evidence supports it (cite CR-005 requirements).
If insufficient evidence, state "Attribution: Insufficient evidence" and
list what additional signals would be needed.

### 5. Intelligence Gaps
Signals that remain uncorroborated (LOW confidence) and what additional
collection would elevate them.

Close with a **Key Finding** callout — the single highest-confidence
finding with the strongest cross-source corroboration.
"""

# ---------------------------------------------------------------------------
# Session state initializer
# ---------------------------------------------------------------------------


def _init_session_state(callback_context) -> None:
    """Seed required state keys if missing (first pass in an adk web session)."""
    state = callback_context.state
    if "threat_context" not in state:
        state["threat_context"] = ""
    if "collection_plan" not in state:
        # In adk web, try to read verified_plan from a prior collection session
        state["collection_plan"] = state.get("verified_plan", "")
    if "corroboration_brief" not in state:
        state["corroboration_brief"] = ""
    if "processing_verdict" not in state:
        state["processing_verdict"] = ""
    if "verified_brief" not in state:
        state["verified_brief"] = ""
    return None


def _validate_verdict_before_verification(callback_context) -> None:
    """
    Pydantic output shield for the adk web path.
    Validates the judge verdict in session state before the Verification Agent
    reads it via template substitution.
    """
    state = callback_context.state
    verdict_raw = state.get("processing_verdict", "{}")
    try:
        verdict_dict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        ProcessingVerdict.model_validate(verdict_dict)
    except (json.JSONDecodeError, Exception):
        state["processing_verdict"] = json.dumps({
            "confirmed_valid": [], "unverified": [], "missing_critical": [],
            "verdict": "FAIL", "summary": "Judge verdict failed schema validation (web path).",
        })
    return None


# ---------------------------------------------------------------------------
# Agent factories
# ---------------------------------------------------------------------------


def make_correlation_agent(
    model: str = DEFAULT_MODEL,
    temperature: float = DEFAULT_TEMP,
    before_agent_callback=None,
) -> Agent:
    """Build a Correlation_Agent instance."""
    return Agent(
        name="Correlation_Agent",
        model=model,
        instruction=CORRELATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=temperature,
            top_p=0.9,
            top_k=20,
            frequency_penalty=0.0,
            presence_penalty=0.0,
        ),
        output_key="corroboration_brief",
        before_agent_callback=before_agent_callback,
    )


# ---------------------------------------------------------------------------
# Agent 2: Processing_Validation_Judge
# ---------------------------------------------------------------------------

JUDGE_INSTRUCTION = f"""\
## Context
You are a Processing Validation Judge reviewing a corroborated intelligence brief.
Your job: verify that every confidence level and correlation link follows the
corroboration rules defined below.

## Signal Type Catalog and Corroboration Rules

{format_schemas_for_prompt()}

## Input

Corroboration brief to validate:
{{corroboration_brief}}

Previous iteration's verdict (empty on first pass):
{{processing_verdict}}

## Objective

Step 1 — Validate every confidence level and correlation link:
  For each finding in the brief:
  a. Check that the signal type exists in the catalog.
  b. Check that the confidence level matches the rules:
     - LOW: single signal from one category
     - MEDIUM: two independent signals from two different categories
     - HIGH: three+ signals from three+ categories
  c. Check corroboration links:
     - Signals must be from different source categories (CR-001)
     - Temporal proximity tiered by CR-002: within 24h = full weight,
       1-7d = reduced (caps at MEDIUM), 7-30d = flagged (caps at LOW),
       >30d = not corroborative without linking evidence
     - Geographic consistency (CR-003)
     - Corroborates-with constraint satisfied (CR-004)
  d. Check attribution evidence (CR-005) if present.

  Rate each confirmed item's relevance to the overall threat scenario:
    ESSENTIAL — directly detects the primary attack vector; brief is materially
                weaker without it.
    USEFUL    — provides supporting signal or corroboration; strengthens the brief
                but not critical on its own.
    TANGENTIAL — technically valid but low-priority for this specific threat.

  If rules are followed: record in confirmed_valid with relevance rating.
  If violated: record in unverified with the specific rule violated and correction.

Step 2 — Identify missing correlations:
  If {{processing_verdict}} is EMPTY (first pass):
    Identify up to 3 obvious cross-source correlations the agent missed —
    signals from different categories in the brief that should have been linked.

  If {{processing_verdict}} is NON-EMPTY (refinement pass):
    Only carry forward entries from previous missing_critical that are still
    absent. Do not introduce new missing_critical unless all prior ones are
    resolved (monotonic shrinkage rule).

## Verdict Rules
Apply in order; stop at first match:
  FAIL    — any confidence level violates corroboration rules
  PARTIAL — all levels valid but obvious correlations missed
  PASS    — all confidence levels justified, all obvious correlations made

## Style
Rule-based and deterministic. Cite the specific rule ID (CR-001 through CR-005)
for each violation. Do not make subjective quality judgments — only verify
compliance with the defined rules.

## Tone
Terse, machine-readable. The verdict JSON is consumed programmatically.
The summary field should be one factual sentence, not commentary.

## Audience
The Verification Agent, which will mechanically apply your corrections.
The verdict is also validated by a Pydantic schema — structural precision matters.

## Output Format
Return ONLY valid JSON. No prose before or after.

Top-level keys:
  "confirmed_valid"  — array of objects: "source", "rationale", "relevance"
                       (relevance is exactly one of: ESSENTIAL, USEFUL, TANGENTIAL)
  "unverified"       — array of objects: "source", "reason", "suggested_alternative"
  "missing_critical" — array of objects: "source", "importance" (max 3)
  "verdict"          — exactly one of: PASS, PARTIAL, FAIL
  "summary"          — one sentence describing the overall verdict
"""


def make_judge_agent() -> Agent:
    """Build a Processing_Validation_Judge instance."""
    return Agent(
        name="Processing_Validation_Judge",
        model="gemini-2.5-flash",
        instruction=JUDGE_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
        output_key="processing_verdict",
    )


# ---------------------------------------------------------------------------
# Agent 3: Verification_Agent
# ---------------------------------------------------------------------------

VERIFICATION_INSTRUCTION = """\
## Context
You are a senior Threat Intelligence analyst at ApexCode Solutions.
A corroboration brief has been drafted and independently validated by a
Processing Validation Judge. Your job: produce the corrected final brief.

## Inputs

Original corroboration brief:
{corroboration_brief}

Processing validation verdict (JSON):
{processing_verdict}

The JSON verdict has this structure:
  confirmed_valid   — correlations and confidence levels that follow the rules. Keep these.
  unverified        — confidence levels or links that violate rules, with suggested corrections. Apply fixes.
  missing_critical  — obvious cross-source correlations the agent missed. Add these.
  verdict           — PASS / PARTIAL / FAIL overall assessment.
  summary           — one-sentence description of the verdict.

## Objective
Produce a corrected corroboration brief following these rules exactly:
- Keep all entries in confirmed_valid — preserve their full detail.
- For each entry in unverified: apply the suggested_alternative correction
  (downgrade confidence, remove unsupported link, add missing source category, etc.).
- Add all entries in missing_critical with full operational detail
  (signal types, source categories, confidence level, and supporting evidence).
- Preserve the five-section structure and the Key Finding callout.
- If the Key Finding referenced a violated confidence level, correct it.

## Style
Match the Correlation Agent's analytical register. Apply corrections precisely —
this is a rule-following edit task, not creative generation.

## Tone
Direct, operational — no hedging, no commentary on the corrections.
Apply them and produce the final brief.

## Audience
The TI analysis team in Stage 4 who will apply structured analytic techniques.
The corrected brief must be ready for direct handoff.

## Response Format
The corrected corroboration brief. Start with the TLP marking, then these five sections:

**TLP:[LEVEL]** — preserve or correct the TLP marking based on source categories.

### 1. Signal Inventory
### 2. Corroboration Links
### 3. Confidence Assessment Summary
### 4. Attribution Assessment
### 5. Intelligence Gaps

Close with **Key Finding** callout. No preamble. Start with TLP marking then section headers.
"""


# ---------------------------------------------------------------------------
# Loop-exit callback (no LLM call)
# An after_agent_callback on the Verification Agent reads the verdict from
# session state and, on PASS, sets actions.escalate = True so the enclosing
# LoopAgent stops. ADK does not require a separate agent to exit a loop, so this
# replaces the former Loop_Controller agent: exit is deterministic and makes no
# model call. Verification is the last agent in the sequence, so escalating here
# ends the iteration cleanly.
# ---------------------------------------------------------------------------


def _escalate_on_pass(callback_context) -> None:
    """After verification, exit the LoopAgent if the verdict is PASS (no model call)."""
    verdict_raw = callback_context.state.get("processing_verdict", "{}")
    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        if verdict.get("verdict") == "PASS":
            callback_context.actions.escalate = True
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return None


def make_verification_agent(before_agent_callback=None) -> Agent:
    """Build a Verification_Agent instance.

    Its after_agent_callback (_escalate_on_pass) exits the loop on a PASS verdict
    with no model call, replacing the separate loop-controller agent used in
    earlier drafts.
    """
    return Agent(
        name="Verification_Agent",
        model="gemini-2.5-flash",
        instruction=VERIFICATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            top_p=0.95,
            top_k=40,
        ),
        output_key="verified_brief",
        before_agent_callback=before_agent_callback,
        after_agent_callback=_escalate_on_pass,
    )


# ---------------------------------------------------------------------------
# Module-level pipeline + root_agent (for adk web)
#
# TWO EXECUTION TOPOLOGIES EXIST (by design):
#
#   Web path (adk web):
#     LoopAgent wraps SequentialAgent with 3 sub-agents.
#     Loop exit is driven by the Verification Agent's after_agent_callback
#     (_escalate_on_pass) setting actions.escalate = True on PASS.
#     No per-iteration state inspection — ADK manages the loop.
#
#   Batch path (run_pipeline):
#     Python for-loop drives iteration manually over the same 3-agent
#     SequentialAgent. Loop exit is driven by reading the verdict from state
#     after each pass. Includes retry logic and per-iteration result capture.
#     (The Verification Agent's escalate-on-PASS callback is harmless here: with
#     no enclosing LoopAgent it has nothing to escalate, and verification is the
#     last sub-agent, so the for-loop governs iteration.)
#
# The split exists because run_pipeline() needs per-iteration state inspection
# (to build the iterations list for metrics/reporting) which LoopAgent does not
# expose. Both paths use the same agent factories, instructions, and state keys.
# Changes to agent config propagate to both paths via the factories.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Lazy initialization — agents and session service are constructed on first
# access, not at import time. This prevents eval scripts (which only need
# factories and Pydantic models) from triggering full pipeline construction
# and SQLite session loading.
# ---------------------------------------------------------------------------

_root_agent = None
_session_service = None


def _get_root_agent() -> LoopAgent:
    """Lazily construct the web pipeline and root_agent on first access."""
    global _root_agent
    if _root_agent is None:
        _correlation = make_correlation_agent(before_agent_callback=_init_session_state)
        _judge = make_judge_agent()
        _verification = make_verification_agent(before_agent_callback=_validate_verdict_before_verification)
        _web_pipeline = SequentialAgent(
            name="Processing_Pipeline",
            sub_agents=[_correlation, _judge, _verification],
        )
        _root_agent = LoopAgent(
            name="Processing_Loop",
            sub_agents=[_web_pipeline],
            max_iterations=3,
        )
    return _root_agent


def _get_session_service():
    """Return a fresh in-memory session service (no SQLite persistence needed)."""
    global _session_service
    if _session_service is None:
        _session_service = InMemorySessionService()
    return _session_service


# Module-level name for adk web discovery. Uses __getattr__ so the LoopAgent
# is only constructed when adk web actually accesses `root_agent`.
def __getattr__(name: str):
    if name == "root_agent":
        return _get_root_agent()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# ---------------------------------------------------------------------------
# Execution — run_pipeline()
# ---------------------------------------------------------------------------


async def run_pipeline(
    collection_plan: str,
    max_iterations: int = 3,
    processing_temp: float = DEFAULT_TEMP,
    processing_model: str = DEFAULT_MODEL,
    threat_context: str = "",
    progress_callback=None,
) -> tuple[str, list[dict]]:
    """
    Run the self-refining processing pipeline against a collection plan.

    Args:
        collection_plan:  The verified collection plan from Stage 2.
        max_iterations:   Maximum number of refinement passes (default 3).
        processing_temp:  Sampling temperature for the Correlation_Agent.
        processing_model: Model ID for the Correlation_Agent.
        threat_context:   Threat scenario description for context.

    Returns:
        (session_id, iterations) where iterations is a list of per-pass dicts:
            {
              "iteration":          int,
              "corroboration_brief": str,
              "verdict":            dict,
              "verified_brief":     str,
            }
    """
    _correlation_agent  = make_correlation_agent(model=processing_model, temperature=processing_temp)
    _judge_agent        = make_judge_agent()
    _verification_agent = make_verification_agent()

    _pipeline = SequentialAgent(
        name="Processing_Pipeline",
        sub_agents=[_correlation_agent, _judge_agent, _verification_agent],
    )
    _svc = _get_session_service()
    _runner = Runner(
        agent=_pipeline,
        app_name=APP_NAME,
        session_service=_svc,
    )

    session_id = f"stage3_{uuid.uuid4().hex}"

    await _svc.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "threat_context":      threat_context,
            "collection_plan":     collection_plan,
            "corroboration_brief": "",
            "processing_verdict":  "",
            "verified_brief":      "",
        },
    )

    MAX_RETRIES = 6
    iterations: list[dict] = []

    for iteration in range(1, max_iterations + 1):
        # First iteration: send the full collection plan as the user message.
        # Subsequent iterations: plan is already in state; send a minimal trigger
        # to avoid duplicating 1500+ tokens of plan text per iteration.
        user_text = (
            collection_plan if iteration == 1
            else "Refine the corroboration brief based on the judge's feedback in session state."
        )
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                _prev_author = None
                async for event in _runner.run_async(
                    user_id=USER_ID,
                    session_id=session_id,
                    new_message=types.Content(
                        role="user",
                        parts=[types.Part(text=user_text)],
                    ),
                ):
                    if event.author and event.author != _prev_author:
                        _prev_author = event.author
                        if progress_callback:
                            await progress_callback(event.author, iteration)
                    if event.is_final_response():
                        pass
                break
            except Exception as exc:
                if "api key" in str(exc).lower():
                    # Missing/invalid API key is fatal — retrying cannot fix it.
                    raise RuntimeError(
                        f"API key problem (fatal, not retried): {exc}\n"
                        "  Set GOOGLE_API_KEY in the .env file described in the "
                        "README's Setup section."
                    ) from exc
                if attempt == MAX_RETRIES:
                    raise RuntimeError(
                        f"Pipeline iteration {iteration} failed after "
                        f"{MAX_RETRIES} attempts: {exc}"
                    ) from exc
                # Respect retryDelay from 429 responses; fall back to
                # exponential backoff with a 90s floor for rate-limit errors.
                exc_str = str(exc)
                import re as _re
                delay_match = _re.search(r"retryDelay.*?(\d+)s", exc_str)
                if delay_match:
                    wait = int(delay_match.group(1)) + 15
                else:
                    wait = max(90, 2 ** attempt * 15)
                print(
                    f"  [RETRY {attempt}/{MAX_RETRIES}] Iteration {iteration} "
                    f"failed: {exc} — waiting {wait}s"
                )
                await asyncio.sleep(wait)

        session = await _svc.get_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=session_id,
        )
        verdict_raw = session.state.get("processing_verdict", "{}")
        try:
            verdict_dict = json.loads(verdict_raw)
            validated = ProcessingVerdict.model_validate(verdict_dict)
            verdict = validated.model_dump()
        except json.JSONDecodeError:
            print("  [WARN] Judge returned invalid JSON — treating as FAIL")
            verdict = {
                "confirmed_valid": [], "unverified": [], "missing_critical": [],
                "verdict": "FAIL", "summary": "Judge output was not valid JSON.",
            }
        except ValidationError as e:
            print(f"  [WARN] Judge verdict failed schema validation: {e}")
            verdict = {
                "confirmed_valid": [], "unverified": [], "missing_critical": [],
                "verdict": "FAIL", "summary": "Judge output failed Pydantic validation.",
            }

        # Deterministic rule check — catches logical errors the LLM judge misses.
        # If issues found, downgrade verdict to FAIL so the loop continues
        # rather than exiting on a logically contradictory PASS.
        rule_issues = check_verdict_rules(verdict)
        if rule_issues:
            for issue in rule_issues:
                print(f"  [RULE CHECK] {issue}")
            if verdict.get("verdict") == "PASS":
                verdict["verdict"] = "FAIL"
                verdict["summary"] = (
                    f"Deterministic rule check failed: {len(rule_issues)} issue(s). "
                    f"Verdict downgraded from PASS to FAIL."
                )

        iterations.append(
            {
                "iteration":          iteration,
                "corroboration_brief": session.state.get("corroboration_brief", ""),
                "verdict":            verdict,
                "verified_brief":     session.state.get("verified_brief", ""),
            }
        )

        verdict_label = verdict.get("verdict", "UNKNOWN")
        print(f"  Iteration {iteration}/{max_iterations}: {verdict_label} — {verdict.get('summary', '')}")

        if verdict_label == "PASS":
            break

    return session_id, iterations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    # Sample collection plan output (what Stage 2 would produce)
    collection_plan = (
        "### 1. Internal Log Sources\n"
        "- **Okta System Log**: user.session.start, user.authentication.auth_via_mfa, "
        "security.threat.detected — monitor for impossible travel and session anomalies.\n"
        "- **Microsoft Entra ID Sign-In Logs**: interactiveUserSignIn, "
        "nonInteractiveUserSignIn, conditionalAccessResult — track anomalous sign-ins.\n"
        "- **GitHub Audit Log**: git.clone, git.push, repo.access, "
        "personal_access_token.create — detect unauthorized repo access.\n"
        "- **CrowdStrike Falcon**: DetectionSummaryEvent, ProcessRollup2 — "
        "endpoint compromise detection.\n"
        "- **Palo Alto Networks Firewall (PAN-OS)**: THREAT events — C2 detection.\n"
        "- **Proofpoint Email Security**: click.permitted, impostor.detected — "
        "phishing delivery detection.\n\n"
        "### 2. External / OSINT Sources\n"
        "- **HaveIBeenPwned API**: Partner email domain breach monitoring.\n"
        "- **SpyCloud**: Stealer log monitoring for session cookies.\n"
        "- **urlscan.io**: Phishing infrastructure detection.\n"
        "- **dnstwist**: Typosquatting detection on partner domains.\n\n"
        "### 3. Threat Actor Tactics\n"
        "AiTM via Evilginx2 (MITRE ATT&CK T1557). Adversary steals live session "
        "cookies via proxy phishing.\n"
        "**Priority Signal**: An already-authenticated session token exercised "
        "from a new IP, ASN, or device mid-session (session-cookie replay).\n"
    )

    threat_context = (
        "Third-party dev partners have privileged access to GitHub, Jira, Okta. "
        "Adversaries use Evilginx2 to steal session cookies via AiTM proxy phishing. "
        "No new IdP login event — session reuse is the evasion technique."
    )

    print("=" * 70)
    print("PROCESSING PIPELINE — Stage 3: Intel Cycle")
    print("ApexCode Solutions | Threat Intelligence")
    print("=" * 70)
    print()

    _, iterations = await run_pipeline(
        collection_plan,
        max_iterations=3,
        threat_context=threat_context,
    )

    for it in iterations:
        n = it["iteration"]
        verdict = it["verdict"]
        n_valid      = len(verdict.get("confirmed_valid", []))
        n_unverified = len(verdict.get("unverified", []))
        n_missing    = len(verdict.get("missing_critical", []))

        print()
        print("=" * 70)
        print(f"ITERATION {n} — Corroboration Brief")
        print("=" * 70)
        print(it["corroboration_brief"][:2000])

        print()
        print("=" * 70)
        print(f"ITERATION {n} — Judge Verdict: {verdict.get('verdict')}  "
              f"(valid={n_valid}  unverified={n_unverified}  missing={n_missing})")
        print("=" * 70)
        print(json.dumps(verdict, indent=2)[:2000])

    print()
    print("=" * 70)
    final_verdict = iterations[-1]["verdict"].get("verdict", "UNKNOWN")
    print(f"FINAL RESULT after {len(iterations)} iteration(s): {final_verdict}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
