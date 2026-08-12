"""
Stage 7: Feedback Pipeline
Intel Cycle AI — ApexCode Solutions

Three-agent SequentialAgent pipeline with self-refinement loop:
  1. Transformation_Agent  — decomposes raw stakeholder feedback into atomic
                             follow-on QIRs conforming to QIR_TEMPLATE.
  2. Compliance_Judge      — validates template completeness, scope classification,
                             priority justification, compound question splitting,
                             and temporal window explicitness.
  3. Verification_Agent    — corrects violations: fills missing fields, fixes scope
                             misclassification, splits compound QIRs, adds priority
                             justification, makes temporal windows explicit.

Loop exit is handled by _check_loop_exit_callback (before_agent_callback on
Transformation_Agent), which reads the verdict from state and sets escalate=True
on PASS. No LLM-based Loop_Controller agent is needed.

IMPORTANT — Feedback, not dissemination:
  This pipeline operates on STAKEHOLDER FEEDBACK (received after Stage 6
  Dissemination). The Transformation Agent decomposes raw questions/concerns
  into structured follow-on QIRs. The output re-enters the intelligence cycle
  at Stage 1 Requirement.

State handoff:
  transformation_agent  → output_key="feedback_qirs"       → session.state
  compliance_judge      → output_key="feedback_verdict"     → session.state (JSON)
  verification_agent    → output_key="verified_feedback"    → session.state

Loop exits when verdict == "PASS" or max_iterations is reached.

Run (batch):
    python my_agent/agent.py     # from the chapter-12/ directory

Run (interactive):
    adk web                      # from the chapter-12/ directory
"""

import asyncio
import json
import random
import uuid
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError

load_dotenv()

from google.adk import Agent, Runner
from google.adk.agents import LoopAgent, SequentialAgent
from google.adk.events.event import Event as _AdkEvent
from google.adk.events.event_actions import EventActions as _AdkEventActions
from google.genai import types

# Support both direct execution and package import (adk web).
try:
    from .requirement_templates import (
        format_templates_for_prompt, QIR_TEMPLATE, REQUIRED_FIELDS,
        SCOPE_TYPES, PRIORITY_LEVELS, TRANSFORMATION_RULES,
        TEMPLATE_VERSION, validate_qir_fields,
    )
except ImportError:
    from requirement_templates import (
        format_templates_for_prompt, QIR_TEMPLATE, REQUIRED_FIELDS,
        SCOPE_TYPES, PRIORITY_LEVELS, TRANSFORMATION_RULES,
        TEMPLATE_VERSION, validate_qir_fields,
    )

# Session service factory — same try/except pattern as requirement_templates.
try:
    from .session_service import create_session_service
except ImportError:
    from session_service import create_session_service


# ---------------------------------------------------------------------------
# Output Shield — Pydantic schema for feedback judge verdicts
# ---------------------------------------------------------------------------


class ConfirmedQIR(BaseModel):
    source: str
    rationale: str
    relevance: Literal["ESSENTIAL", "USEFUL", "TANGENTIAL"]


class UnverifiedQIR(BaseModel):
    source: str
    reason: str
    suggested_alternative: str


class MissingQIR(BaseModel):
    source: str
    importance: str


class FeedbackVerdict(BaseModel):
    confirmed_valid: list[ConfirmedQIR]
    unverified: list[UnverifiedQIR]
    missing_critical: list[MissingQIR]
    verdict: Literal["PASS", "PARTIAL", "FAIL"]
    summary: str


# ---------------------------------------------------------------------------
# Deterministic rule checker — validates the structured verdict against
# transformation rules programmatically. Catches structural errors the LLM
# judge may miss (e.g., PASS with non-empty unverified).
# ---------------------------------------------------------------------------


def _strip_code_fence(text: str) -> str:
    """Strip a leading/trailing markdown code fence from LLM output.

    Models occasionally wrap JSON output in ```json ... ``` even when prompted
    not to. This helper removes that wrapping defensively before json.loads.
    Returns the input unchanged if no fence is present.
    """
    if not isinstance(text, str):
        return text
    s = text.strip()
    if s.startswith("```"):
        # Drop opening fence and optional language tag (```json, ```python, ```)
        first_newline = s.find("\n")
        if first_newline != -1:
            s = s[first_newline + 1:]
    if s.endswith("```"):
        s = s[:-3].rstrip()
    return s


def check_verdict_rules(verdict: dict) -> list[str]:
    """
    Programmatically check a structured verdict for logical consistency.

    Returns a list of discrepancy strings. Empty list = no issues found.
    """
    issues: list[str] = []

    v = verdict.get("verdict", "")
    unverified = verdict.get("unverified", [])
    missing = verdict.get("missing_critical", [])

    # Logical consistency: verdict vs fields.
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

# Stale-config guard: warn if best_config.json was produced under a different
# template schema version.
_cfg_template_ver = _best_cfg.get("template_version", "")
if _best_cfg and _cfg_template_ver and _cfg_template_ver != TEMPLATE_VERSION:
    print(
        f"[WARN] best_config.json was produced under template schema "
        f"v{_cfg_template_ver}, but current schema is v{TEMPLATE_VERSION}. "
        f"Re-run the gs-run notebook cell in 'Chap 12 Simulations.ipynb' to re-evaluate under the updated rules."
    )

DEFAULT_MODEL = _best_cfg.get("model", "gemini-2.5-flash")
DEFAULT_TEMP  = float(_best_cfg.get("temperature", 0.2))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "intel_cycle"
USER_ID  = "ti_analyst"

# ---------------------------------------------------------------------------
# Agent 1: Transformation_Agent
# ---------------------------------------------------------------------------

TRANSFORMATION_INSTRUCTION = f"""\
## Context
You are a senior Intelligence Requirements Officer at ApexCode Solutions.
You are performing Stage 7 of the intelligence cycle: Feedback.

You have access to the original QIR and the disseminated intelligence product
context. Your task is to process stakeholder feedback received after Stage 6
Dissemination and transform it into formal follow-on QIRs.

### Original QIR Context
{{original_qir}}

If the original QIR above is empty, inform the user that an original QIR
context is required for the feedback pipeline to operate.

### Stakeholder Feedback to Process
{{stakeholder_feedback}}

NOTE: You are decomposing raw stakeholder questions and concerns into
structured, atomic follow-on QIRs. Each distinct question becomes its own QIR.
Compound questions must be split. Every QIR must conform to the QIR_TEMPLATE
with ALL required fields present.

## QIR Template, Scope Types, Priority Levels, and Transformation Rules
You MUST produce QIRs that conform to the template below. The Compliance Judge
will validate every field. Any missing field, misclassified scope, or unjustified
priority will be rejected.

{format_templates_for_prompt()}

## Refinement Feedback from Previous Iteration
If {{verified_feedback}} is EMPTY → this is the first pass. Generate the
initial QIR decomposition from scratch.

If {{verified_feedback}} is NON-EMPTY → this is a refinement pass:
  Rule 1 — Preserve: Keep all correctly formed QIRs from {{verified_feedback}}.
  Rule 2 — Fix violations: Parse {{feedback_verdict}} and correct every
           entry in "unverified" (fill missing fields, fix scope classification,
           add priority justification, make temporal window explicit).
  Rule 3 — Add missing: Add every entry in "missing_critical" (questions from
           the feedback that were not captured as separate QIRs).
  Rule 4 — No changes beyond what Rules 2 and 3 require.

### Previously Verified Feedback
{{verified_feedback}}

### Compliance Judge Verdict (JSON)
{{feedback_verdict}}

## Objective
Decompose the stakeholder feedback into an array of follow-on QIRs. Each QIR
must contain ALL 9 required fields from QIR_TEMPLATE:
  qir_id, originator, raw_feedback, refined_requirement, scope,
  temporal_window, priority, priority_justification, linked_qir

Rules:
1. Each distinct question or concern → separate QIR (TR-001).
2. Every QIR must link to the original QIR via linked_qir (TR-002).
3. Scope must be classified as EXPANSION / DEEPENING / PIVOT / VALIDATION (TR-003).
4. Priority must be justified with operational impact (TR-004).
5. Temporal window must be explicit — no vague references (TR-005).
6. Non-actionable feedback (praise, acknowledgments) → 0 QIRs (TR-006).
7. Compound questions must be split into atomic QIRs.

## Style
Precise, structured. Each QIR is a formal intelligence requirement, not a
paraphrase of the original question. The refined_requirement field must specify
what intelligence is needed, what scope it covers, and what decision it enables.

## Tone
Operational, professional.

## Audience
Stage 1 Requirement agent, which will refine each follow-on QIR into a full
intelligence requirement for the next intelligence cycle.

## Response Format
Return ONLY valid JSON — an array of QIR objects. No prose before or after.

```json
[
  {{
    "qir_id": "FP-001",
    "originator": "<role or name>",
    "raw_feedback": "<verbatim question>",
    "refined_requirement": "<formal requirement statement>",
    "scope": "<EXPANSION|DEEPENING|PIVOT|VALIDATION>",
    "temporal_window": "<explicit time scope>",
    "priority": "<IMMEDIATE|ROUTINE|DEFERRED>",
    "priority_justification": "<operational impact justification>",
    "linked_qir": "<original QIR ID>"
  }}
]
```
"""

# ---------------------------------------------------------------------------
# Session state contract
#
#   Key                   Producer                    Consumer(s)
#   original_qir          External (user/Stage 6)     Transformation_Agent
#   stakeholder_feedback  External (user/Stage 6)     Transformation_Agent
#   feedback_qirs         Transformation_Agent        Compliance_Judge
#   feedback_verdict      Compliance_Judge             Verification_Agent, loop exit
#   verified_feedback     Verification_Agent          Transformation_Agent (refinement)
#
# NAMESPACE ISOLATION: Stage 7 only seeds its own output keys. It does NOT
# overwrite keys written by prior stages.
# ---------------------------------------------------------------------------

# State keys owned by Stage 7 agents.
_STAGE7_OUTPUT_KEYS = {
    "feedback_qirs":     "",   # Written by Transformation_Agent
    "feedback_verdict":  "",   # Written by Compliance_Judge
    "verified_feedback": "",   # Written by Verification_Agent
}

# State keys consumed by Stage 7 but produced externally — read-only.
_STAGE7_INPUT_KEYS = {
    "original_qir",          # The original QIR this feedback traces to
    "stakeholder_feedback",  # Raw feedback from stakeholders
}


def _init_session_state(callback_context) -> None:
    """Seed Stage 7 output keys if missing. Does NOT overwrite upstream keys."""
    state = callback_context.state
    for key, default in _STAGE7_OUTPUT_KEYS.items():
        if key not in state:
            state[key] = default
    for key in _STAGE7_INPUT_KEYS:
        if key not in state:
            state[key] = ""
    return None


def _validate_verdict_before_verification(callback_context) -> None:
    """
    Pydantic output shield for the adk web path.
    Validates the judge verdict in session state before the Verification Agent
    reads it via template substitution.
    """
    state = callback_context.state
    verdict_raw = state.get("feedback_verdict", "{}")
    try:
        verdict_dict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        FeedbackVerdict.model_validate(verdict_dict)
    except (json.JSONDecodeError, ValidationError) as exc:
        print(
            f"  [WARN] Verdict validation failed (web path): "
            f"{type(exc).__name__}: {str(exc)[:200]}"
        )
        state["feedback_verdict"] = json.dumps({
            "confirmed_valid": [], "unverified": [], "missing_critical": [],
            "verdict": "FAIL",
            "summary": f"Judge verdict failed schema validation: {type(exc).__name__}.",
        })
    return None


# ---------------------------------------------------------------------------
# Agent factories
# ---------------------------------------------------------------------------


def make_generator_agent(
    model: str = DEFAULT_MODEL,
    temperature: float = DEFAULT_TEMP,
    before_agent_callback=None,
) -> Agent:
    """Build a Transformation_Agent instance with constrained JSON output."""
    return Agent(
        name="Transformation_Agent",
        description=(
            "Decomposes raw stakeholder feedback into atomic follow-on QIRs. "
            "Each question becomes a separate QIR with scope classification, "
            "priority justification, and explicit temporal window. Output is a "
            "JSON array conforming to QIR_TEMPLATE."
        ),
        model=model,
        instruction=TRANSFORMATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=temperature,
            response_mime_type="application/json",
        ),
        output_key="feedback_qirs",
        before_agent_callback=before_agent_callback,
    )


# ---------------------------------------------------------------------------
# Agent 2: Compliance_Judge
# ---------------------------------------------------------------------------

JUDGE_INSTRUCTION = f"""\
## Context
You are a Compliance Judge reviewing follow-on QIRs generated from stakeholder
feedback. Your job: verify that every QIR conforms to the QIR_TEMPLATE, that
scope classification is correct, that priority is justified, and that all
distinct questions from the feedback have been captured as separate QIRs.

## QIR Template, Scope Types, Priority Levels, and Transformation Rules

{format_templates_for_prompt()}

## Input

Follow-on QIRs to validate:
{{feedback_qirs}}

Original QIR context:
{{original_qir}}

Stakeholder feedback that was processed:
{{stakeholder_feedback}}

Previous iteration's verdict (empty on first pass):
{{feedback_verdict}}

## Objective

Step 1 — Validate template completeness:
  For each QIR:
  a. Verify ALL 9 required fields are present and non-empty:
     qir_id, originator, raw_feedback, refined_requirement, scope,
     temporal_window, priority, priority_justification, linked_qir
  b. Verify qir_id follows FP-NNN format.
  c. Verify linked_qir references the original QIR (QIR- prefix).
  d. Verify scope is one of: EXPANSION, DEEPENING, PIVOT, VALIDATION.
  e. Verify priority is one of: IMMEDIATE, ROUTINE, DEFERRED.

Step 2 — Validate scope classification:
  For each QIR, check that the scope classification matches the actual nature
  of the question using the distinguishing criteria:
  - EXPANSION: asks about MORE entities/systems/time
  - DEEPENING: asks HOW or HOW LONG about existing finding
  - PIVOT: introduces new domain (legal, regulatory, business)
  - VALIDATION: asks WHETHER something is true or effective

Step 3 — Validate priority justification:
  For each QIR, verify priority_justification:
  a. Is non-empty and substantive (not just "because requested").
  b. Cites at least one criterion from the corresponding PRIORITY_LEVELS entry.
  c. Is grounded in operational impact, not authority of the requester.

Step 4 — Validate temporal window:
  For each QIR, verify temporal_window is explicit:
  a. Specifies a concrete duration (e.g., "90-day retroactive hunt") or a
     monitoring mandate with review cycle (e.g., "continuous, 30-day review").
  b. Does NOT use vague terms like "recent", "ongoing", or "as needed".

Step 5 — Validate completeness of feedback capture:
  a. Count distinct questions/concerns in the original stakeholder feedback.
  b. Verify each distinct question maps to at least one QIR.
  c. Detect compound questions that were not split (TR-001 violation).
  d. Verify non-actionable feedback (praise, acknowledgments) produced 0 QIRs.

  If {{feedback_verdict}} is EMPTY (first pass):
    Identify up to 3 questions not captured as separate QIRs.

  If {{feedback_verdict}} is NON-EMPTY (refinement pass):
    Only carry forward entries from previous missing_critical that are still
    absent. Do not introduce new missing_critical unless all prior ones are
    resolved (monotonic shrinkage rule).

Step 6 — Rate relevance of each confirmed QIR:
  ESSENTIAL — captures a critical stakeholder question; omission means the
              feedback loop is incomplete.
  USEFUL    — valid QIR that extends understanding but not strictly required.
  TANGENTIAL — technically valid but low-priority for the current context.

## Verdict Rules
Apply in order; stop at first match:
  FAIL    — any QIR missing required fields (template violation),
            unjustified priority (TR-004 violation), or vague temporal
            window (TR-005 violation)
  PARTIAL — all QIRs complete but a distinct question from the feedback
            was not captured as a separate QIR (TR-001 violation), or
            scope misclassification detected (TR-003 violation)
  PASS    — all feedback captured, all fields present, all priorities
            justified, all temporal windows explicit

## Style
Rule-based and deterministic. Cite the specific rule ID (TR-001 through TR-006)
for each violation.

## Tone
Terse, machine-readable. The verdict JSON is consumed programmatically.
The summary field should be one factual sentence, not commentary.

## Audience
The Verification Agent, which will mechanically apply your corrections.

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
    """Build a Compliance_Judge instance with constrained JSON output."""
    return Agent(
        name="Compliance_Judge",
        description=(
            "Validates follow-on QIRs against QIR_TEMPLATE (9 required fields), "
            "transformation rules TR-001 through TR-006 (atomic decomposition, "
            "linked QIR, scope classification, priority justification, temporal "
            "window, non-actionable filtering). Returns a structured FeedbackVerdict "
            "JSON with PASS / PARTIAL / FAIL."
        ),
        model="gemini-2.5-flash",
        instruction=JUDGE_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
        output_key="feedback_verdict",
        output_schema=FeedbackVerdict,
        include_contents="none",
    )


# ---------------------------------------------------------------------------
# Agent 3: Verification_Agent
# ---------------------------------------------------------------------------

# NOTE: Plain string, NOT an f-string — by design.
# {feedback_qirs} and {feedback_verdict} are ADK state-key template placeholders,
# substituted at runtime by the ADK runner from session state.
VERIFICATION_INSTRUCTION = """\
## Context
You are a senior Intelligence Requirements Editor at ApexCode Solutions.
Follow-on QIRs have been generated from stakeholder feedback and independently
validated by a Compliance Judge. Your job: produce the corrected final set of QIRs.

## Inputs

Generated follow-on QIRs:
{feedback_qirs}

Compliance judge verdict (JSON):
{feedback_verdict}

The JSON verdict has this structure:
  confirmed_valid   — QIRs that conform to template and rules. Keep these.
  unverified        — QIRs that violate rules, with suggested corrections. Apply fixes.
  missing_critical  — questions from feedback not captured as QIRs. Add these.
  verdict           — PASS / PARTIAL / FAIL overall assessment.
  summary           — one-sentence description of the verdict.

## Objective
Produce a corrected set of follow-on QIRs following these rules exactly:

For each entry in confirmed_valid: preserve the QIR as-is.
For each entry in unverified: apply the suggested_alternative correction:
  - Fill missing required fields.
  - Correct scope misclassification (use the distinguishing criteria).
  - Split compound QIRs into atomic ones (each question → separate QIR).
  - Add priority justification grounded in operational impact.
  - Make temporal window explicit (concrete duration or monitoring mandate).
Add all entries in missing_critical as new QIRs with all required fields.

QIR ID sequencing: when adding new QIRs (from splits or missing_critical),
assign the next available FP-NNN ID in sequence.

## Style
Match the Transformation Agent's structured JSON format. Apply corrections
precisely — this is a rule-following edit task, not creative generation.

## Tone
Direct, operational — no hedging, no commentary on the corrections.
Apply them and produce the final QIR set.

## Audience
Stage 1 Requirement agent, which will refine each follow-on QIR into a full
intelligence requirement for the next intelligence cycle.

## Response Format
Return ONLY valid JSON — an array of corrected QIR objects matching the
QIR_TEMPLATE schema. No prose before or after.
"""


def make_verification_agent(before_agent_callback=None) -> Agent:
    """Build a Verification_Agent instance."""
    return Agent(
        name="Verification_Agent",
        description=(
            "Applies Compliance Judge corrections to produce the final verified "
            "set of follow-on QIRs: preserves confirmed-valid QIRs, fixes "
            "unverified QIRs per suggested_alternative, and adds all "
            "missing_critical questions as new QIRs."
        ),
        model="gemini-2.5-flash",
        instruction=VERIFICATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
        ),
        output_key="verified_feedback",
        before_agent_callback=before_agent_callback,
        include_contents="none",
    )


# ---------------------------------------------------------------------------
# Loop exit logic — deterministic, no LLM call
# ---------------------------------------------------------------------------


def _check_loop_exit_callback(callback_context) -> None:
    """Deterministic loop exit check — runs as before_agent_callback.

    Reads feedback_verdict from session state. If verdict is PASS,
    sets escalate=True to exit the LoopAgent. No LLM call needed.
    """
    state = callback_context.state
    verdict_raw = state.get("feedback_verdict", "")
    if not verdict_raw:
        return None  # First pass — no verdict yet.
    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        if verdict.get("verdict") == "PASS":
            callback_context.actions.escalate = True
    except (json.JSONDecodeError, AttributeError):
        pass  # Malformed verdict — continue iterating.
    return None


# ---------------------------------------------------------------------------
# Web-path guardrails — mirrors batch-path post-iteration checks
# ---------------------------------------------------------------------------


def _apply_web_path_guardrails(callback_context) -> None:
    """
    Apply deterministic guardrails to the web path — mirrors run_pipeline().

    Reads feedback_verdict from session state. If the verdict is non-empty
    (iteration 2+), runs check_verdict_rules(). Downgrades the verdict in
    state from PASS to FAIL if logical inconsistencies are detected.
    """
    state = callback_context.state
    verdict_raw = state.get("feedback_verdict", "")
    if not verdict_raw:
        return None  # First iteration — no verdict to check yet.

    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
    except (json.JSONDecodeError, TypeError):
        return None

    rule_issues = check_verdict_rules(verdict)
    if rule_issues:
        for issue in rule_issues:
            print(f"  [WEB RULE CHECK] {issue}")
        if verdict.get("verdict") == "PASS":
            verdict["verdict"] = "FAIL"
            verdict["summary"] = (
                f"Deterministic rule check failed: {len(rule_issues)} issue(s). "
                f"Verdict downgraded from PASS to FAIL."
            )
            state["feedback_verdict"] = json.dumps(verdict)

    return None


# ---------------------------------------------------------------------------
# Module-level pipeline + root_agent (for adk web)
#
# TWO EXECUTION TOPOLOGIES EXIST (by design):
#
#   Web path (adk web):
#     LoopAgent wraps SequentialAgent. Loop exit is driven by
#     _check_loop_exit_callback (before_agent_callback on Transformation_Agent).
#     Guardrails run in the same callback chain before the exit check.
#
#   Batch path (run_pipeline):
#     Python for-loop drives iteration manually. Includes retry logic and
#     per-iteration result capture for metrics/reporting.
#
# Both paths use the same agent factories, instructions, and state keys.
# ---------------------------------------------------------------------------

_root_agent = None
_session_service = None


def _get_root_agent() -> LoopAgent:
    """Lazily construct the web pipeline and root_agent on first access."""
    global _root_agent
    if _root_agent is None:
        def _combined_before_callback(callback_context):
            """Combines state init + guardrails + loop exit check.

            Order is deliberate:
            1. _init_session_state       — seed missing state keys.
            2. _apply_web_path_guardrails — validate previous verdict, downgrade
                                            if rule violations detected.
            3. _check_loop_exit_callback  — read (possibly downgraded) verdict,
                                            set escalate=True only on genuine PASS.
            """
            _init_session_state(callback_context)
            _apply_web_path_guardrails(callback_context)
            _check_loop_exit_callback(callback_context)

        _transformation = make_generator_agent(
            before_agent_callback=_combined_before_callback,
        )
        _judge = make_judge_agent()
        _verification = make_verification_agent(
            before_agent_callback=_validate_verdict_before_verification,
        )
        _web_pipeline = SequentialAgent(
            name="Feedback_Pipeline",
            sub_agents=[_transformation, _judge, _verification],
        )
        _root_agent = LoopAgent(
            name="Feedback_Loop",
            sub_agents=[_web_pipeline],
            max_iterations=3,
        )
    return _root_agent


def _get_session_service():
    """Lazily construct the session service on first access."""
    global _session_service
    if _session_service is None:
        try:
            _session_service = create_session_service(persistent=True)
        except Exception as exc:
            print(
                f"  [WARN] Persistent session service failed: {type(exc).__name__}: {exc}. "
                f"Falling back to InMemorySessionService — sessions will NOT persist "
                f"across restarts and cross-stage state transfer will fail."
            )
            _session_service = create_session_service(persistent=False)
    return _session_service


# Module-level name for adk web discovery.
def __getattr__(name: str):
    if name == "root_agent":
        return _get_root_agent()
    if name == "session_service":
        return _get_session_service()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Execution — run_pipeline()
# ---------------------------------------------------------------------------


async def run_pipeline(
    stakeholder_feedback: str,
    original_qir: str = "",
    max_iterations: int = 3,
    generator_temp: float = DEFAULT_TEMP,
    generator_model: str = DEFAULT_MODEL,
    progress_callback=None,
    session_service=None,
) -> tuple[str, list[dict]]:
    """
    Run the self-refining feedback pipeline against stakeholder feedback.

    Args:
        stakeholder_feedback: Raw stakeholder questions/concerns from Stage 6.
        original_qir:         The original QIR context this feedback traces to.
        max_iterations:       Maximum number of refinement passes (default 3).
        generator_temp:       Sampling temperature for the Transformation Agent.
        generator_model:      Model ID for the Transformation Agent.
        progress_callback:    Optional async callable(agent_name, iteration).
        session_service:      ADK session service to use. If None, the lazy
                              singleton from session_service.py is used (an
                              InMemorySessionService; sessions do not persist
                              across restarts). Pass your own service for
                              batch eval / grid search if needed.

    Returns:
        (session_id, iterations) where iterations is a list of per-pass dicts:
            {
              "iteration":              int,
              "feedback_qirs":          str,
              "verdict":                dict,
              "verified_feedback":      str,
              "n_unverified":           int,
              "convergence_regressed":  bool,
              "qir_validation_issues":  list[str],
            }
    """
    _transformation_agent = make_generator_agent(
        model=generator_model, temperature=generator_temp,
    )
    _judge_agent          = make_judge_agent()
    _verification_agent   = make_verification_agent()

    _pipeline = SequentialAgent(
        name="Feedback_Pipeline",
        sub_agents=[_transformation_agent, _judge_agent, _verification_agent],
    )

    _svc = session_service if session_service is not None else _get_session_service()
    _runner = Runner(
        agent=_pipeline,
        app_name=APP_NAME,
        session_service=_svc,
    )

    session_id = f"stage7_{uuid.uuid4().hex}"

    await _svc.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "original_qir":         original_qir,
            "stakeholder_feedback": stakeholder_feedback,
            "feedback_qirs":        "",
            "feedback_verdict":     "",
            "verified_feedback":    "",
        },
    )

    MAX_RETRIES = 3
    _ITER_TIMEOUT_S = 600
    iterations: list[dict] = []

    for iteration in range(1, max_iterations + 1):
        user_text = (
            stakeholder_feedback if iteration == 1
            else "Refine the follow-on QIRs based on the judge's feedback in session state."
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async def _consume() -> None:
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

                await asyncio.wait_for(_consume(), timeout=_ITER_TIMEOUT_S)
                break
            except (TypeError, KeyError, AttributeError, ValidationError) as exc:
                # Deterministic failures — retrying won't help.
                raise RuntimeError(
                    f"Pipeline iteration {iteration} hit a non-retryable error: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            except Exception as exc:
                if "api key" in str(exc).lower():
                    # Missing/invalid API key is fatal — retrying cannot fix it.
                    raise RuntimeError(
                        f"API key problem (fatal, not retried): {exc}\n"
                        "  Set GOOGLE_API_KEY in the .env file described in the "
                        "README's Setup section."
                    ) from exc
                # Transient failures (API errors, rate limits, network) — retry.
                if attempt == MAX_RETRIES:
                    raise RuntimeError(
                        f"Pipeline iteration {iteration} failed after "
                        f"{MAX_RETRIES} attempts: {exc}"
                    ) from exc
                wait = 2 ** attempt * 5 * (0.5 + random.random())
                print(
                    f"  [RETRY {attempt}/{MAX_RETRIES}] Iteration {iteration} "
                    f"failed: {type(exc).__name__}: {exc} — waiting {wait:.0f}s"
                )
                await asyncio.sleep(wait)

        # Read state after iteration.
        session = await _svc.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
        )

        # Parse and validate verdict.
        verdict_raw = session.state.get("feedback_verdict", {})
        try:
            verdict_dict = (
                verdict_raw if isinstance(verdict_raw, dict)
                else json.loads(verdict_raw)
            )
            validated = FeedbackVerdict.model_validate(verdict_dict)
            verdict = validated.model_dump()
        except (json.JSONDecodeError, TypeError):
            print("  [WARN] Judge returned invalid JSON — treating as FAIL")
            verdict = {
                "confirmed_valid": [],
                "unverified": [{
                    "source": "entire QIR set",
                    "reason": "Judge returned invalid JSON — full re-validation required.",
                    "suggested_alternative": "Re-generate QIRs with strict adherence "
                    "to QIR_TEMPLATE and all 9 required fields.",
                }],
                "missing_critical": [],
                "verdict": "FAIL",
                "summary": "Judge output was not valid JSON — Verification Agent "
                "should re-validate the full QIR set.",
            }
        except ValidationError as e:
            print(f"  [WARN] Judge verdict failed schema validation: {e}")
            verdict = {
                "confirmed_valid": [],
                "unverified": [{
                    "source": "entire QIR set",
                    "reason": f"Judge verdict failed Pydantic validation: "
                    f"{str(e)[:200]}. Full re-validation required.",
                    "suggested_alternative": "Re-generate QIRs ensuring all "
                    "required fields and valid enum values are present.",
                }],
                "missing_critical": [],
                "verdict": "FAIL",
                "summary": "Judge output failed Pydantic validation.",
            }

        # Deterministic rule check.
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
                await _svc.append_event(
                    session,
                    _AdkEvent(
                        author="rule_checker",
                        actions=_AdkEventActions(
                            state_delta={"feedback_verdict": json.dumps(verdict)}
                        ),
                    ),
                )

        # Deterministic QIR field validation on the verified output.
        # Strip any markdown code fence first — Verification_Agent occasionally
        # wraps its JSON output in ```json ... ``` despite prompt instructions.
        verified_raw = session.state.get("verified_feedback", "")
        verified_clean = _strip_code_fence(verified_raw) if isinstance(verified_raw, str) else verified_raw
        qir_validation_issues: list[str] = []
        try:
            qirs = json.loads(verified_clean) if isinstance(verified_clean, str) else verified_clean
            if isinstance(qirs, list):
                for i, qir in enumerate(qirs):
                    field_issues = validate_qir_fields(qir)
                    for fi in field_issues:
                        qir_validation_issues.append(f"QIR[{i}]: {fi}")
        except (json.JSONDecodeError, TypeError):
            qir_validation_issues.append("verified_feedback is not valid JSON")

        if qir_validation_issues:
            for pvi in qir_validation_issues[:5]:
                print(f"  [QIR VALIDATION] {pvi}")

        # Convergence tracking.
        feedback_qirs_text = session.state.get("feedback_qirs", "")
        curr_n_unverified = len(verdict.get("unverified", []))
        convergence_regressed = False
        if iterations:
            prev_n_unverified = len(iterations[-1]["verdict"].get("unverified", []))
            if curr_n_unverified > prev_n_unverified:
                convergence_regressed = True
                print(
                    f"  [CONVERGENCE WARN] Unverified count increased: "
                    f"{prev_n_unverified} → {curr_n_unverified} "
                    f"(loop not contracting on iteration {iteration})."
                )

        # Also strip any code fence on feedback_qirs (Transformation_Agent
        # output, same drift risk as Verification_Agent).
        feedback_qirs_clean = (
            _strip_code_fence(feedback_qirs_text)
            if isinstance(feedback_qirs_text, str)
            else feedback_qirs_text
        )

        iterations.append(
            {
                "iteration":              iteration,
                "feedback_qirs":          feedback_qirs_clean,
                "verdict":                verdict,
                "verified_feedback":      verified_clean,
                "n_unverified":           curr_n_unverified,
                "convergence_regressed":  convergence_regressed,
                "qir_validation_issues":  qir_validation_issues,
            }
        )

        verdict_label = verdict.get("verdict", "UNKNOWN")
        print(
            f"  Iteration {iteration}/{max_iterations}: {verdict_label} — "
            f"{verdict.get('summary', '')}"
        )

        if verdict_label == "PASS":
            break

    return session_id, iterations


# ---------------------------------------------------------------------------
# Sample input — for standalone testing
# ---------------------------------------------------------------------------

SAMPLE_ORIGINAL_QIR = (
    "QIR-2025-0042: Determine attribution, scope, and business impact of the "
    "AiTM session hijacking incident targeting ApexCode Solutions via partner "
    "developer DevPartner, Inc, including assessment of data exfiltration from "
    "12 private GitHub repositories."
)

SAMPLE_STAKEHOLDER_FEEDBACK = (
    "CISO feedback after Stage 6 briefing:\n\n"
    "1. Could 50 other vendors be compromised the same way? We need to know "
    "our exposure across the entire partner ecosystem, not just DevPartner, Inc.\n\n"
    "2. Can we prevent session hijacking entirely with FIDO2? I want to know "
    "if deploying FIDO2/WebAuthn keys would have stopped this attack and "
    "whether it's worth the investment.\n\n"
    "3. How long did the attacker have access before we detected it? The "
    "briefing mentioned the initial compromise but I need the full dwell time."
)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    print("=" * 70)
    print("FEEDBACK PIPELINE — Stage 7: Intel Cycle")
    print("ApexCode Solutions | Threat Intelligence")
    print("=" * 70)
    print()

    _, iterations = await run_pipeline(
        stakeholder_feedback=SAMPLE_STAKEHOLDER_FEEDBACK,
        original_qir=SAMPLE_ORIGINAL_QIR,
        max_iterations=3,
    )

    for it in iterations:
        n = it["iteration"]
        verdict = it["verdict"]
        n_valid      = len(verdict.get("confirmed_valid", []))
        n_unverified = len(verdict.get("unverified", []))
        n_missing    = len(verdict.get("missing_critical", []))

        print()
        print("=" * 70)
        print(f"ITERATION {n} — Generated QIRs")
        print("=" * 70)
        print(it["feedback_qirs"][:3000])

        print()
        print("=" * 70)
        print(
            f"ITERATION {n} — Judge Verdict: {verdict.get('verdict')}  "
            f"(valid={n_valid}  unverified={n_unverified}  missing={n_missing})"
        )
        print("=" * 70)
        print(json.dumps(verdict, indent=2)[:2000])

    print()
    print("=" * 70)
    final_verdict = iterations[-1]["verdict"].get("verdict", "UNKNOWN")
    print(f"FINAL RESULT after {len(iterations)} iteration(s): {final_verdict}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
