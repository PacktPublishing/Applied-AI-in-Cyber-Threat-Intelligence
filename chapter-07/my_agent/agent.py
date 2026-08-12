"""
Chapter 7 — The Collection Stage
A self-refining collection-plan pipeline:

    Collection → Judge → Verification

wrapped in a LoopAgent (max 3 iterations). An after_agent_callback on the
Verification Agent sets actions.escalate = True to exit the loop when the judge
returns verdict == "PASS", so loop exit is deterministic and costs no model call.

Run interactively:
    adk web                # from the chapter-07 root
Run as a script:
    cd my_agent && python agent.py
"""

import asyncio
import json
import uuid
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel

from google.adk import Agent, Runner
from google.adk.agents import LoopAgent, SequentialAgent
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Support both `python agent.py` and `adk web` (which imports as a package).
try:
    from .sources import format_catalog_for_prompt
except ImportError:
    from sources import format_catalog_for_prompt

load_dotenv()


# ---------------------------------------------------------------------------
# 1. Pydantic verdict schema
# Validates the judge's JSON output before it reaches the verification agent.
# A malformed verdict surfaces as a clear ValidationError instead of corrupting
# downstream state.
# ---------------------------------------------------------------------------

class ConfirmedSource(BaseModel):
    source: str
    rationale: str
    relevance: Literal["ESSENTIAL", "USEFUL", "TANGENTIAL"]


class UnverifiedSource(BaseModel):
    source: str
    reason: str
    suggested_alternative: str


class MissingCriticalSource(BaseModel):
    source: str
    importance: str


class JudgeVerdict(BaseModel):
    confirmed_valid: list[ConfirmedSource]
    unverified: list[UnverifiedSource]
    missing_critical: list[MissingCriticalSource]
    verdict: Literal["PASS", "PARTIAL", "FAIL"]
    summary: str


# ---------------------------------------------------------------------------
# 2. Instructions
# Each instruction is a multi-line string with {placeholder} substitutions
# that ADK fills from session.state at runtime. The catalog is injected once,
# at import time, via format_catalog_for_prompt().
# ---------------------------------------------------------------------------

COLLECTION_INSTRUCTION = f"""\
## Context
You are a Threat Intelligence Collection Planner at ApexCode Solutions.

### Active Threat Scenario
{{threat_context}}

If the threat scenario above is empty, derive it from the analyst's QIR: extract
the threat actor, attack mechanism (how the adversary gains or maintains access),
target environment (which platforms and systems are in scope), and key evasion
technique (what makes this hard to detect with standard controls). Use this as
your threat context for all source selection and priority signal decisions.

## Approved Source Catalog
You may ONLY recommend sources from this catalog. Any source not listed here will
be rejected as UNVERIFIED by the validation judge, which reduces your score. Select
from what is available below; do not invent sources outside this list.

{format_catalog_for_prompt()}

## Refinement Feedback from Previous Iteration
The sections below are populated after the first pass. Check them before writing.

If {{verified_plan}} is EMPTY → this is the first pass. Generate the initial plan
fresh, selecting the most relevant sources from the catalog above.

If {{verified_plan}} is NON-EMPTY → this is a refinement pass. Follow these rules
exactly; do not deviate:

  Rule 1 — Preserve: Copy the entire {{verified_plan}} as your starting draft. Do not
            remove, rewrite, rename, or restructure any source already present.
            Every confirmed source must appear in your output verbatim.

  Rule 2 — Add missing only: Parse {{validation_verdict}} and extract the
            "missing_critical" array. For each entry in that array, add the source
            to the appropriate section with the same level of operational detail
            (specific event types, field names, anomaly patterns) as the other sources.

  Rule 3 — Replace unverified: For each entry in the "unverified" array, replace
            the named source with the "suggested_alternative" from that entry.
            The suggested_alternative is guaranteed to be in the catalog above.

  Rule 4 — No new sources: Do not add any source beyond what Rule 2 and Rule 3
            require. Do not add catalog sources not in "missing_critical". Do not
            add sources outside the catalog. Any addition not mandated by the
            verdict will cause a score decrease.

### Previously Verified Plan
{{verified_plan}}

### Judge Validation Verdict (JSON)
{{validation_verdict}}

## Objective
Produce (or refine) a concrete, actionable collection plan from the analyst's QIR.
The plan must name exact event types, API endpoints, and field names — not generic
log categories. Every bullet must carry operational signal a SOC engineer can act on.

## Style
Write like a senior TI analyst producing an internal deliverable. Be specific.
Avoid filler.

## Tone
Direct and operational. State what to monitor and why — no hedging, no
qualifications without evidence. Every recommendation must be actionable.

## Audience
The TI team and the SOC leads who will configure detections.

## Response Format
Structure the output in three labeled sections:

### 1. Internal Log Sources
For each source: name it, list the specific event types or fields to ingest,
and describe the anomaly pattern that indicates compromise.

### 2. External / OSINT Sources
For each source: name the tool or API, describe what to monitor, and explain
what a hit means operationally.

### 3. Threat Actor Tactics
Explain the techniques being used, how each works mechanically, why it defeats
standard controls, and the MITRE ATT&CK ID where applicable.

Close with a **Priority Signal** callout — the single indicator with the
highest fidelity and lowest false positive rate for detecting an active compromise.
"""

JUDGE_INSTRUCTION = f"""\
## Context
You are a Source Validation Judge reviewing a collection plan. Your only job:
verify every recommended source against the approved catalog below.

## Approved Source Catalog

{format_catalog_for_prompt()}

## Input

Collection plan to validate:
{{collection_plan}}

Previous iteration's verdict (empty on first pass):
{{validation_verdict}}

## Objective

Step 1 — Validate every source in the plan:
  - If it appears in the catalog by name or clear equivalent → confirmed_valid,
    with a one-line rationale and a relevance rating:
      ESSENTIAL — directly detects the primary attack vector
      USEFUL    — supporting or corroborating signal
      TANGENTIAL — in the catalog but low-priority for this threat
  - If not → unverified, with the reason and the closest catalog alternative.

Step 2 — Identify missing_critical sources:
  If {{validation_verdict}} is EMPTY (first pass): flag up to 3 catalog sources
  that are HIGH-PRIORITY for this attack vector and absent from the plan.
  If NON-EMPTY (refinement pass): only carry forward entries from the previous
  missing_critical that are still absent. Do not introduce new entries unless a
  critical gap remains.

## Verdict Rules (apply in order; stop at first match)
  FAIL    — unverified is non-empty.
  PARTIAL — unverified is empty AND missing_critical is non-empty.
  PASS    — both are empty.

## Style
Catalog-based and deterministic. Check by exact name or clear equivalent.

## Tone
Terse and machine-readable. The summary is one factual sentence.

## Audience
The Verification Agent, which will mechanically apply your corrections, and a
Pydantic schema validator.

## Output Format
Return ONLY a valid JSON object. No prose before or after.

Top-level keys:
  "confirmed_valid"  — array of objects with string fields source, rationale,
                       and relevance (relevance is exactly one of: ESSENTIAL,
                       USEFUL, TANGENTIAL).
  "unverified"       — array of objects with string fields source, reason, and
                       suggested_alternative.
  "missing_critical" — array of objects with string fields source and
                       importance. Maximum 3 entries.
  "verdict"          — string, exactly one of: PASS, PARTIAL, FAIL.
  "summary"          — one sentence describing the overall verdict.
"""

VERIFICATION_INSTRUCTION = """\
## Context
You are a senior Threat Intelligence analyst at ApexCode Solutions. A collection
plan has been drafted and independently validated. Your job: produce the corrected,
final plan.

## Inputs

Original collection plan:
{collection_plan}

Source validation verdict (JSON):
{validation_verdict}

## Objective
Apply the verdict mechanically:
  - Keep every source in confirmed_valid with its full operational detail.
  - Remove every source in unverified; replace with its suggested_alternative,
    keeping the same level of detail.
  - Add every source in missing_critical with the same level of detail as
    the others (specific event types, field names, anomaly patterns).
  - The only sources permitted in your output are the three sets above.
  - Preserve the three-section structure and the Priority Signal callout.
  - If the Priority Signal referenced an unverified source, update it.

## Style
Match the Collection Agent's analytical register. This is a rule-following edit
task, not creative generation.

## Tone
Direct and operational. Apply the corrections; do not commentate on them.

## Audience
The TI team and SOC leads. The plan must be ready for direct handoff.

## Response Format
The corrected plan with three sections (Internal Log Sources, External / OSINT
Sources, Threat Actor Tactics) and a closing **Priority Signal** callout. No
preamble. Start with the first section header.
"""


# ---------------------------------------------------------------------------
# 3. Constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "gemini-2.5-flash"
DEFAULT_TEMP  = 0.0
JUDGE_MODEL   = "gemini-3.1-pro-preview"


# ---------------------------------------------------------------------------
# 4. Callbacks
# ---------------------------------------------------------------------------

def _init_session_state(callback_context) -> None:
    """Seed required state keys on the first agent turn (adk web compatibility).

    When running via `adk web` the main() entrypoint is never called, so the
    three state keys that COLLECTION_INSTRUCTION references are absent and ADK
    raises "Context variable not found". This callback seeds them if missing.
    """
    for key, default in (
        ("threat_context",     ""),
        ("verified_plan",      ""),
        ("validation_verdict", ""),
    ):
        if key not in callback_context.state:
            callback_context.state[key] = default


def _validate_verdict_before_verification(callback_context) -> types.Content | None:
    """Skip verification if the judge verdict is absent or not valid JSON.

    Returns a placeholder Content so the verified_plan state key is written
    without the Verification Agent running, keeping downstream state consistent.
    """
    raw = callback_context.state.get("validation_verdict", "")
    if not raw:
        return types.Content(
            role="model",
            parts=[types.Part(text="(verification skipped — no verdict available)")],
        )
    try:
        json.loads(raw)
    except json.JSONDecodeError:
        return types.Content(
            role="model",
            parts=[types.Part(text="(verification skipped — verdict was not valid JSON)")],
        )
    return None  # verdict is valid; proceed normally


# ---------------------------------------------------------------------------
# 5. Loop-exit callback (no LLM call)
# An after_agent_callback on the Verification Agent reads the verdict from
# session.state and, on PASS, sets actions.escalate = True to tell the enclosing
# LoopAgent to stop. ADK does not require a separate agent to exit a loop, so
# this is deterministic and makes zero model calls. (Later chapters reuse this
# callback pattern.)
# ---------------------------------------------------------------------------

def _escalate_on_pass(callback_context) -> None:
    """After verification, escalate (exit the LoopAgent) if the verdict is PASS."""
    verdict_raw = callback_context.state.get("validation_verdict", "{}")
    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        if verdict.get("verdict") == "PASS":
            callback_context.actions.escalate = True
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return None


# ---------------------------------------------------------------------------
# 6. Named agent factories
# Each factory returns a fresh Agent instance. ADK sets a parent reference on
# every sub-agent when it is added to a SequentialAgent or LoopAgent; reusing
# a single instance across multiple parent constructions raises
# "Agent already has a parent". Factories prevent that by ensuring every
# pipeline gets its own leaf-agent objects.
# ---------------------------------------------------------------------------

def make_collection_agent(
    model: str = DEFAULT_MODEL,
    temperature: float = DEFAULT_TEMP,
    before_agent_callback=None,
    after_agent_callback=None,
) -> Agent:
    """Build a Collection_Recommendation_Agent instance.

    The before/after callbacks let the grid search time this agent's generation in
    isolation: the grid tunes the Collection agent's parameters, so the latency it
    records is this agent's single generation, not the whole pipeline.
    """
    return Agent(
        name="Collection_Recommendation_Agent",
        model=model,
        instruction=COLLECTION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=temperature,
            top_p=0.9,
            top_k=20,
            frequency_penalty=0.0,
            presence_penalty=0.0,
        ),
        output_key="collection_plan",
        before_agent_callback=before_agent_callback,
        after_agent_callback=after_agent_callback,
    )


def make_judge_agent() -> Agent:
    """Build a Source_Validation_Judge instance.

    Uses JUDGE_MODEL (gemini-3.1-pro-preview) at temperature 0.0. A stronger
    model is used here because precision on catalog membership verification
    matters more than cost. A false negative on hallucination detection silently
    corrupts the entire pipeline.
    """
    return Agent(
        name="Source_Validation_Judge",
        model=JUDGE_MODEL,
        instruction=JUDGE_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
        output_key="validation_verdict",
    )


def make_verification_agent(before_agent_callback=None) -> Agent:
    """Build a Verification_Agent instance.

    Its after_agent_callback (_escalate_on_pass) exits the loop on a PASS verdict
    with no model call, replacing the separate Loop_Controller agent used in
    earlier drafts. Verification is the last stage in the sequence, so escalating
    here ends the iteration cleanly.
    """
    return Agent(
        name="Verification_Agent",
        model=DEFAULT_MODEL,
        instruction=VERIFICATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            top_p=0.95,
            top_k=40,
        ),
        output_key="verified_plan",
        before_agent_callback=before_agent_callback,
        after_agent_callback=_escalate_on_pass,
    )


# ---------------------------------------------------------------------------
# 7. Web pipeline (adk web)
# _get_root_agent() lazily constructs the pipeline on first access so that
# module import does not trigger agent construction before load_dotenv() runs.
# root_agent is the name ADK's web server discovers at module level.
# ---------------------------------------------------------------------------

_root_agent = None


def _get_root_agent() -> LoopAgent:
    """Lazily construct the web pipeline and root_agent on first access."""
    global _root_agent
    if _root_agent is None:
        _collection = make_collection_agent(
            before_agent_callback=_init_session_state,
        )
        _judge = make_judge_agent()
        _verification = make_verification_agent(
            before_agent_callback=_validate_verdict_before_verification,
        )
        _web_pipeline = SequentialAgent(
            name="Collection_Pipeline",
            sub_agents=[_collection, _judge, _verification],
        )
        _root_agent = LoopAgent(
            name="Collection_Loop",
            sub_agents=[_web_pipeline],
            max_iterations=3,
        )
    return _root_agent


root_agent = _get_root_agent()


# ---------------------------------------------------------------------------
# 8. Pipeline factory (notebook / evaluation use)
# Returns a fully wired LoopAgent with fresh agent instances each call.
# Called by the simulation notebook and judge_eval.py — never reuses the
# module-level root_agent, avoiding the "Agent already has a parent" guard.
# ---------------------------------------------------------------------------

def build_pipeline(
    collection_temp: float = DEFAULT_TEMP,
    collection_model: str = DEFAULT_MODEL,
    max_iterations: int = 3,
    collection_before_callback=None,
    collection_after_callback=None,
) -> LoopAgent:
    """Return a fully wired LoopAgent ready for a single pipeline run.

    `collection_model` / `collection_temp` set the Collection (generator) agent's
    model and temperature, which is what the config grid search sweeps. The judge
    and verification agents keep their own fixed models, so the grid measures the
    generator against a constant evaluator. `collection_before_callback` /
    `collection_after_callback` are passed to the Collection agent so the grid can
    time its generation in isolation.
    """
    _pipeline = SequentialAgent(
        name="Collection_Pipeline",
        sub_agents=[
            make_collection_agent(model=collection_model, temperature=collection_temp,
                                  before_agent_callback=collection_before_callback,
                                  after_agent_callback=collection_after_callback),
            make_judge_agent(),
            make_verification_agent(
                before_agent_callback=_validate_verdict_before_verification,
            ),
        ],
    )
    return LoopAgent(
        name="Collection_Loop",
        sub_agents=[_pipeline],
        max_iterations=max_iterations,
    )


# ---------------------------------------------------------------------------
# 9. Script entrypoint
# Seeds the three required state keys (threat_context, verified_plan,
# validation_verdict) so the first-iteration template substitutions resolve
# without KeyError, then runs the LoopAgent end-to-end and prints the final
# verified plan.
# ---------------------------------------------------------------------------

APP_NAME = "intel_cycle_collection"
USER_ID  = "ti_analyst"


async def main() -> None:
    qir = (
        "QIR-001 (Refined): Detect indicators of third-party partner account "
        "compromise targeting ApexCode's GitHub, Jira, and Okta environments. "
        "Threat actors are using session hijacking via proxy phishing tools "
        "(Evilginx2) to steal partner employee session cookies and bypass MFA."
    )

    threat_context = (
        "Third-party software development partners have privileged access to "
        "ApexCode's SaaS platforms (GitHub, Jira, Okta). Threat actors are "
        "compromising partner employees via proxy phishing (Evilginx2) to steal "
        "live session cookies, executing an Adversary-in-the-Middle attack "
        "(MITRE ATT&CK T1557). Once they hold the cookie, they authenticate to "
        "ApexCode systems as the partner — no password, no MFA prompt. The "
        "detection signal is the reuse itself: the same authenticated session "
        "(externalSessionId / session token) appearing from a new IP, ASN, "
        "device, or user-agent than the one that established it."
    )

    session_service = InMemorySessionService()
    session_id = f"chap7_{uuid.uuid4().hex}"
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "threat_context":     threat_context,
            "verified_plan":      "",
            "validation_verdict": "",
        },
    )

    runner = Runner(agent=root_agent, app_name=APP_NAME, session_service=session_service)

    print("=" * 70)
    print("COLLECTION PIPELINE — Chapter 7")
    print("=" * 70)
    print(f"\nQIR:\n  {qir}\n")

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=session_id,
        new_message=types.Content(role="user", parts=[types.Part(text=qir)]),
    ):
        if event.author and event.is_final_response():
            print(f"--- {event.author} completed ---")

    session = await session_service.get_session(
        app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
    )

    verdict_raw = session.state.get("validation_verdict", "{}")
    verdict = json.loads(verdict_raw) if verdict_raw else {}

    print("\n" + "=" * 70)
    print(f"FINAL VERDICT: {verdict.get('verdict', 'UNKNOWN')}")
    print(f"  {verdict.get('summary', '')}")
    print("=" * 70)
    print("\nFINAL VERIFIED PLAN")
    print("-" * 70)
    print(session.state.get("verified_plan", "(no plan produced)"))


if __name__ == "__main__":
    asyncio.run(main())
