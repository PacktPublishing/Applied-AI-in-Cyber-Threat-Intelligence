"""
Stage 6: Dissemination Pipeline
Intel Cycle AI — ApexCode Solutions

Fan-out architecture with self-refinement loop:
  1. Routing_Agent          — identifies affected stakeholders from verified product,
                              produces a routing manifest (JSON).
  2. Brief generation       — Python for-loop calls a single-brief agent per
                              stakeholder in the manifest. Assembles results into
                              the dissemination plan.
  3. Classification check   — deterministic Python function validates classification
                              compliance, channel validity, and mandatory routing.
  4. Routing_Judge          — validates content quality, action appropriateness,
                              IOC handling, and routing completeness.
  5. Verification_Agent     — corrects routing errors, adds missing stakeholders,
                              fixes classification violations.

IMPORTANT — Dissemination, not production:
  This pipeline operates on VERIFIED PRODUCT (Stage 5 output). The Routing Agent
  determines who should receive the intel, the Brief Generator tailors content
  per recipient, and the judge validates routing correctness and compliance.

State handoff:
  routing_agent           → output_key="routing_manifest"       → session.state
  brief_generation        → "dissemination_plan"                → session.state
  routing_judge           → output_key="dissemination_verdict"  → session.state (JSON)
  verification_agent      → output_key="verified_dissemination" → session.state

Loop exits when verdict == "PASS" or max_iterations is reached.

Run (batch):
    python my_agent/agent.py

Run (interactive):
    adk web          # from the chapter-11/ project root
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
    from .stakeholder_directory import (
        format_directory_for_prompt, STAKEHOLDERS, ROUTING_RULES,
        NOTIFICATION_ORDER, CLASSIFICATION_MAP, CLASSIFICATION_HIERARCHY,
        CONFIDENCE_ROUTING, check_classification_compliance, check_over_routing,
    )
except ImportError:
    from stakeholder_directory import (
        format_directory_for_prompt, STAKEHOLDERS, ROUTING_RULES,
        NOTIFICATION_ORDER, CLASSIFICATION_MAP, CLASSIFICATION_HIERARCHY,
        CONFIDENCE_ROUTING, check_classification_compliance, check_over_routing,
    )

# Session service lives at project root — shared across all stages.
from google.adk.sessions import InMemorySessionService


# ---------------------------------------------------------------------------
# Output Shield — Pydantic schema for dissemination judge verdicts
# ---------------------------------------------------------------------------


class ConfirmedRouting(BaseModel):
    source: str
    rationale: str
    relevance: Literal["ESSENTIAL", "USEFUL", "TANGENTIAL"]


class UnverifiedRouting(BaseModel):
    source: str
    reason: str
    suggested_alternative: str


class MissingRouting(BaseModel):
    source: str
    importance: str


class DisseminationVerdict(BaseModel):
    confirmed_valid: list[ConfirmedRouting]
    unverified: list[UnverifiedRouting]
    missing_critical: list[MissingRouting]
    verdict: Literal["PASS", "PARTIAL", "FAIL"]
    summary: str


# ---------------------------------------------------------------------------
# Deterministic rule checker — validates the structured verdict against
# routing rules programmatically. Catches structural errors the LLM judge
# may miss (e.g., PASS with non-empty unverified, classification violations).
# ---------------------------------------------------------------------------

_VALID_ROLE_IDS = set(STAKEHOLDERS.keys())
_NON_TECHNICAL_ROLES = {
    "general_counsel", "head_of_product", "corporate_comms",
    "privacy_dpo", "hr_operations",
}


def check_verdict_rules(verdict: dict, dissemination_plan: str = "") -> list[str]:
    """
    Programmatically check a structured verdict against routing rules.

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

DEFAULT_MODEL = _best_cfg.get("model", "gemini-2.5-flash")
DEFAULT_TEMP  = float(_best_cfg.get("temperature", 0.0))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "intel_cycle"
USER_ID  = "ti_analyst"

# ---------------------------------------------------------------------------
# Agent 1: Routing_Agent — produces routing manifest
# ---------------------------------------------------------------------------

ROUTING_INSTRUCTION = f"""\
## Context
You are a senior Intelligence Dissemination Officer at ApexCode Solutions.
You are performing Stage 6 of the intelligence cycle: Dissemination.

### Verified Intelligence Product (from Stage 5)
{{verified_product}}

If the verified product above is empty, inform the user that Stage 5 Production
must be completed before Dissemination can begin.

NOTE: You are determining which stakeholders should receive this intelligence
product, what classification each brief should carry, and what actions each
recipient should take. This is a routing and access control decision.

## Stakeholder Directory and Routing Rules
You may ONLY route to stakeholders in the directory below. Any routing to
stakeholders not in this directory will be rejected by the Routing Judge.

{format_directory_for_prompt()}

## Refinement Feedback from Previous Iteration
If {{verified_dissemination}} is EMPTY → this is the first pass. Generate the
initial routing manifest from scratch.

If {{verified_dissemination}} is NON-EMPTY → this is a refinement pass:
  Rule 1 — Preserve: Keep all correctly routed stakeholders from {{verified_dissemination}}.
  Rule 2 — Fix violations: Parse {{dissemination_verdict}} and correct every
           entry in "unverified" (fix classification, correct actions, update channels).
  Rule 3 — Add missing: Add every entry in "missing_critical" (missing stakeholders
           who should receive the product based on scope overlap and routing rules).
  Rule 4 — No changes beyond what Rules 2 and 3 require.

### Previously Verified Dissemination
{{verified_dissemination}}

### Routing Judge Verdict (JSON)
{{dissemination_verdict}}

## Objective
Produce a JSON routing manifest with these fields:

```json
{{
  "product_classification": "<RESTRICTED|CONFIDENTIAL|INTERNAL>",
  "product_confidence": "<HIGH|MEDIUM|LOW>",
  "routed_stakeholders": [
    {{
      "stakeholder_id": "<role_id from directory>",
      "classification": "<tier at or below recipient clearance>",
      "actions": ["<action from allowed_actions list>"],
      "delivery_channel": "<channel from recipient's allowed channels>",
      "rationale": "<why this stakeholder receives this product>",
      "ioc_included": true|false,
      "brief_summary": "<2-3 sentence summary tailored to this recipient's scope>"
    }}
  ],
  "excluded_stakeholders": [
    {{
      "stakeholder_id": "<role_id>",
      "reason": "<why this stakeholder was excluded>"
    }}
  ],
  "notification_sequence": ["<role_id in notification order>"]
}}
```

## Rules for Routing
1. Route based on scope overlap with the intel product's affected systems.
2. Apply confidence-gated routing: LOW = SOC + Hunt only; MEDIUM = add technical
   + triggered mandatory; HIGH = full cascade.
3. Never route technical IOCs to non-technical stakeholders.
4. Brief classification must not exceed recipient's clearance level.
5. SOC Manager always receives operational intelligence.
6. General Counsel must be routed if legal/contractual implications exist.
7. Corporate Comms only routed if public disclosure is possible.
8. Privacy/DPO must be routed if PII is exposed.
9. HR must be routed if insider threat is indicated.
10. Follow the static notification order.

## Style
Structured JSON. Every routing decision is justified with rationale.

## Tone
Analytical, compliance-focused. Classification decisions are precise.

## Response Format
Return ONLY valid JSON matching the schema above. No prose before or after.
"""

# ---------------------------------------------------------------------------
# Session state initializer
# ---------------------------------------------------------------------------


def _init_session_state(callback_context) -> None:
    """Seed required state keys if missing (first pass in an adk web session)."""
    state = callback_context.state
    if "verified_product" not in state:
        state["verified_product"] = state.get("verified_product", "")
    if "routing_manifest" not in state:
        state["routing_manifest"] = ""
    if "dissemination_plan" not in state:
        state["dissemination_plan"] = ""
    if "dissemination_verdict" not in state:
        state["dissemination_verdict"] = ""
    if "verified_dissemination" not in state:
        state["verified_dissemination"] = ""
    if "threat_context" not in state:
        state["threat_context"] = ""
    return None


def _validate_verdict_before_verification(callback_context) -> None:
    """
    Pydantic output shield for the adk web path.
    Validates the judge verdict in session state before the Verification Agent
    reads it via template substitution.
    """
    state = callback_context.state
    verdict_raw = state.get("dissemination_verdict", "{}")
    try:
        verdict_dict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        DisseminationVerdict.model_validate(verdict_dict)
    except (json.JSONDecodeError, Exception):
        state["dissemination_verdict"] = json.dumps({
            "confirmed_valid": [], "unverified": [], "missing_critical": [],
            "verdict": "FAIL", "summary": "Judge verdict failed schema validation (web path).",
        })
    return None


# ---------------------------------------------------------------------------
# Agent factories
# ---------------------------------------------------------------------------


def make_routing_agent(
    model: str = DEFAULT_MODEL,
    temperature: float = 0.0,
    before_agent_callback=None,
) -> Agent:
    """Build a Routing_Agent instance with constrained JSON output."""
    return Agent(
        name="Routing_Agent",
        model=model,
        instruction=ROUTING_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=temperature,
            response_mime_type="application/json",
        ),
        output_key="routing_manifest",
        before_agent_callback=before_agent_callback,
    )


# ---------------------------------------------------------------------------
# Agent 2: Routing_Judge
# ---------------------------------------------------------------------------

JUDGE_INSTRUCTION = f"""\
## Context
You are a Routing Judge reviewing a dissemination plan for a threat intelligence
product. Your job: verify that every routing decision follows the stakeholder
directory, routing rules, classification hierarchy, and IOC handling policy.

## Stakeholder Directory and Routing Rules

{format_directory_for_prompt()}

## Input

Dissemination plan to validate:
{{dissemination_plan}}

Previous iteration's verdict (empty on first pass):
{{dissemination_verdict}}

## Objective

Step 1 — Validate routing correctness:
  For each routed stakeholder:
  a. Verify stakeholder_id exists in the directory.
  b. Verify each action is in the stakeholder's allowed_actions list.
  c. Verify classification does not exceed recipient's clearance (RR-004).
  d. Verify delivery_channel is in the stakeholder's allowed channels.
  e. Verify technical IOCs are not routed to non-technical stakeholders (RR-005).
  f. Verify scope overlap justification is reasonable.

Step 2 — Validate routing completeness:
  a. SOC Manager included for operational intel (RR-001).
  b. General Counsel included if legal/contractual implications (RR-002).
  c. Corporate Comms NOT included unless public disclosure risk (RR-003).
  d. Privacy/DPO included if PII exposure (RR-006).
  e. HR included if insider threat (RR-007).
  f. Confidence-gated routing thresholds respected (RR-008).

Step 3 — Rate relevance of each confirmed routing:
  ESSENTIAL — stakeholder must receive this product; omission creates
              operational or compliance risk.
  USEFUL    — stakeholder benefits from receiving; strengthens response
              but not critical.
  TANGENTIAL — routing is valid but low-priority for this scenario.

  If rules are followed: record in confirmed_valid with relevance rating.
  If violated: record in unverified with the specific rule violated and correction.

Step 4 — Identify missing stakeholders:
  If {{dissemination_verdict}} is EMPTY (first pass):
    Identify up to 3 stakeholders who should have been routed based on
    scope overlap and routing rules.

  If {{dissemination_verdict}} is NON-EMPTY (refinement pass):
    Only carry forward entries from previous missing_critical that are still
    absent. Do not introduce new missing_critical unless all prior ones are
    resolved (monotonic shrinkage rule).

## Verdict Rules
Apply in order; stop at first match:
  FAIL    — classification violation (RR-004), technical IOCs to non-technical
            recipient (RR-005), over-routing (RR-003), or wrong action types for the stakeholder
  PARTIAL — all routing valid but mandatory stakeholders omitted (RR-001,
            RR-002, RR-006, RR-007)
  PASS    — complete, appropriate routing with correct classification handling

## Style
Rule-based and deterministic. Cite the specific rule ID (RR-001 through RR-008)
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
    """Build a Routing_Judge instance with constrained JSON output."""
    return Agent(
        name="Routing_Judge",
        model="gemini-2.5-flash",
        instruction=JUDGE_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
        output_key="dissemination_verdict",
        output_schema=DisseminationVerdict,
    )


# ---------------------------------------------------------------------------
# Agent 3: Verification_Agent
# ---------------------------------------------------------------------------

VERIFICATION_INSTRUCTION = """\
## Context
You are a senior Intelligence Dissemination Editor at ApexCode Solutions.
A dissemination plan has been drafted and independently validated by a
Routing Judge. Your job: produce the corrected final dissemination plan.

## Inputs

Original dissemination plan:
{dissemination_plan}

Routing judge verdict (JSON):
{dissemination_verdict}

The JSON verdict has this structure:
  confirmed_valid   — routing decisions that follow the rules. Keep these.
  unverified        — routing decisions that violate rules, with suggested corrections. Apply fixes.
  missing_critical  — stakeholders who should be routed but were omitted. Add these.
  verdict           — PASS / PARTIAL / FAIL overall assessment.
  summary           — one-sentence description of the verdict.

## Objective
Produce a corrected dissemination plan following these rules exactly:

Priority ordering for classification conflicts:
  1. NEVER violate classification — a brief's tier must not exceed the recipient's clearance.
  2. If a stakeholder cannot receive the brief at their clearance level, create a
     REDACTED version that omits classified details, or exclude them with documented rationale.
  3. Flag any unresolvable classification conflicts in the rationale.

For each entry in unverified: apply the suggested_alternative correction
  (fix classification, correct action types, update channels, remove IOCs
  from non-technical briefs).
Add all entries in missing_critical with appropriate routing details.
Preserve all entries in confirmed_valid.

## Style
Match the Routing Agent's structured JSON format. Apply corrections precisely —
this is a rule-following edit task, not creative generation.

## Tone
Direct, operational — no hedging, no commentary on the corrections.
Apply them and produce the final plan.

## Audience
The stakeholders who will receive routed intel briefs, and the Stage 7
Feedback pipeline which will process stakeholder responses.

## Response Format
The corrected dissemination plan as structured JSON matching the routing
manifest schema.
"""


def _escalate_on_pass(callback_context) -> None:
    """After verification, escalate (exit LoopAgent) if verdict is PASS."""
    verdict_raw = callback_context.state.get("dissemination_verdict", "{}")
    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        if verdict.get("verdict") == "PASS":
            callback_context.actions.escalate = True
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return None


def make_verification_agent(before_agent_callback=None) -> Agent:
    """Build a Verification_Agent instance."""
    return Agent(
        name="Verification_Agent",
        model="gemini-2.5-flash",
        instruction=VERIFICATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            top_p=0.95,
            top_k=40,
        ),
        output_key="verified_dissemination",
        before_agent_callback=before_agent_callback,
        after_agent_callback=_escalate_on_pass,
    )

# ---------------------------------------------------------------------------
# Module-level pipeline + root_agent (for adk web)
#
# TWO EXECUTION TOPOLOGIES EXIST (by design):
#
#   Web path (adk web):
#     LoopAgent ("Dissemination_Loop") wraps a SequentialAgent
#     ("Dissemination_Pipeline") of Routing_Agent, Routing_Judge, and
#     Verification_Agent. Loop exit is driven by _escalate_on_pass, an
#     after_agent_callback on the Verification_Agent that escalates when the
#     verdict is PASS. No fan-out brief generation in this path.
#
#   Batch path (run_pipeline):
#     Python for-loop drives iteration manually. Loop exit is driven by reading
#     verdict from state after each pass. Includes retry logic, deterministic
#     classification checking, and per-iteration result capture.
#
# Both paths use the same agent factories, instructions, and state keys.
# ---------------------------------------------------------------------------

_root_agent = None
_session_service = None


def _get_root_agent() -> LoopAgent:
    """Lazily construct the web pipeline and root_agent on first access."""
    global _root_agent
    if _root_agent is None:
        _routing = make_routing_agent(before_agent_callback=_init_session_state)
        _judge = make_judge_agent()
        _verification = make_verification_agent(
            before_agent_callback=_validate_verdict_before_verification,
        )
        _web_pipeline = SequentialAgent(
            name="Dissemination_Pipeline",
            sub_agents=[_routing, _judge, _verification],
        )
        _root_agent = LoopAgent(
            name="Dissemination_Loop",
            sub_agents=[_web_pipeline],
            max_iterations=3,
        )
    return _root_agent


def _get_session_service():
    """Lazily construct the session service on first access."""
    global _session_service
    if _session_service is None:
        _session_service = InMemorySessionService()
    return _session_service


# Module-level name for adk web discovery.
def __getattr__(name: str):
    if name == "root_agent":
        return _get_root_agent()
    if name == "session_service":
        return _get_session_service()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Brief generation — fan-out per stakeholder
# ---------------------------------------------------------------------------

BRIEF_INSTRUCTION = """\
## Context
You are writing a single stakeholder brief for dissemination of a threat
intelligence product.

## Intelligence Product
{verified_product}

## Recipient
Role: {recipient_role}
Scope: {recipient_scope}
Allowed actions: {recipient_actions}
Classification ceiling: {recipient_clearance}
IOC policy: {ioc_policy}

## Objective
Write a 3-5 paragraph brief tailored to this specific recipient's role and scope.
Include ONLY information relevant to their scope and authority.
Recommend ONLY actions from their allowed actions list.
If IOCs are excluded (non-technical recipient), summarize the threat impact
in business terms without raw indicators.

## Response Format
A concise, role-appropriate brief. No JSON — plain text.
"""


async def _generate_briefs_for_manifest(
    manifest: dict,
    verified_product: str,
    model: str = DEFAULT_MODEL,
    temperature: float = DEFAULT_TEMP,
) -> list[dict]:
    """
    Fan-out: generate one tailored brief per stakeholder in the routing manifest.

    Args:
        manifest: parsed routing manifest from the Routing Agent.
        verified_product: the Stage 5 intelligence product.
        model: LLM model for brief generation.
        temperature: sampling temperature.

    Returns:
        List of dicts, each with stakeholder_id and generated brief_text.
    """
    routed = manifest.get("routed_stakeholders", [])
    if not routed:
        return []

    briefs = []
    brief_svc = InMemorySessionService()

    for entry in routed:
        sid = entry.get("stakeholder_id", "")
        stakeholder = STAKEHOLDERS.get(sid)
        if not stakeholder:
            briefs.append({"stakeholder_id": sid, "brief_text": "(unknown stakeholder)"})
            continue

        is_technical = sid not in _NON_TECHNICAL_ROLES
        ioc_policy = (
            "Include relevant technical IOCs (IPs, hashes, domains)."
            if is_technical
            else "Do NOT include raw technical IOCs. Summarize threat impact in business terms."
        )

        instruction = BRIEF_INSTRUCTION.format(
            verified_product=verified_product,
            recipient_role=stakeholder["role"],
            recipient_scope=", ".join(stakeholder["scope"]),
            recipient_actions=", ".join(stakeholder["allowed_actions"]),
            recipient_clearance=stakeholder["clearance"],
            ioc_policy=ioc_policy,
        )

        brief_agent = Agent(
            name=f"Brief_Generator_{sid}",
            model=model,
            instruction=instruction,
            generate_content_config=types.GenerateContentConfig(
                temperature=temperature,
            ),
            output_key="brief_text",
        )

        brief_runner = Runner(
            agent=brief_agent,
            app_name=APP_NAME,
            session_service=brief_svc,
        )

        session_id = f"brief_{sid}_{uuid.uuid4().hex[:8]}"
        await brief_svc.create_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=session_id,
            state={"brief_text": ""},
        )

        brief_text = ""
        for _attempt in range(3):
            try:
                async for event in brief_runner.run_async(
                    user_id=USER_ID,
                    session_id=session_id,
                    new_message=types.Content(
                        role="user",
                        parts=[types.Part(text=f"Generate the stakeholder brief for {stakeholder['role']}.")],
                    ),
                ):
                    pass
                session = await brief_svc.get_session(
                    app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
                )
                brief_text = session.state.get("brief_text", "")
                break
            except (AttributeError, Exception) as exc:
                if "api key" in str(exc).lower():
                    # Missing/invalid API key is fatal — retrying cannot fix it.
                    raise RuntimeError(
                        f"API key problem (fatal, not retried): {exc}\n"
                        "  Set GOOGLE_API_KEY in the .env file described in the "
                        "README's Setup section."
                    ) from exc
                wait = 2 ** _attempt * 5
                print(f"  [RETRY {_attempt+1}/3] Brief gen for {sid} failed: {exc} — waiting {wait}s")
                await asyncio.sleep(wait)
        briefs.append({"stakeholder_id": sid, "brief_text": brief_text})

    return briefs


# ---------------------------------------------------------------------------
# Execution — run_pipeline()
# ---------------------------------------------------------------------------


async def run_pipeline(
    verified_product: str,
    max_iterations: int = 3,
    routing_temp: float = 0.0,
    routing_model: str = DEFAULT_MODEL,
    threat_context: str = "",
    progress_callback=None,
) -> tuple[str, list[dict]]:
    """
    Run the self-refining dissemination pipeline against a verified product.

    Args:
        verified_product: The verified intelligence product from Stage 5.
        max_iterations:   Maximum number of refinement passes (default 3).
        routing_temp:     Sampling temperature for the Routing Agent.
        routing_model:    Model ID for the Routing Agent.
        threat_context:   Threat scenario description for context.

    Returns:
        (session_id, iterations) where iterations is a list of per-pass dicts:
            {
              "iteration":              int,
              "routing_manifest":       str,
              "dissemination_plan":     str,
              "verdict":                dict,
              "verified_dissemination": str,
            }
    """
    # Build agents for this run.
    _routing_agent      = make_routing_agent(model=routing_model, temperature=routing_temp)
    _judge_agent        = make_judge_agent()
    _verification_agent = make_verification_agent()

    # Batch path: the same 3 agents driven by a Python for-loop (no LoopAgent wrapper).
    # The routing agent produces the manifest, then we fan out for briefs,
    # then the judge validates, then verification corrects.
    _svc = _get_session_service()

    session_id = f"stage6_{uuid.uuid4().hex}"

    await _svc.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "verified_product":       verified_product,
            "routing_manifest":       "",
            "dissemination_plan":     "",
            "dissemination_verdict":  "",
            "verified_dissemination": "",
            "threat_context":         threat_context,
        },
    )

    MAX_RETRIES = 3
    iterations: list[dict] = []

    for iteration in range(1, max_iterations + 1):
        user_text = (
            verified_product if iteration == 1
            else "Refine the dissemination plan based on the judge's feedback in session state."
        )

        # --- Phase 1: Routing Agent produces manifest ---
        if progress_callback:
            await progress_callback("Routing_Agent", iteration)
        routing_runner = Runner(
            agent=_routing_agent,
            app_name=APP_NAME,
            session_service=_svc,
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async for event in routing_runner.run_async(
                    user_id=USER_ID,
                    session_id=session_id,
                    new_message=types.Content(
                        role="user",
                        parts=[types.Part(text=user_text)],
                    ),
                ):
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
                        f"Routing agent iteration {iteration} failed after "
                        f"{MAX_RETRIES} attempts: {exc}"
                    ) from exc
                wait = 2 ** attempt * 5
                print(f"  [RETRY {attempt}/{MAX_RETRIES}] Routing agent failed: {exc} — waiting {wait}s")
                await asyncio.sleep(wait)

        # Read manifest from state.
        session = await _svc.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
        )
        manifest_raw = session.state.get("routing_manifest", "{}")
        try:
            manifest = json.loads(manifest_raw) if isinstance(manifest_raw, str) else manifest_raw
        except json.JSONDecodeError:
            manifest = {}

        # --- Phase 2: Fan-out brief generation ---
        briefs = await _generate_briefs_for_manifest(
            manifest, verified_product, model=routing_model, temperature=DEFAULT_TEMP,
        )

        # Assemble the full dissemination plan: manifest + generated briefs.
        for brief in briefs:
            for entry in manifest.get("routed_stakeholders", []):
                if entry.get("stakeholder_id") == brief["stakeholder_id"]:
                    entry["generated_brief"] = brief["brief_text"]
                    break

        dissemination_plan = json.dumps(manifest, indent=2)

        # Write assembled plan to session state.
        session = await _svc.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
        )
        session.state["dissemination_plan"] = dissemination_plan

        # --- Phase 2.5: Deterministic classification check ---
        routed = manifest.get("routed_stakeholders", [])
        classification_violations = check_classification_compliance(routed)
        if classification_violations:
            for cv in classification_violations:
                print(f"  [CLASSIFICATION] {cv}")

        # --- Phase 3: Judge validates the plan ---
        if progress_callback:
            await progress_callback("Routing_Judge", iteration)
        judge_runner = Runner(
            agent=_judge_agent,
            app_name=APP_NAME,
            session_service=_svc,
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async for event in judge_runner.run_async(
                    user_id=USER_ID,
                    session_id=session_id,
                    new_message=types.Content(
                        role="user",
                        parts=[types.Part(text="Validate this dissemination plan.")],
                    ),
                ):
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
                        f"Judge iteration {iteration} failed after "
                        f"{MAX_RETRIES} attempts: {exc}"
                    ) from exc
                wait = 2 ** attempt * 5
                print(f"  [RETRY {attempt}/{MAX_RETRIES}] Judge failed: {exc} — waiting {wait}s")
                await asyncio.sleep(wait)

        # Read and validate verdict.
        session = await _svc.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
        )
        verdict_raw = session.state.get("dissemination_verdict", "{}")
        try:
            verdict_dict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
            validated = DisseminationVerdict.model_validate(verdict_dict)
            verdict = validated.model_dump()
        except (json.JSONDecodeError, TypeError):
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
        rule_issues = check_verdict_rules(verdict, dissemination_plan)
        if rule_issues:
            for issue in rule_issues:
                print(f"  [RULE CHECK] {issue}")
            if verdict.get("verdict") == "PASS":
                verdict["verdict"] = "FAIL"
                verdict["summary"] = (
                    f"Deterministic rule check failed: {len(rule_issues)} issue(s). "
                    f"Verdict downgraded from PASS to FAIL."
                )

        # Over-routing check — catches RR-003 and RR-008 violations the judge
        # under-penalizes (returns PARTIAL when FAIL is required).
        over_routing_issues = check_over_routing(manifest)
        if over_routing_issues:
            for issue in over_routing_issues:
                print(f"  [OVER-ROUTING] {issue}")
            if verdict.get("verdict") != "FAIL":
                verdict["verdict"] = "FAIL"
                verdict["summary"] = (
                    f"Over-routing check failed: {len(over_routing_issues)} violation(s). "
                    f"Verdict forced to FAIL."
                )

        # Classification violations force FAIL regardless of judge verdict.
        if classification_violations and verdict.get("verdict") == "PASS":
            verdict["verdict"] = "FAIL"
            verdict["summary"] = (
                f"Classification compliance check failed: "
                f"{len(classification_violations)} violation(s). "
                f"Verdict forced to FAIL."
            )

        # Write corrected verdict back to state for verification agent.
        session = await _svc.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
        )
        session.state["dissemination_verdict"] = json.dumps(verdict)

        # --- Phase 4: Verification agent corrects ---
        if progress_callback:
            await progress_callback("Verification_Agent", iteration)
        verification_runner = Runner(
            agent=_verification_agent,
            app_name=APP_NAME,
            session_service=_svc,
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async for event in verification_runner.run_async(
                    user_id=USER_ID,
                    session_id=session_id,
                    new_message=types.Content(
                        role="user",
                        parts=[types.Part(text="Apply the judge's corrections to the dissemination plan.")],
                    ),
                ):
                    pass
                break
            except Exception as exc:
                if attempt == MAX_RETRIES:
                    raise RuntimeError(
                        f"Verification iteration {iteration} failed after "
                        f"{MAX_RETRIES} attempts: {exc}"
                    ) from exc
                wait = 2 ** attempt * 5
                print(f"  [RETRY {attempt}/{MAX_RETRIES}] Verification failed: {exc} — waiting {wait}s")
                await asyncio.sleep(wait)

        session = await _svc.get_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
        )

        iterations.append(
            {
                "iteration":              iteration,
                "routing_manifest":       manifest_raw,
                "dissemination_plan":     dissemination_plan,
                "verdict":                verdict,
                "verified_dissemination": session.state.get("verified_dissemination", ""),
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
    # Sample verified product (what Stage 5 would produce).
    verified_product = (
        "### 1. Executive Summary\n"
        "With HIGH confidence, a threat actor used Evilginx2 AiTM proxy phishing to steal "
        "an active Okta session cookie from a partner developer, then accessed 12 private "
        "GitHub repositories. Immediate session revocation and partner notification recommended.\n\n"
        "### 2. Key Findings\n"
        "- C-001 [HIGH confidence]: AiTM session hijacking via stolen Okta session cookie "
        "enabled unauthorized GitHub repository access. Supported by I-001, I-002.\n\n"
        "### 3. Evidence Summary\n"
        "- E-001 [Okta System Log, identity_provider]: user.session.start from Tor exit node "
        "IP 185.220.101.42 with no MFA event in 24h. Confidence: HIGH.\n"
        "- E-002 [SpyCloud, breach_intelligence]: Recaptured Okta session cookie for partner "
        "user. Confidence: HIGH.\n"
        "- E-003 [Proofpoint, email_security]: click.permitted on Evilginx2 phishing URL. "
        "Confidence: HIGH.\n"
        "- E-004 [GitHub Audit Log, version_control]: git.clone of 12 private repos from "
        "same IP. Confidence: HIGH.\n\n"
        "### 4. Analytical Reasoning\n"
        "- I-001 [STRONG]: AiTM session hijacking via stolen cookie. Supporting evidence: "
        "E-001, E-002, E-003. Three independent signals from three categories.\n"
        "- I-002 [MODERATE]: Unauthorized GitHub access via hijacked session. Supporting "
        "evidence: E-001, E-004. Same IP, same time window.\n\n"
        "### 5. Assumptions and Limitations\n"
        "- A-001: Tor exit IP was not legitimate partner VPN. Testable: confirm with partner.\n"
        "- A-002: SpyCloud data is current. Testable: check cookie expiry.\n\n"
        "### 6. Alternative Hypotheses\n"
        "- ALT-001: Legitimate partner VPN. Rejected: Tor exit node, partner confirmed no "
        "Tor policy, phishing click occurred (E-003).\n\n"
        "### 7. Recommendations\n"
        "- Revoke all active Okta sessions for affected partner user.\n"
        "- Rotate all GitHub PATs and deploy keys.\n"
        "- Notify partner organization's security team.\n\n"
        "### 8. Appendix: Source List with TLP Markings\n"
        "- Okta System Log — TLP:AMBER\n"
        "- SpyCloud — TLP:AMBER\n"
        "- Proofpoint Email Security — TLP:AMBER\n"
        "- GitHub Audit Log — TLP:AMBER\n"
        "Product TLP: TLP:AMBER\n"
    )

    print("=" * 70)
    print("DISSEMINATION PIPELINE — Stage 6: Intel Cycle")
    print("ApexCode Solutions | Threat Intelligence")
    print("=" * 70)
    print()

    _, iterations = await run_pipeline(
        verified_product,
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
        print(f"ITERATION {n} — Routing Manifest")
        print("=" * 70)
        print(it["dissemination_plan"][:2000])

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
