"""
Stage 4: Analysis Pipeline
Intel Cycle AI -- ApexCode Solutions

Three-agent SequentialAgent pipeline with self-refinement loop:
  1. SAT_Recommendation_Agent    -- selects and applies Structured Analytic Techniques
                                    to the corroborated brief from Stage 3.
  2. SAT_Judge                   -- validates technique selection, application quality,
                                    and tradecraft compliance.
  3. Analysis_Verification_Agent -- corrects flagged issues, fills gaps, produces
                                    the verified analysis for Stage 5 Production.

State handoff:
  SAT_Recommendation_Agent      -> output_key="analysis_output"    -> session.state
  SAT_Judge                     -> output_key="analysis_verdict"   -> session.state (JSON)
  Analysis_Verification_Agent   -> output_key="verified_analysis"  -> session.state

Loop exits when verdict == "PASS" or max_iterations is reached.

TWO EXECUTION TOPOLOGIES (by design):

  Web path (adk web):
    LoopAgent wraps SequentialAgent with 3 sub-agents. Loop exit is driven by
    _check_loop_exit_callback (before_agent_callback on SAT_Recommendation_Agent).
    Guardrails (_apply_web_path_guardrails) run in the same callback chain,
    before the exit check, ensuring parity with the batch path.
    No per-iteration state inspection -- ADK manages the loop.

  Batch path (run_pipeline):
    Python for-loop drives iteration manually over a 3-agent SequentialAgent.
    Loop exit is driven by reading verdict from state after each pass.
    Includes retry logic, timeout handling, convergence tracking, state
    write-back, and per-iteration result capture for metrics/reporting.

  The split exists because run_pipeline() needs per-iteration state inspection
  (to build the iterations list for metrics/reporting) which LoopAgent does not
  expose. Both paths use the same agent factories, instructions, and state keys.
  Changes to agent config propagate to both paths via the factories.

Run (batch):
    python my_agent/agent.py      # from the chapter-09/ folder

Run (interactive):
    adk web                       # from the chapter-09/ folder (the parent of my_agent/)
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

# ---------------------------------------------------------------------------
# Domain data import -- dual import supports both package and direct execution
# ---------------------------------------------------------------------------

try:
    from .domain_data import (
        SAT_CATALOG,
        SAT_NAMES,
        SAT_SELECTION_RULES,
        AUDIENCE_MAP,
        SAT_TAXONOMY,
        COGNITIVE_BIASES,
        ANALYTIC_SPECTRUM,
        TRADECRAFT_STANDARDS,
        CONFIG_SEARCH_INPUTS,
        TEMPLATE_VERSION,
    )
except ImportError:
    from domain_data import (
        SAT_CATALOG,
        SAT_NAMES,
        SAT_SELECTION_RULES,
        AUDIENCE_MAP,
        SAT_TAXONOMY,
        COGNITIVE_BIASES,
        ANALYTIC_SPECTRUM,
        TRADECRAFT_STANDARDS,
        CONFIG_SEARCH_INPUTS,
        TEMPLATE_VERSION,
    )

# ---------------------------------------------------------------------------
# Session service -- lives at project root, shared across all stages
# ---------------------------------------------------------------------------

from google.adk.sessions import InMemorySessionService

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
# template schema than the one currently in memory. A version mismatch means
# SAT_CATALOG, SAT_SELECTION_RULES, TRADECRAFT_STANDARDS, or SAT_TAXONOMY
# changed after the config search ran — the stored model/temperature may no
# longer be optimal under the new schema.
_cfg_template_ver = _best_cfg.get("template_version", "")
if _best_cfg and _cfg_template_ver and _cfg_template_ver != TEMPLATE_VERSION:
    print(
        f"[WARN] best_config.json was produced under template schema "
        f"v{_cfg_template_ver}, but current schema is v{TEMPLATE_VERSION}. "
        f"Re-run the grid search cells in the simulation notebook to "
        f"re-evaluate under the updated rules."
    )

DEFAULT_MODEL = _best_cfg.get("model", "gemini-2.5-flash")
DEFAULT_TEMP = float(_best_cfg.get("temperature", 0.0))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "intel_cycle"
USER_ID = "ti_analyst"


# ---------------------------------------------------------------------------
# Output Shield -- Pydantic schema for analysis judge verdicts
# ---------------------------------------------------------------------------


class ConfirmedItem(BaseModel):
    source: str
    rationale: str
    relevance: Literal["ESSENTIAL", "USEFUL", "TANGENTIAL"]


class UnverifiedItem(BaseModel):
    source: str
    reason: str
    suggested_alternative: str


class MissingItem(BaseModel):
    source: str
    importance: str


class JudgeVerdict(BaseModel):
    confirmed_valid: list[ConfirmedItem]
    unverified: list[UnverifiedItem]
    missing_critical: list[MissingItem]
    verdict: Literal["PASS", "PARTIAL", "FAIL"]
    summary: str


# ---------------------------------------------------------------------------
# Deterministic rule checker -- validates the structured verdict against
# analysis rules programmatically. Catches logical errors the LLM judge
# may miss (e.g., PASS with non-empty unverified, confirmed items not in
# catalog, taxonomy diversity violations). Runs after Pydantic validation
# as a second safety net.
# ---------------------------------------------------------------------------


def check_analysis_verdict_rules(verdict: dict) -> list[str]:
    """
    Programmatically check a structured verdict against analysis rules.

    Returns a list of discrepancy strings. Empty list = no issues found.
    This does NOT replace the LLM judge -- it catches logical errors the
    judge may miss and logs them as warnings.
    """
    issues: list[str] = []

    v = verdict.get("verdict", "")
    confirmed_list = verdict.get("confirmed_valid", [])
    unverified = verdict.get("unverified", [])
    missing = verdict.get("missing_critical", [])

    # Dedup: a technique listed in both confirmed_valid and unverified is
    # treated as confirmed (confirmed_valid takes precedence).
    confirmed_sources = {item.get("source", "") for item in confirmed_list}
    effective_unverified = [
        item for item in unverified if item.get("source", "") not in confirmed_sources
    ]

    # --- SAT catalog membership: confirmed items must reference valid SATs ---
    _sat_names_lower = {name.lower(): name for name in SAT_NAMES}
    _sat_fullnames_lower = {}
    for _key, _details in SAT_CATALOG.items():
        fn = _details.get("full_name", "")
        if fn:
            _sat_fullnames_lower[fn.lower()] = _key
    for item in confirmed_list:
        source_text = item.get("source", "").strip()
        if not source_text:
            continue
        source_lower = source_text.lower()
        if source_lower in _sat_names_lower:
            continue
        if source_lower in _sat_fullnames_lower:
            continue
        matched = any(
            sat_name.lower() == source_lower
            or source_lower.startswith(sat_name.lower())
            for sat_name in SAT_NAMES
        ) or any(
            fn_lower == source_lower
            or source_lower.startswith(fn_lower)
            for fn_lower in _sat_fullnames_lower
        )
        if not matched:
            issues.append(
                f"Confirmed item source '{source_text}' does not match "
                f"any SAT in the approved catalog"
            )

    # --- Taxonomy diversity: flag if >2 techniques from same category ---
    taxonomy_violated = False
    if SAT_TAXONOMY:
        sat_to_category: dict[str, str] = {}
        for category, members in SAT_TAXONOMY.items():
            for sat_name in members:
                sat_to_category[sat_name] = category

        category_counts: dict[str, int] = {}
        for item in confirmed_list:
            source_text = item.get("source", "").strip().lower()
            for sat_name in SAT_NAMES:
                if sat_name.lower() == source_text or source_text.startswith(sat_name.lower()):
                    cat = sat_to_category.get(sat_name, "")
                    if cat:
                        category_counts[cat] = category_counts.get(cat, 0) + 1
                    break

        for cat, count in category_counts.items():
            if count > 2:
                taxonomy_violated = True
                issues.append(
                    f"Taxonomy diversity violation: {count} techniques from "
                    f"category '{cat}' (max 2 recommended)"
                )

    # --- Logical consistency: verdict vs fields ---
    # The PASS checks below intentionally use the raw unverified/missing lists.
    # effective_unverified (deduped above) feeds only the FAIL branches, where a
    # technique duplicated across confirmed_valid and unverified must not, on its
    # own, keep a FAIL alive.
    if v == "PASS" and len(unverified) > 0:
        issues.append(
            f"Verdict is PASS but unverified has {len(unverified)} entries -- "
            f"should be FAIL"
        )
    if v == "PASS" and len(missing) > 0:
        issues.append(
            f"Verdict is PASS but missing_critical has {len(missing)} entries -- "
            f"should be PARTIAL"
        )
    # FAIL with no effective unverified and non-empty missing is only an
    # inconsistency when there is no taxonomy violation — taxonomy violations
    # are a legitimate reason for FAIL even with empty unverified.
    if (v == "FAIL" and not effective_unverified and len(missing) > 0
            and not taxonomy_violated):
        issues.append(
            f"Verdict is FAIL but unverified is empty and missing_critical has "
            f"{len(missing)} entries -- should be PARTIAL (techniques are valid, "
            f"required SATs are missing)"
        )
    if v == "FAIL" and not effective_unverified and len(missing) == 0 and not taxonomy_violated:
        issues.append(
            f"Verdict is FAIL but both unverified and missing_critical are empty -- "
            f"no basis for FAIL"
        )

    return issues


# ---------------------------------------------------------------------------
# SAT catalog and domain data formatting for prompt injection
# ---------------------------------------------------------------------------


def _format_sat_catalog() -> str:
    """Format all SATs with full name, when_to_use, required_inputs, output_format."""
    lines = []
    for name, spec in SAT_CATALOG.items():
        lines.append(f"### {name}")
        lines.append(f"Full name: {spec['full_name']}")
        lines.append(f"When to use: {spec['when_to_use']}")
        lines.append(f"Required inputs: {', '.join(spec['required_inputs'])}")
        lines.append(f"Output format: {spec['output_format']}")
        lines.append("")
    return "\n".join(lines)


def _format_audience_map() -> str:
    """Format audience mapping with primary, secondary, classification."""
    lines = []
    for name, mapping in AUDIENCE_MAP.items():
        lines.append(
            f"- {name}: Primary={mapping['primary']}, "
            f"Secondary={mapping['secondary']}, "
            f"Classification={mapping['classification']}"
        )
    return "\n".join(lines)


def _format_analytic_spectrum() -> str:
    """Format the analytic spectrum levels for prompt injection."""
    lines = []
    for level, details in ANALYTIC_SPECTRUM.items():
        label = details.get("label", level)
        question = details.get("question", "")
        sats = ", ".join(details.get("sat_alignment", []))
        conf = details.get("confidence_requirement", "")
        lines.append(f"- **{label}** (\"{question}\"): Aligned SATs: {sats}")
        lines.append(f"  Confidence: {conf}")
    return "\n".join(lines)


def _format_cognitive_biases() -> str:
    """Format cognitive biases with name, description, and mitigation."""
    lines = []
    for bias_key, bias in COGNITIVE_BIASES.items():
        name = bias.get("name", bias_key)
        desc = bias.get("description", "")
        mitigation = bias.get("mitigation", "")
        lines.append(f"- **{name}**: {desc}")
        if mitigation:
            lines.append(f"  Mitigation: {mitigation}")
    return "\n".join(lines)


def _format_tradecraft_standards() -> str:
    """Format tradecraft standards for prompt injection."""
    lines = []
    # Confidence calibration
    cal = TRADECRAFT_STANDARDS.get("confidence_calibration", {})
    if cal:
        lines.append("**Confidence Calibration:**")
        for level, desc in cal.items():
            lines.append(f"  - {level}: {desc}")
    # Assumption surfacing
    assumption = TRADECRAFT_STANDARDS.get("assumption_surfacing", "")
    if assumption:
        lines.append(f"\n**Assumption Surfacing:** {assumption}")
    # Alternative hypothesis standard
    alt_hyp = TRADECRAFT_STANDARDS.get("alternative_hypothesis_standard", "")
    if alt_hyp:
        lines.append(f"\n**Alternative Hypothesis Standard:** {alt_hyp}")
    # Analytic process steps
    steps = TRADECRAFT_STANDARDS.get("analytic_process_steps", [])
    if steps:
        lines.append("\n**Analytic Process Steps:**")
        for step in steps:
            lines.append(f"  {step}")
    return "\n".join(lines)


def _format_selection_rules() -> str:
    """Format selection rules as a numbered list."""
    rules = SAT_SELECTION_RULES.get("rules", [])
    lines = []
    for i, rule in enumerate(rules, 1):
        lines.append(f"{i}. {rule}")
    return "\n".join(lines)


# Pre-format texts for prompt injection
_SAT_CATALOG_TEXT = _format_sat_catalog()
_AUDIENCE_MAP_TEXT = _format_audience_map()
_ANALYTIC_SPECTRUM_TEXT = _format_analytic_spectrum()
_COGNITIVE_BIASES_TEXT = _format_cognitive_biases()
_TRADECRAFT_STANDARDS_TEXT = _format_tradecraft_standards()
_SELECTION_RULES_TEXT = _format_selection_rules()


# ---------------------------------------------------------------------------
# Agent Instructions (COSTAR with Critical Thinking Framework)
# ---------------------------------------------------------------------------

GENERATOR_INSTRUCTION = f"""\
## Context
You are the SAT Recommendation Agent in Stage 4 (Analysis) of an intelligence
lifecycle pipeline. You receive a corroborated intelligence brief from Stage 3
(Processing) that contains verified signals with confidence levels. Your role is
to select and apply the correct Structured Analytic Techniques to this scenario.

### Critical Thinking Framework

**Analytic Spectrum** -- Classify where the intelligence question falls:
{_ANALYTIC_SPECTRUM_TEXT}

**Cognitive Biases** -- Be aware of and actively mitigate these biases:
{_COGNITIVE_BIASES_TEXT}

**Tradecraft Standards** -- Adhere to these analytic standards:
{_TRADECRAFT_STANDARDS_TEXT}

## Objective
1. Read the corroborated brief from {{corroborated_brief}}
2. Classify the intelligence question on the analytic spectrum (descriptive /
   explanatory / evaluative / estimative)
3. Identify which cognitive biases are most likely to affect this scenario and
   describe how you will mitigate them
4. Recommend 2-4 Structured Analytic Techniques from the approved catalog below
5. For each recommended SAT, justify WHY it applies to this specific scenario
6. APPLY each technique to the scenario -- produce the actual analytical output
   following the technique's defined output_format
7. Map each SAT's output to its target audience
8. State key assumptions explicitly and rate their vulnerability (HIGH / MEDIUM / LOW)

## Style
Methodical, evidence-based, structured. Apply each technique rigorously with all
required inputs. Never skip a required input field. Surface assumptions rather
than embedding them silently.

## Tone
Professional, analytical, precise. No hedging or filler.

## Audience
The SAT Judge agent will evaluate your output. Downstream consumers include
Security Operations, Business Leadership, and the CISO.

## Response
Output a structured analysis containing:

- ANALYTIC_SPECTRUM_POSITION: Which level (descriptive / explanatory / evaluative /
  estimative) and a one-sentence justification
- BIAS_AWARENESS: Which biases are most relevant to this scenario and how you
  mitigated them in your analysis
- RECOMMENDED_TECHNIQUES: List of 2-4 SAT names (exact catalog names)
- For each technique:
  - TECHNIQUE_NAME: exact name from catalog
  - TAXONOMY_CATEGORY: which taxonomy category this technique belongs to
  - JUSTIFICATION: why this technique applies to the specific scenario
  - APPLICATION: the full analytical output following the technique's output_format
  - AUDIENCE: primary and secondary recipients
- KEY_ASSUMPTIONS: Explicit list of assumptions with vulnerability ratings
  (HIGH / MEDIUM / LOW) and impact-if-wrong description for each
- OVERALL_CONFIDENCE: High / Medium / Low with justification

APPROVED SAT CATALOG (you may ONLY recommend techniques from this list):
{_SAT_CATALOG_TEXT}

AUDIENCE MAPPING:
{_AUDIENCE_MAP_TEXT}

SELECTION RULES:
{_SELECTION_RULES_TEXT}

Threat context (if available): {{threat_context}}
"""

JUDGE_INSTRUCTION = f"""\
## Context
You are the SAT Judge in Stage 4 (Analysis). You evaluate whether the
SAT Recommendation Agent selected appropriate techniques from the approved
catalog and applied them correctly to the scenario.

## Objective
Evaluate the analysis output in {{analysis_output}} against:
1. Does each recommended SAT exist in the approved catalog?
2. Does each SAT match the 'when_to_use' criteria for the given scenario?
3. Was each SAT applied with ALL required inputs present?
4. Were any high-priority SATs for this scenario omitted?
5. Does the output follow each SAT's defined output_format?
6. Did the analysis explicitly state key assumptions?
7. Is the analytic spectrum classification consistent with the scenario?
8. Were more than 2 techniques from the same taxonomy category recommended?
   (this is a violation of taxonomy diversity)
9. Was bias awareness addressed?

## Style
Rigorous, systematic, forensic. Check each technique against catalog rules.
Verify tradecraft compliance in addition to SAT selection.

## Tone
Objective, precise, clinical.

## Audience
The Verification Agent and pipeline metrics system.

## Response
Output ONLY valid JSON matching this exact schema:
{{{{
  "confirmed_valid": [
    {{{{"source": "<SAT name>", "rationale": "<why it's valid>", "relevance": "ESSENTIAL|USEFUL|TANGENTIAL"}}}}
  ],
  "unverified": [
    {{{{"source": "<SAT name or hallucinated technique>", "reason": "<why invalid>", "suggested_alternative": "<catalog SAT>"}}}}
  ],
  "missing_critical": [
    {{{{"source": "<SAT name that should have been included>", "importance": "<why critical for this scenario>"}}}}
  ],
  "verdict": "PASS|PARTIAL|FAIL",
  "summary": "<concise assessment>"
}}}}

Verdict rules:
- FAIL: any recommended technique is NOT in the catalog, OR was applied to the
  wrong scenario type, OR key assumptions were not stated, OR bias awareness
  was absent, OR >2 techniques from the same taxonomy category
- PARTIAL: all techniques are valid but a critical technique for this scenario
  was omitted, OR analytic spectrum classification is inconsistent
- PASS: appropriate techniques selected, correctly applied, no critical
  omissions, tradecraft standards met

The corroborated brief for context: {{corroborated_brief}}

APPROVED SAT CATALOG (only these names are valid):
{_SAT_CATALOG_TEXT}
"""

VERIFICATION_INSTRUCTION = """\
## Context
You are the Verification Agent in Stage 4 (Analysis). You receive the original
analysis output and the Judge's verdict, and you produce a corrected final output.

## Objective
1. Read the analysis output from {analysis_output}
2. Read the Judge's verdict from {analysis_verdict}
3. For items in "unverified": replace the invalid technique with the suggested
   alternative from the catalog, and apply the replacement correctly
4. For items in "missing_critical": add the missing technique and apply it to
   the scenario using the corroborated brief
5. For items in "confirmed_valid": preserve exactly as-is
6. Produce the corrected, complete analysis as the verified output
7. If KEY_ASSUMPTIONS is absent, surface assumptions from the applied techniques
   and rate their vulnerability (HIGH / MEDIUM / LOW)
8. If ANALYTIC_SPECTRUM_POSITION is absent, classify the intelligence question
   on the analytic spectrum (descriptive / explanatory / evaluative / estimative)
9. If BIAS_AWARENESS is absent, identify the most relevant cognitive biases for
   this scenario and describe mitigations applied

## Style
Surgical, precise. Change only what the Judge flagged. Preserve valid work.
Ensure all tradecraft fields are present in the final output.

## Tone
Professional, direct.

## Audience
Stage 5 Production agent and the dissemination pipeline.

## Response
Output the corrected analysis following the same structure as the original:
- ANALYTIC_SPECTRUM_POSITION: preserved or added
- BIAS_AWARENESS: preserved or added
- RECOMMENDED_TECHNIQUES: corrected list
- For each technique: TECHNIQUE_NAME, TAXONOMY_CATEGORY, JUSTIFICATION,
  APPLICATION, AUDIENCE
- KEY_ASSUMPTIONS: preserved or surfaced from applied techniques
- OVERALL_CONFIDENCE: updated if corrections changed the assessment
- VERIFICATION_ACTIONS: list of changes made (replaced X with Y, added Z, etc.)

Corroborated brief: {corroborated_brief}
"""


# ---------------------------------------------------------------------------
# Loop exit logic -- deterministic, no LLM call
#
# New approach: a before_agent_callback on the first agent in the
# SequentialAgent checks the verdict before the next iteration begins.
# If PASS, it sets escalate=True on the callback_context, causing the
# LoopAgent to exit. No LLM call needed.
#
# ---------------------------------------------------------------------------


def _check_loop_exit_callback(callback_context) -> None:
    """Deterministic loop exit check -- runs as before_agent_callback.

    Reads analysis_verdict from session state. If verdict is PASS,
    sets escalate=True to exit the LoopAgent.
    """
    state = callback_context.state
    verdict_raw = state.get("analysis_verdict", "")
    if not verdict_raw:
        return None  # First pass -- no verdict yet.
    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        if verdict.get("verdict") == "PASS":
            callback_context.actions.escalate = True
    except (json.JSONDecodeError, AttributeError):
        pass  # Malformed verdict -- continue iterating.
    return None


# ---------------------------------------------------------------------------
# Session state contract
#
# Each state key has a designated producer (the agent that writes it via
# output_key) and designated consumers (agents that read it via template
# substitution). This contract is enforced by ADK's output_key mechanism
# but documented here for clarity and auditability.
#
#   Key                  Producer                      Consumer(s)
#   corroborated_brief   External (Stage 3 or user)    SAT_Recommendation_Agent
#   threat_context       External (Stage 3 or user)    SAT_Recommendation_Agent
#   analysis_output      SAT_Recommendation_Agent      SAT_Judge, Verification_Agent
#   analysis_verdict     SAT_Judge                     Verification_Agent, loop exit
#   verified_analysis    Verification_Agent             SAT_Recommendation_Agent (refinement)
#
# NAMESPACE ISOLATION: Stage 4 only seeds its own output keys. It does NOT
# overwrite keys written by prior stages (e.g., threat_context from Stage 3,
# verified_brief from Stage 3). The corroborated_brief key is read-only from
# Stage 4's perspective — it is produced by Stage 3 and consumed here.
# ---------------------------------------------------------------------------

# State keys owned by Stage 4 agents — only these are seeded by _init_session_state.
_STAGE4_OUTPUT_KEYS = {
    "analysis_output":   "",  # Written by SAT_Recommendation_Agent
    "analysis_verdict":  "",  # Written by SAT_Judge
    "verified_analysis": "",  # Written by Analysis_Verification_Agent
}

# State keys consumed by Stage 4 but produced externally — read-only, never overwritten.
_STAGE4_INPUT_KEYS = {
    "corroborated_brief",  # Produced by Stage 3 Processing
    "threat_context",      # Produced externally
}


def _init_session_state(callback_context) -> None:
    """Seed Stage 4 output keys if missing. Does NOT overwrite upstream keys.

    Only seeds keys that Stage 4 agents produce (analysis_output, analysis_verdict,
    verified_analysis). Does not touch corroborated_brief or any key from prior
    stages — those are read-only inputs that must be preserved.
    """
    state = callback_context.state
    # Seed Stage 4 output keys only.
    for key, default in _STAGE4_OUTPUT_KEYS.items():
        if key not in state:
            state[key] = default
    # Ensure input keys exist (empty string if Stage 3 hasn't run).
    for key in _STAGE4_INPUT_KEYS:
        if key not in state:
            state[key] = ""
    return None


def _validate_verdict_before_verification(callback_context) -> None:
    """
    Pydantic output shield for the adk web path.
    Validates the judge verdict in session state before the Verification Agent
    reads it via template substitution. Falls back to a FAIL verdict if
    validation fails.
    """
    state = callback_context.state
    verdict_raw = state.get("analysis_verdict", "{}")
    try:
        verdict_dict = (
            json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        )
        JudgeVerdict.model_validate(verdict_dict)
    except (json.JSONDecodeError, ValidationError, TypeError, KeyError):
        state["analysis_verdict"] = json.dumps(
            {
                "confirmed_valid": [],
                "unverified": [],
                "missing_critical": [],
                "verdict": "FAIL",
                "summary": "Judge verdict failed schema validation (web path).",
            }
        )
    return None


# ---------------------------------------------------------------------------
# Web-path guardrails -- mirrors batch-path post-iteration checks
#
# The batch path (run_pipeline) runs check_analysis_verdict_rules() after
# every iteration, downgrading the verdict in state before the next pass.
# The web path previously had no equivalent -- a PASS verdict that failed
# programmatic rule checks would escape undetected.
#
# _apply_web_path_guardrails() closes the gap. It runs as part of
# _combined_before_callback (before_agent_callback on SAT_Recommendation_Agent),
# which fires at the start of every LoopAgent iteration. On iteration 1, no
# verdict exists yet -- the function exits immediately. On iterations 2+, it
# reads the previous verdict from state, runs the same rule check as the
# batch path, and rewrites analysis_verdict in state if a downgrade is needed.
# _check_loop_exit_callback then reads the corrected verdict and only
# escalates if it is still PASS.
# ---------------------------------------------------------------------------


def _apply_web_path_guardrails(callback_context) -> None:
    """
    Apply deterministic guardrails to the web path -- mirrors run_pipeline().

    Reads analysis_verdict from session state. If the verdict is non-empty
    (iteration 2+), runs check_analysis_verdict_rules(). Downgrades the
    verdict in state from PASS to FAIL if rule violations are detected.
    Returns None in all cases so the LoopAgent iteration proceeds normally
    after the callback chain completes.
    """
    state = callback_context.state
    verdict_raw = state.get("analysis_verdict", "")
    if not verdict_raw:
        return None  # First iteration -- no verdict to check yet.

    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
    except (json.JSONDecodeError, TypeError):
        return None  # Malformed verdict -- let _check_loop_exit_callback handle it.

    # Deterministic rule check -- same logic as batch path.
    rule_issues = check_analysis_verdict_rules(verdict)
    if rule_issues:
        for issue in rule_issues:
            print(f"  [WEB RULE CHECK] {issue}")
        v = verdict.get("verdict", "")
        unverified = verdict.get("unverified", [])
        missing = verdict.get("missing_critical", [])
        changed = False
        if v == "PASS":
            verdict["verdict"] = "FAIL"
            verdict["summary"] = (
                f"Deterministic rule check failed: {len(rule_issues)} issue(s). "
                f"Verdict downgraded from PASS to FAIL."
            )
            changed = True
        elif v == "FAIL":
            # Upgrade FAIL → PARTIAL only when:
            #   - no effective unverified (deduped: remove confirmed duplicates)
            #   - at least one required SAT is missing
            #   - no taxonomy violation (taxonomy violations are valid FAILs)
            confirmed_sources = {item.get("source", "") for item in verdict.get("confirmed_valid", [])}
            effective_unverified = [
                item for item in unverified if item.get("source", "") not in confirmed_sources
            ]
            taxonomy_violated = any("Taxonomy diversity" in issue for issue in rule_issues)
            if not effective_unverified and len(missing) > 0 and not taxonomy_violated:
                verdict["verdict"] = "PARTIAL"
                verdict["summary"] = (
                    f"Deterministic rule check: verdict upgraded from FAIL to PARTIAL -- "
                    f"techniques are valid but {len(missing)} required SAT(s) missing."
                )
                changed = True
        if changed:
            # Write corrected verdict back to state so _check_loop_exit_callback
            # reads the corrected value and does not trigger early exit on a PASS.
            state["analysis_verdict"] = json.dumps(verdict)

    return None


# ---------------------------------------------------------------------------
# Agent factory functions
# ---------------------------------------------------------------------------


def make_generator_agent(
    model: str = DEFAULT_MODEL,
    temperature: float = DEFAULT_TEMP,
    before_agent_callback=None,
) -> Agent:
    """Create the SAT Recommendation Agent (Generator)."""
    return Agent(
        name="SAT_Recommendation_Agent",
        description=(
            "Selects and applies Structured Analytic Techniques from the approved "
            "SAT catalog to the corroborated intelligence brief. Classifies the "
            "analytic spectrum position, mitigates cognitive biases, and maps "
            "outputs to target audiences."
        ),
        model=model,
        instruction=GENERATOR_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=temperature,
            top_p=0.95,
            top_k=40,
        ),
        output_key="analysis_output",
        before_agent_callback=before_agent_callback,
    )


def make_judge_agent() -> Agent:
    """Create the SAT Judge Agent with constrained JSON output.

    Uses output_schema to enforce Gemini constrained decoding — the model
    is structurally required to produce JudgeVerdict-shaped JSON at the
    API level, not just instructed to do so via prompt.
    """
    return Agent(
        name="SAT_Judge",
        description=(
            "Validates SAT selection, application quality, and tradecraft "
            "compliance against the approved catalog and selection rules. "
            "Returns a structured JudgeVerdict JSON with PASS / PARTIAL / FAIL."
        ),
        model="gemini-2.5-flash",
        instruction=JUDGE_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
        output_key="analysis_verdict",
        output_schema=JudgeVerdict,
        include_contents="none",
    )


def make_verification_agent(before_agent_callback=None) -> Agent:
    """Create the Verification Agent.

    Uses temperature=0.0 (greedy decoding) — top_p and top_k are not set
    because they have no effect when temperature is zero.
    """
    return Agent(
        name="Analysis_Verification_Agent",
        description=(
            "Applies SAT Judge corrections to produce the verified analysis: "
            "replaces invalid techniques with suggested alternatives, adds "
            "missing critical techniques, and ensures tradecraft completeness "
            "(assumptions, bias awareness, analytic spectrum classification)."
        ),
        model="gemini-2.5-flash",
        instruction=VERIFICATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
        ),
        output_key="verified_analysis",
        before_agent_callback=before_agent_callback,
        include_contents="none",
    )


# ---------------------------------------------------------------------------
# Module-level pipeline + root_agent (for adk web)
#
# TWO EXECUTION TOPOLOGIES EXIST (by design):
#
#   Web path (adk web):
#     LoopAgent wraps SequentialAgent. Loop exit is driven by
#     _check_loop_exit_callback (before_agent_callback on SAT_Recommendation_Agent).
#     Guardrails (_apply_web_path_guardrails) run in the same callback chain,
#     before the exit check, ensuring parity with the batch path.
#
#   Batch path (run_pipeline):
#     Python for-loop drives iteration manually. Includes retry logic and
#     per-iteration result capture for metrics/reporting.
#
# The split exists because run_pipeline() needs per-iteration state inspection
# (to build the iterations list for metrics/reporting) which LoopAgent does not
# expose. Both paths use the same agent factories, instructions, and state keys.
# Changes to agent config propagate to both paths via the factories.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Lazy initialization -- agents and session service are constructed on first
# access, not at import time. This prevents eval scripts (which only need
# factories and Pydantic models) from triggering full pipeline construction
# and SQLite session loading.
# ---------------------------------------------------------------------------

_root_agent = None
_session_service = None


def _get_root_agent() -> LoopAgent:
    """Lazily construct the web pipeline and root_agent on first access.

    Loop exit is handled by _check_loop_exit_callback on the
    SAT_Recommendation_Agent (runs before each iteration).
    """
    global _root_agent
    if _root_agent is None:
        def _combined_before_callback(callback_context):
            """Combines state init + guardrails + loop exit check in one callback.

            Order is deliberate:
            1. _init_session_state        -- seed missing state keys (must run first).
            2. _apply_web_path_guardrails -- validate previous verdict, downgrade in
                                            state if rule violations detected (must
                                            run before exit check sees the verdict).
            3. _check_loop_exit_callback  -- read (possibly downgraded) verdict, set
                                            escalate=True only on genuine PASS.
            """
            _init_session_state(callback_context)
            _apply_web_path_guardrails(callback_context)
            _check_loop_exit_callback(callback_context)

        _gen = make_generator_agent(before_agent_callback=_combined_before_callback)
        _judge = make_judge_agent()
        _verif = make_verification_agent(
            before_agent_callback=_validate_verdict_before_verification,
        )
        _seq = SequentialAgent(
            name="Analysis_Pipeline",
            sub_agents=[_gen, _judge, _verif],
        )
        _root_agent = LoopAgent(
            name="Analysis_Loop",
            sub_agents=[_seq],
            max_iterations=3,
        )
    return _root_agent


def _get_session_service():
    """Lazily construct the session service on first access."""
    global _session_service
    if _session_service is None:
        _session_service = InMemorySessionService()
    return _session_service


# Module-level name for adk web discovery. Uses __getattr__ so the LoopAgent
# is only constructed when adk web actually accesses `root_agent`.
def __getattr__(name: str):
    if name == "root_agent":
        return _get_root_agent()
    if name == "session_service":
        return _get_session_service()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Verdict parsing and metrics
# ---------------------------------------------------------------------------


def parse_verdict(raw: str) -> JudgeVerdict | dict:
    """Parse judge output into a JudgeVerdict. Falls back to raw dict on failure."""
    try:
        data = json.loads(raw)
        return JudgeVerdict(**data)
    except (json.JSONDecodeError, ValidationError) as e:
        print(f"  [WARN] Verdict parse failed: {e} -- falling back to raw dict")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"error": str(e), "raw": raw}


def compute_metrics(verdict: JudgeVerdict) -> dict:
    """Compute precision, coverage, F1, and relevance from a JudgeVerdict."""
    valid = len(verdict.confirmed_valid)
    unverified = len(verdict.unverified)
    missing = len(verdict.missing_critical)

    precision = valid / (valid + unverified) if (valid + unverified) > 0 else 0.0
    coverage = valid / (valid + missing) if (valid + missing) > 0 else 0.0
    f1 = (
        2 * precision * coverage / (precision + coverage)
        if (precision + coverage) > 0
        else 0.0
    )

    essential_useful = sum(
        1
        for item in verdict.confirmed_valid
        if item.relevance in ("ESSENTIAL", "USEFUL")
    )
    relevance = essential_useful / valid if valid > 0 else 0.0

    return {
        "precision": round(precision, 3),
        "coverage": round(coverage, 3),
        "f1": round(f1, 3),
        "relevance": round(relevance, 3),
        "verdict": verdict.verdict,
    }


# ---------------------------------------------------------------------------
# Execution -- run_pipeline()
# ---------------------------------------------------------------------------


async def run_pipeline(
    corroborated_brief: str,
    max_iterations: int = 3,
    analysis_temp: float = DEFAULT_TEMP,
    analysis_model: str = DEFAULT_MODEL,
    threat_context: str = "",
    progress_callback=None,
    session_service=None,
) -> tuple[str, list[dict]]:
    """
    Run the self-refining analysis pipeline against a corroborated brief.

    Args:
        corroborated_brief: The verified corroborated brief from Stage 3.
        max_iterations:     Maximum number of refinement passes (default 3).
        analysis_temp:      Sampling temperature for the SAT Recommendation Agent.
        analysis_model:     Model ID for the SAT Recommendation Agent.
        threat_context:     Threat scenario description for context.
        progress_callback:  Optional async callable(agent_name: str, iteration: int).
        session_service:    ADK session service to use. If None (default), a
                            lazy module-level InMemorySessionService singleton is
                            used. Pass a fresh InMemorySessionService per run for
                            batch eval / grid search so concurrent pipelines do
                            not share session state -- eval sessions do not need
                            to persist across process restarts.

    Returns:
        (session_id, iterations) where iterations is a list of per-pass dicts:
            {
              "iteration":             int,
              "analysis_output":       str,
              "verdict":               dict,
              "verified_analysis":     str,
              "n_unverified":          int,
              "convergence_regressed": bool,
            }
    """
    # Batch path uses a 3-agent SequentialAgent.
    _gen = make_generator_agent(model=analysis_model, temperature=analysis_temp)
    _judge = make_judge_agent()
    _verif = make_verification_agent()

    _pipeline = SequentialAgent(
        name="Analysis_Pipeline",
        sub_agents=[_gen, _judge, _verif],
    )
    # Use caller-supplied session service if provided, otherwise fall back to the
    # module-level lazy InMemorySessionService singleton. Callers running many
    # concurrent pipelines (e.g., config_search) should supply their own
    # InMemorySessionService so runs do not share session state.
    _svc = session_service if session_service is not None else _get_session_service()
    _runner = Runner(
        agent=_pipeline,
        app_name=APP_NAME,
        session_service=_svc,
    )

    session_id = f"stage4_{uuid.uuid4().hex}"

    await _svc.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "corroborated_brief": corroborated_brief,
            "threat_context":     threat_context,
            "analysis_output":    "",
            "analysis_verdict":   "",
            "verified_analysis":  "",
        },
    )

    MAX_RETRIES = 3
    # Per-iteration wall-clock timeout: 3 agents x ~2 min each = 6 min worst case.
    # 10 min is generous; a hung TCP connection to the Gemini API will never raise
    # on its own -- asyncio.wait_for() is the only mechanism that unblocks it.
    _ITER_TIMEOUT_S = 600
    iterations: list[dict] = []

    for iteration in range(1, max_iterations + 1):
        # First iteration: send the full brief as the user message.
        # Subsequent iterations: brief is already in state; send a minimal
        # trigger to avoid duplicating tokens per iteration.
        user_text = (
            corroborated_brief
            if iteration == 1
            else "Refine the analysis based on the judge's feedback in session state."
        )

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # Wrap the async iterator in a coroutine so asyncio.wait_for()
                # can cancel it on timeout. Without this wrapper, a stalled
                # streaming response from the Gemini API blocks indefinitely.
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
                # Deterministic failures -- retrying won't help.
                raise RuntimeError(
                    f"Pipeline iteration {iteration} hit a non-retryable error: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            except Exception as exc:
                if "api key" in str(exc).lower():
                    # Missing/invalid API key is fatal -- retrying cannot fix it.
                    raise RuntimeError(
                        f"API key problem (fatal, not retried): {exc}\n"
                        "  Set GOOGLE_API_KEY in the .env file described in the "
                        "README's Setup section."
                    ) from exc
                # Transient failures (API errors, rate limits, network) -- retry.
                if attempt == MAX_RETRIES:
                    raise RuntimeError(
                        f"Pipeline iteration {iteration} failed after "
                        f"{MAX_RETRIES} attempts: {exc}"
                    ) from exc
                # Jittered exponential backoff to prevent thundering herd.
                wait = 2 ** attempt * 5 * (0.5 + random.random())
                print(
                    f"  [RETRY {attempt}/{MAX_RETRIES}] Iteration {iteration} "
                    f"failed: {type(exc).__name__}: {exc} -- waiting {wait:.0f}s"
                )
                await asyncio.sleep(wait)

        # Read state after this iteration completes.
        session = await _svc.get_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=session_id,
        )
        verdict_raw = session.state.get("analysis_verdict", {})

        # ADK stores output_schema results as dicts when Pydantic decoding
        # succeeds, and as JSON strings when the agent writes raw text.
        # Handle both so json.loads() doesn't raise TypeError on a dict.
        try:
            verdict_dict = (
                verdict_raw if isinstance(verdict_raw, dict)
                else json.loads(verdict_raw)
            )
            validated = JudgeVerdict.model_validate(verdict_dict)
            verdict = validated.model_dump()
        except (json.JSONDecodeError, TypeError):
            # Populate unverified with a meaningful entry so the Verification
            # Agent receives actionable feedback instead of an empty verdict
            # that degrades the pipeline to a pass-through.
            print("  [WARN] Judge returned invalid JSON -- treating as FAIL")
            verdict = {
                "confirmed_valid": [],
                "unverified": [{
                    "source": "entire analysis",
                    "reason": "Judge returned invalid JSON -- full re-validation required.",
                    "suggested_alternative": "Re-generate the analysis with stricter "
                    "adherence to the SAT catalog and application format.",
                }],
                "missing_critical": [],
                "verdict": "FAIL",
                "summary": "Judge output was not valid JSON -- Verification Agent "
                "should re-validate the full analysis.",
            }
        except ValidationError as e:
            print(f"  [WARN] Judge verdict failed schema validation: {e}")
            verdict = {
                "confirmed_valid": [],
                "unverified": [{
                    "source": "entire analysis",
                    "reason": f"Judge verdict failed Pydantic validation: "
                    f"{str(e)[:200]}. Full re-validation required.",
                    "suggested_alternative": "Re-generate the analysis ensuring "
                    "all SAT selections and applications follow catalog rules.",
                }],
                "missing_critical": [],
                "verdict": "FAIL",
                "summary": "Judge output failed Pydantic validation -- Verification "
                "Agent should re-validate the full analysis.",
            }

        # Deterministic rule check -- catches logical errors the LLM judge misses.
        # If issues found, downgrade verdict to FAIL so the loop continues
        # rather than exiting on a logically contradictory PASS.
        rule_issues = check_analysis_verdict_rules(verdict)
        if rule_issues:
            for issue in rule_issues:
                print(f"  [RULE CHECK] {issue}")
            _v = verdict.get("verdict", "")
            _unverified = verdict.get("unverified", [])
            _missing = verdict.get("missing_critical", [])
            _changed = False
            if _v == "PASS":
                verdict["verdict"] = "FAIL"
                verdict["summary"] = (
                    f"Deterministic rule check failed: {len(rule_issues)} issue(s). "
                    f"Verdict downgraded from PASS to FAIL."
                )
                _changed = True
            elif _v == "FAIL":
                _confirmed_sources = {item.get("source", "") for item in verdict.get("confirmed_valid", [])}
                _effective_unverified = [
                    item for item in _unverified if item.get("source", "") not in _confirmed_sources
                ]
                _taxonomy_violated = any("Taxonomy diversity" in issue for issue in rule_issues)
                if not _effective_unverified and len(_missing) > 0 and not _taxonomy_violated:
                    verdict["verdict"] = "PARTIAL"
                    verdict["summary"] = (
                        f"Deterministic rule check: verdict upgraded from FAIL to PARTIAL -- "
                        f"techniques are valid but {len(_missing)} required SAT(s) missing."
                    )
                    _changed = True
            if _changed:
                # Write corrected verdict back to session state. session.state
                # returned by get_session() is a copy -- mutating the local
                # `verdict` dict does not update the stored session. Without this
                # write-back, the next iteration's SAT_Recommendation_Agent reads
                # {analysis_verdict} from state and sees the original verdict.
                await _svc.append_event(
                    session,
                    _AdkEvent(
                        author="rule_checker",
                        actions=_AdkEventActions(
                            state_delta={"analysis_verdict": json.dumps(verdict)}
                        ),
                    ),
                )

        # Convergence tracking: detect non-monotone regression so callers can
        # observe it. The self-refining loop assumes each pass reduces violations,
        # but this is not guaranteed.
        curr_n_unverified = len(verdict.get("unverified", []))
        convergence_regressed = False
        if iterations:
            prev_n_unverified = len(iterations[-1]["verdict"].get("unverified", []))
            if curr_n_unverified > prev_n_unverified:
                convergence_regressed = True
                print(
                    f"  [CONVERGENCE WARN] Unverified count increased: "
                    f"{prev_n_unverified} -> {curr_n_unverified} "
                    f"(loop not contracting on iteration {iteration})."
                )

        iterations.append(
            {
                "iteration":             iteration,
                "analysis_output":       session.state.get("analysis_output", ""),
                "verdict":               verdict,
                "verified_analysis":     session.state.get("verified_analysis", ""),
                "n_unverified":          curr_n_unverified,
                "convergence_regressed": convergence_regressed,
            }
        )

        verdict_label = verdict.get("verdict", "UNKNOWN")
        print(
            f"  Iteration {iteration}/{max_iterations}: {verdict_label} -- "
            f"{verdict.get('summary', '')}"
        )

        if verdict_label == "PASS":
            break

    return session_id, iterations


# ---------------------------------------------------------------------------
# Main -- CLI entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    """Run the pipeline with the default ApexCode AiTM scenario."""
    default_brief = (
        "HIGH CONFIDENCE: Partner developer at DevPartner Inc. account used to clone 3 sensitive repos "
        "(phoenix-core, phoenix-api, phoenix-auth) from IP 185.220.101.x (known UNC-XXXX egress point). "
        "Developer's credentials appeared in dark web dump 48h prior. Impossible travel detected: US login, "
        "then RU-based clone within 20min. CrowdStrike process alert on partner workstation shows Evilginx2 "
        "proxy artifact. Three competing explanations remain in play: targeted state-sponsored IP theft, "
        "opportunistic credential abuse, or a disgruntled insider. The breach is confirmed, but its downstream "
        "business impact on ApexCode's revenue-generating products has not yet been quantified and must be "
        "assessed. The actor's follow-on objectives are likewise unassessed and provisional, so a forward "
        "monitoring plan is required to define the new signals that would confirm the actor's next moves "
        "(searching the cloned code for hardcoded secrets, targeting downstream customers, or weaponizing the "
        "code) and that would strengthen or refute the current attribution over time."
    )
    threat_context = (
        "AiTM session-hijacking activity targeting third-party developer partners with Write "
        "access to core repositories. Post-breach focus: define the forward indicators that "
        "confirm or refute the provisional attribution and reveal the actor's next-stage objectives."
    )

    print("=" * 70)
    print("ANALYSIS PIPELINE -- Stage 4: Intel Cycle")
    print("ApexCode Solutions | Threat Intelligence")
    print("=" * 70)
    print()

    session_id, iterations = await run_pipeline(
        corroborated_brief=default_brief,
        max_iterations=3,
        threat_context=threat_context,
    )

    for it in iterations:
        n = it["iteration"]
        verdict = it["verdict"]
        n_valid = len(verdict.get("confirmed_valid", []))
        n_unverified = len(verdict.get("unverified", []))
        n_missing = len(verdict.get("missing_critical", []))

        print()
        print("=" * 70)
        print(f"ITERATION {n} -- Analysis Output")
        print("=" * 70)
        print(it["analysis_output"][:2000])

        print()
        print("=" * 70)
        print(
            f"ITERATION {n} -- Judge Verdict: {verdict.get('verdict')}  "
            f"(valid={n_valid}  unverified={n_unverified}  missing={n_missing})"
        )
        print("=" * 70)
        print(json.dumps(verdict, indent=2)[:2000])

    print()
    print("=" * 70)
    final_verdict = iterations[-1]["verdict"].get("verdict", "UNKNOWN")
    print(f"FINAL RESULT after {len(iterations)} iteration(s): {final_verdict}")
    print(f"Session ID: {session_id}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
