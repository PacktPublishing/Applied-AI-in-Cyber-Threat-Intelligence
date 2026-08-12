"""
Stage 5: Production Pipeline
Intel Cycle AI — ApexCode Solutions

Three-stage SequentialAgent pipeline with self-refinement loop:
  1. Argument_Mapping_Agent  — transforms verified analysis into a structured
                               argument map (evidence → inference → conclusion).
  2. Logic_Judge             — validates structural soundness: evidence chains,
                               source citations, strength calibration, explicit
                               assumptions, and alternative hypotheses.
  3. Verification_Agent      — corrects structural violations, adds missing nodes.

Loop exit is a deterministic after_agent_callback on the Verification_Agent that reads
the verdict from state and signals the LoopAgent to exit on a genuine PASS (no LLM call).

IMPORTANT — Analytic product, not raw data:
  This pipeline operates on VERIFIED ANALYSIS (Stage 4 output), not on raw
  telemetry or collection data. The Argument Mapping Agent structures analytic
  conclusions from the analysis stage into a formal argument map with explicit
  evidence chains, assumptions, and alternatives. The output is an intelligence
  product ready for stakeholder dissemination in Stage 6.

State handoff:
  argument_mapping_agent  → output_key="argument_map"        → session.state
  judge_agent             → output_key="production_verdict"   → session.state (JSON)
  verification_agent      → output_key="verified_product"     → session.state

Loop exits when verdict == "PASS" or max_iterations is reached.

Run (batch):
    python my_agent/agent.py

Run (interactive):
    adk web          # from the chapter-10/ repo root
"""

import asyncio
import json
import random
import re
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
from google.adk.tools import ToolContext
from google.genai import types

# Support both direct execution and package import (adk web).
try:
    from .argument_templates import (
        format_templates_for_prompt, NODE_TYPES, STRENGTH_LEVELS,
        LOGIC_RULES, PRODUCT_SECTIONS, TEMPLATE_VERSION,
    )
except ImportError:
    from argument_templates import (
        format_templates_for_prompt, NODE_TYPES, STRENGTH_LEVELS,
        LOGIC_RULES, PRODUCT_SECTIONS, TEMPLATE_VERSION,
    )

# Session service lives at project root — shared across all stages.
from google.adk.sessions import InMemorySessionService


# ---------------------------------------------------------------------------
# Output Shield — Pydantic schema for production judge verdicts
# ---------------------------------------------------------------------------


class ConfirmedNode(BaseModel):
    source: str
    rationale: str
    relevance: Literal["ESSENTIAL", "USEFUL", "TANGENTIAL"]


class UnverifiedNode(BaseModel):
    source: str
    reason: str
    suggested_alternative: str


class MissingNode(BaseModel):
    source: str
    importance: str


class ProductionVerdict(BaseModel):
    confirmed_valid: list[ConfirmedNode]
    unverified: list[UnverifiedNode]
    missing_critical: list[MissingNode]
    verdict: Literal["PASS", "PARTIAL", "FAIL"]
    summary: str


# ---------------------------------------------------------------------------
# Deterministic rule checker — validates the structured verdict against
# logic rules programmatically. Catches structural errors the LLM judge
# may miss (e.g., PASS with non-empty unverified, STRONG with insufficient
# evidence). Runs after Pydantic validation as a second safety net.
# ---------------------------------------------------------------------------

# TLP validation — programmatic enforcement of TLP marking rules.
# The LLM assigns TLP in the product text; this function verifies it.
_TLP_PATTERN = re.compile(r"\bTLP:(RED|AMBER|GREEN|CLEAR)\b", re.IGNORECASE)
_TLP_RESTRICTIVENESS = {"RED": 4, "AMBER": 3, "GREEN": 2, "CLEAR": 1}

# Argument map node-ID patterns — used by check_verdict_rules for programmatic
# LR-001/002/004/005 compliance checks on the raw argument map text.
# These operate on the text produced by Argument_Mapping_Agent, not the verdict.
_ARG_C   = re.compile(r"\bC-\d+\b",   re.IGNORECASE)  # Conclusion nodes
_ARG_I   = re.compile(r"\bI-\d+\b",   re.IGNORECASE)  # Inference nodes (any occurrence)
_ARG_E   = re.compile(r"\bE-\d+\b",   re.IGNORECASE)  # Evidence nodes
_ARG_A   = re.compile(r"\bA-\d+\b",   re.IGNORECASE)  # Assumption nodes
_ARG_ALT = re.compile(r"\bALT-\d+\b", re.IGNORECASE)  # Alternative hypothesis nodes

# Inference node definition lines only — used by the LR-002 citation check.
# _ARG_I matches every I-NNN in the document, including
# cross-references embedded in conclusions ("Supported by I-001, I-002.") and
# in other inference blocks. A 500-char window from a cross-reference position
# typically contains conclusion text, not the inference's "Supporting evidence:"
# block, producing false-positive "uncited" flags on compliant inferences.
#
# _ARG_I_DEF restricts matches to lines that start an inference definition:
#   optional whitespace, optional list marker (-, *, •), then I-NNN.
# The node ID is captured in group(1); m.start(1) gives its position for the
# 500-char window, preserving the same window behavior as before.
_ARG_I_DEF = re.compile(
    r"^[ \t]*[-*•]?[ \t]*(I-\d+)\b",
    re.MULTILINE | re.IGNORECASE,
)

# Inline assumption language — embedding assumptions in inference text violates LR-004.
# These phrases flag where an explicit A-NNN node should exist instead.
_ASSUMPTION_PHRASES = re.compile(
    r"\b(assuming|we assume|assumption:|assumes|assumed that)\b",
    re.IGNORECASE,
)


def validate_product_tlp(verified_product: str) -> list[str]:
    """
    Validate TLP marking in the verified product.

    Checks:
    1. At least one TLP marking exists in the product.
    2. A "Product TLP:" line exists declaring the overall level.
    3. The declared product TLP is the most restrictive of all source TLPs.

    Returns a list of issue strings. Empty = valid.
    """
    issues: list[str] = []
    if not verified_product:
        return issues

    # Find all TLP markings in the product.
    all_tlps = _TLP_PATTERN.findall(verified_product)
    if not all_tlps:
        issues.append("TLP: No TLP marking found in verified product.")
        return issues

    # Normalize to uppercase.
    all_tlps_upper = [t.upper() for t in all_tlps]

    # Find the declared product-level TLP (usually last, after "Product TLP:").
    product_tlp = None
    for line in verified_product.split("\n"):
        if "product tlp" in line.lower():
            match = _TLP_PATTERN.search(line)
            if match:
                product_tlp = match.group(1).upper()

    if product_tlp is None:
        issues.append(
            "TLP: No 'Product TLP:' declaration found. "
            f"Source TLPs found: {', '.join(set(all_tlps_upper))}"
        )
        return issues

    # The product TLP must be the most restrictive source TLP.
    most_restrictive = max(
        all_tlps_upper,
        key=lambda t: _TLP_RESTRICTIVENESS.get(t, 0),
    )
    if _TLP_RESTRICTIVENESS.get(product_tlp, 0) < _TLP_RESTRICTIVENESS.get(most_restrictive, 0):
        issues.append(
            f"TLP: Product declared TLP:{product_tlp} but sources include "
            f"TLP:{most_restrictive} — product must be at least TLP:{most_restrictive}."
        )

    return issues


def check_verdict_rules(verdict: dict, argument_map: str = "") -> list[str]:
    """
    Programmatically check a structured verdict against logic rules.

    Args:
        verdict:      ProductionVerdict-shaped dict (confirmed_valid, unverified,
                      missing_critical, verdict, summary).
        argument_map: Raw argument map text from the Argument_Mapping_Agent.
                      When provided, enables text-based checks for LR-001/002/004/005
                      that the verdict alone cannot cover. Defaults to "" (skips
                      text analysis — verdict-consistency checks still run).

    Returns:
        A list of discrepancy strings. Empty list = no issues found.
        This does NOT replace the LLM judge — it catches structural errors the
        judge may miss and logs them as warnings. The verdict is downgraded in
        run_pipeline() if issues are found.
    """
    issues: list[str] = []

    # --- Logical consistency: verdict field vs lists ---
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

    # --- LR-003 spot check via verdict: STRONG claims in confirmed items ---
    # Checks the judge's own rationale for STRONG labels with insufficient evidence.
    for item in verdict.get("confirmed_valid", []):
        source_text = item.get("source", "").lower()
        rationale_text = item.get("rationale", "").lower()
        combined = f"{source_text} {rationale_text}"

        # Only trigger when the judge's rationale explicitly cites E-NNN node
        # IDs. Without this guard, prose like "strong inference with sufficient
        # evidence" fires the check even though no E-NNN IDs are present — a
        # false positive that causes unnecessary FAIL downgrades.
        evidence_refs = re.findall(r"\bE-\d+\b", combined, re.IGNORECASE)
        if "strong" in combined and evidence_refs and len(set(evidence_refs)) < 3:
            issues.append(
                f"LR-003: Confirmed item mentions STRONG but references "
                f"only {len(set(evidence_refs))} evidence nodes (need 3+): "
                f"{item.get('source', '')[:80]}"
            )

    # --- Argument map text analysis: LR-001, LR-002, LR-004, LR-005 ---
    # These checks require the raw argument map text, which the verdict dict
    # does not contain. Skipped if argument_map is empty.
    if not argument_map:
        return issues

    conclusions = set(_ARG_C.findall(argument_map))
    evidence    = set(_ARG_E.findall(argument_map))
    assumptions = set(_ARG_A.findall(argument_map))
    alts        = set(_ARG_ALT.findall(argument_map))

    # LR-001: Every conclusion must trace to >= 2 independent evidence nodes.
    # Heuristic: if conclusions exist but total unique E-NNN nodes in the map < 2,
    # no conclusion can possibly satisfy the chain-completeness requirement.
    if conclusions and len(evidence) < 2:
        issues.append(
            f"LR-001: {len(conclusions)} conclusion node(s) found but only "
            f"{len(evidence)} unique evidence node(s) in argument map "
            f"(minimum 2 required for evidence chain completeness)."
        )

    # LR-002: Every inference must cite at least one evidence node.
    # Uses _ARG_I_DEF (definition-line-only pattern) so the 500-char window
    # starts at the inference definition, not at a cross-reference embedded
    # in a conclusion or another inference block.
    uncited: set[str] = set()
    for m in _ARG_I_DEF.finditer(argument_map):
        node_id = m.group(1).upper()
        window = argument_map[m.start(1) : m.start(1) + 500]
        if not _ARG_E.search(window):
            uncited.add(node_id)
    if uncited:
        issues.append(
            f"LR-002: {len(uncited)} inference node reference(s) have no E-NNN "
            f"evidence citation within 500 characters: "
            f"{', '.join(sorted(uncited)[:5])}."
        )

    # LR-004: Key assumptions must be explicit A-NNN nodes, not embedded phrases.
    # Flag if assumption language appears in the text but no A-NNN nodes exist.
    if _ASSUMPTION_PHRASES.search(argument_map) and not assumptions:
        issues.append(
            "LR-004: Assumption language detected in argument map but no A-NNN "
            "assumption nodes found. Extract embedded assumptions into explicit "
            "nodes with assumption, if_wrong_impact, and testable fields."
        )

    # LR-005: Each conclusion requires at least one alternative hypothesis.
    # Flag if conclusions exist but no ALT-NNN nodes are present anywhere in the map.
    if conclusions and not alts:
        issues.append(
            f"LR-005: {len(conclusions)} conclusion node(s) found but no ALT-NNN "
            "alternative hypothesis nodes detected. Each conclusion requires at "
            "least one alternative with rejection rationale."
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

# Stale-config guard: warn if best_config.json was produced
# under a different template schema than the one currently in memory. A version
# mismatch means LOGIC_RULES, STRENGTH_LEVELS, NODE_TYPES, or PRODUCT_SECTIONS
# changed after the config search ran — the stored model/temperature may no
# longer be optimal under the new schema.
_cfg_template_ver = _best_cfg.get("template_version", "")
if _best_cfg and _cfg_template_ver and _cfg_template_ver != TEMPLATE_VERSION:
    print(
        f"[WARN] best_config.json was produced under template schema "
        f"v{_cfg_template_ver}, but current schema is v{TEMPLATE_VERSION}. "
        f"Re-run the grid search cell in the simulation notebook to re-evaluate under the updated rules."
    )

DEFAULT_MODEL = _best_cfg.get("model", "gemini-2.5-flash")
DEFAULT_TEMP  = float(_best_cfg.get("temperature", 0.2))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "intel_cycle"
USER_ID  = "ti_analyst"

# ---------------------------------------------------------------------------
# Agent 1: Argument_Mapping_Agent
# ---------------------------------------------------------------------------

ARGUMENT_INSTRUCTION = f"""\
## Context
You are a senior Intelligence Product Author at ApexCode Solutions.
You are performing Stage 5 of the intelligence cycle: Production.

### Verified Analysis (from Stage 4)
{{verified_analysis}}

If the verified analysis above is empty, inform the user that Stage 4 Analysis
must be completed before Production can begin.

NOTE: You are transforming analysis results into a structured argument map
following formal logic rules. Every conclusion must trace to evidence through
explicit inference chains. Assumptions must be stated, not embedded.

## Argument Node Types and Logic Rules
You may ONLY construct argument structures according to the node types,
strength levels, and logic rules below. Any structure that violates these
rules will be rejected by the Logic Judge.

{format_templates_for_prompt()}

## Refinement Feedback from Previous Iteration
If {{verified_product}} is EMPTY → this is the first pass. Generate the initial
argument map and intelligence product from scratch.

If {{verified_product}} is NON-EMPTY → this is a refinement pass:
  Rule 1 — Preserve: Keep all validated nodes from {{verified_product}}.
  Rule 2 — Fix violations: Parse {{production_verdict}} and correct every
           entry in "unverified" (strengthen evidence chains, add citations,
           recalibrate strength levels).
  Rule 3 — Add missing elements: Add every entry in "missing_critical"
           (missing assumptions, alternative hypotheses, product sections).
  Rule 4 — No new structural changes beyond what Rules 2 and 3 require.

### Previously Verified Product
{{verified_product}}

### Logic Judge Verdict (JSON)
{{production_verdict}}

## Objective
Produce a structured intelligence product that:
1. Maps every conclusion to its supporting inferences and evidence nodes
2. Labels each evidence node with source, timestamp range, and confidence
3. Labels each inference with strength (STRONG/MODERATE/WEAK) per evidence rules
4. States all key assumptions as explicit assumption nodes with impact-if-wrong
5. Lists alternative hypotheses with reasons for rejection
6. Includes all 8 required product sections

## Style
Structured, evidence-based. Every claim traces to specific evidence.
Use node IDs (E-001, I-001, C-001, A-001, ALT-001) for cross-referencing.

## Tone
Authoritative but qualified. Confidence levels and strength labels communicate
certainty. Do not overstate — let the evidence structure speak.

## Audience
The dissemination team (Stage 6) who will route this product to stakeholders.
The product must be self-contained and interpretable without analyst context.

## Response Format
Structure the product with these sections:

### 1. Executive Summary
2-3 sentences: what happened, confidence level, recommended action.

### 2. Key Findings
Numbered conclusions (C-001, C-002, ...) with confidence and supporting inferences.

### 3. Evidence Summary
All evidence nodes (E-001, E-002, ...) grouped by source.

### 4. Analytical Reasoning
Inference chains (I-001, I-002, ...) from evidence to conclusions.
Each inference cites evidence nodes and declares strength.

### 5. Assumptions and Limitations
All assumption nodes (A-001, A-002, ...) with if-wrong impact.

### 6. Alternative Hypotheses
Alternative explanations (ALT-001, ALT-002, ...) with rejection rationale.

### 7. Recommendations
Actionable next steps tied to specific conclusions.

### 8. Appendix: Source List with TLP Markings
All sources with their TLP marking. Product TLP is the most restrictive.
"""

# ---------------------------------------------------------------------------
# Session state contract
#
# Each state key has a designated producer (the agent that writes it via
# output_key) and designated consumers (agents that read it via template
# substitution). This contract is enforced by ADK's output_key mechanism
# but documented here for clarity and auditability.
#
#   Key                  Producer                    Consumer(s)
#   verified_analysis    External (Stage 4)          Argument_Mapping_Agent
#   argument_map         Argument_Mapping_Agent      Logic_Judge, Verification_Agent
#   production_verdict   Logic_Judge                 Verification_Agent, _check_loop_exit_callback
#   verified_product     Verification_Agent          Argument_Mapping_Agent (refinement)
#
# NAMESPACE ISOLATION: Stage 5 only seeds its own output keys. It does NOT
# overwrite keys written by prior stages (e.g., threat_context from Stage 3,
# verified_plan from Stage 2). The verified_analysis key is read-only from
# Stage 5's perspective — it is produced by Stage 4 and consumed here.
# ---------------------------------------------------------------------------

# State keys owned by Stage 5 agents — only these are seeded by _init_session_state.
_STAGE5_OUTPUT_KEYS = {
    "argument_map":       "",  # Written by Argument_Mapping_Agent
    "production_verdict": "",  # Written by Logic_Judge
    "verified_product":   "",  # Written by Verification_Agent
}

# State keys consumed by Stage 5 but produced externally — read-only, never overwritten.
_STAGE5_INPUT_KEYS = {
    "verified_analysis",  # Produced by Stage 4 Analysis
}


def _init_session_state(callback_context) -> None:
    """Seed Stage 5 output keys if missing. Does NOT overwrite upstream keys.

    Only seeds keys that Stage 5 agents produce (argument_map, production_verdict,
    verified_product). Does not touch verified_analysis or any key from prior
    stages — those are read-only inputs that must be preserved.
    """
    state = callback_context.state
    # Seed Stage 5 output keys only.
    for key, default in _STAGE5_OUTPUT_KEYS.items():
        if key not in state:
            state[key] = default
    # Ensure input keys exist (empty string if Stage 4 hasn't run).
    for key in _STAGE5_INPUT_KEYS:
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
    verdict_raw = state.get("production_verdict", "{}")
    try:
        verdict_dict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        ProductionVerdict.model_validate(verdict_dict)
    except (json.JSONDecodeError, ValidationError) as exc:
        print(
            f"  [WARN] Verdict validation failed (web path): "
            f"{type(exc).__name__}: {str(exc)[:200]}"
        )
        state["production_verdict"] = json.dumps({
            "confirmed_valid": [], "unverified": [], "missing_critical": [],
            "verdict": "FAIL",
            "summary": f"Judge verdict failed schema validation: {type(exc).__name__}.",
        })
    return None


# ---------------------------------------------------------------------------
# Agent factories
# ---------------------------------------------------------------------------


def make_argument_mapping_agent(
    model: str = DEFAULT_MODEL,
    temperature: float = DEFAULT_TEMP,
    before_agent_callback=None,
) -> Agent:
    """Build an Argument_Mapping_Agent instance."""
    return Agent(
        name="Argument_Mapping_Agent",
        description=(
            "Transforms verified Stage 4 analysis into a structured intelligence "
            "product: evidence nodes → inference chains → conclusions, with explicit "
            "assumption nodes and alternative hypotheses, following logic rules "
            "LR-001 through LR-005."
        ),
        model=model,
        instruction=ARGUMENT_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=temperature,
            top_p=0.9,
            top_k=20,
            frequency_penalty=0.0,
            presence_penalty=0.0,
        ),
        output_key="argument_map",
        before_agent_callback=before_agent_callback,
    )


# ---------------------------------------------------------------------------
# Agent 2: Logic_Judge
# ---------------------------------------------------------------------------

JUDGE_INSTRUCTION = f"""\
## Context
You are a Logic Judge reviewing a structured intelligence product.
Your job: verify that every evidence chain, inference strength, assumption,
and structural element follows the logic rules defined below.

## Argument Node Types and Logic Rules

{format_templates_for_prompt()}

## Input

Intelligence product (argument map) to validate:
{{argument_map}}

Previous iteration's verdict (empty on first pass):
{{production_verdict}}

## Objective

Step 1 — Validate structural soundness:
  For each conclusion node:
  a. Trace to supporting inferences — verify each inference is cited.
  b. Trace inferences to evidence nodes — verify each evidence node exists
     and is cited by source name.
  c. Count independent evidence nodes in the chain:
     - If < 2 independent evidence nodes → LR-001 violation.
  d. Verify inference strength calibration:
     - STRONG requires 3+ evidence nodes from 3+ categories → LR-003.
     - MODERATE requires 2+ from 2+ categories → LR-003.
     - WEAK requires 1+ from 1+ category → LR-003.
  e. Check source citations in every inference → LR-002.
  f. Check that key assumptions are explicit nodes, not embedded in
     inference reasoning → LR-004.
  g. Check that at least one alternative hypothesis is stated per
     conclusion with reason for rejection → LR-005.

Step 2 — Validate product completeness:
  Check that all 8 required sections are present:
  Executive Summary, Key Findings, Evidence Summary, Analytical Reasoning,
  Assumptions and Limitations, Alternative Hypotheses, Recommendations,
  Appendix: Source List with TLP Markings.

Step 3 — Rate relevance of each confirmed element:
  ESSENTIAL — directly supports the primary conclusion chain; product is
              materially weaker without it.
  USEFUL    — provides supporting structure or corroboration; strengthens
              the product but not critical on its own.
  TANGENTIAL — technically valid but low-priority for this specific scenario.

  If rules are followed: record in confirmed_valid with relevance rating.
  If violated: record in unverified with the specific rule violated and correction.

Step 4 — Identify missing structural elements:
  If {{production_verdict}} is EMPTY (first pass):
    Identify up to 3 structural deficiencies:
    - Missing assumption nodes (LR-004)
    - Missing alternative hypotheses (LR-005)
    - Missing product sections
    - Weak evidence chains that could be strengthened

  If {{production_verdict}} is NON-EMPTY (refinement pass):
    Only carry forward entries from previous missing_critical that are still
    absent. Do not introduce new missing_critical unless all prior ones are
    resolved (monotonic shrinkage rule).

## Verdict Rules
Apply in order; stop at first match:
  FAIL    — any conclusion lacks a complete evidence chain (LR-001),
            any inference lacks source citations (LR-002),
            or any strength level is miscalibrated (LR-003)
  PARTIAL — all chains valid but assumptions implicit (LR-004),
            alternatives missing (LR-005), or required sections absent
  PASS    — complete argument map with all rules satisfied

## Style
Rule-based and deterministic. Cite the specific rule ID (LR-001 through LR-005)
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
    """Build a Logic_Judge instance with constrained JSON output.

    Uses output_schema to enforce Gemini constrained decoding — the model
    is structurally required to produce ProductionVerdict-shaped JSON at
    the API level, not just instructed to do so via prompt. This prevents
    the class of failures where the judge returns product content or
    arbitrary JSON instead of a verdict (e.g., the BEC scenario failure).
    """
    return Agent(
        name="Logic_Judge",
        description=(
            "Validates the argument map against logic rules LR-001 through LR-005 "
            "(evidence chain completeness, source citations, strength calibration, "
            "assumption explicitness, alternative hypotheses). Returns a structured "
            "ProductionVerdict JSON classifying each element as confirmed, unverified, "
            "or missing, with an overall PASS / PARTIAL / FAIL verdict."
        ),
        model="gemini-2.5-flash",
        instruction=JUDGE_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
        output_key="production_verdict",
        output_schema=ProductionVerdict,
        # The judge only needs the current argument_map and
        # production_verdict from session state — it does not need conversation
        # history. 'none' drops the prior turn history from the model request,
        # reducing token consumption on every judge call without loss of context.
        include_contents="none",
    )


# ---------------------------------------------------------------------------
# Agent 3: Verification_Agent
# ---------------------------------------------------------------------------

# NOTE: Plain string, NOT an f-string — by design.
# {argument_map} and {production_verdict} are ADK state-key template placeholders,
# substituted at runtime by the ADK runner from session state. Do NOT add an
# f-prefix: that would cause Python to evaluate {argument_map} as a Python
# expression at import time, raising NameError. ARGUMENT_INSTRUCTION above is an
# f-string only because it embeds {format_templates_for_prompt()} — a Python call
# that must execute at module load. No such call is needed here.
VERIFICATION_INSTRUCTION = """\
## Context
You are a senior Intelligence Product Editor at ApexCode Solutions.
An intelligence product has been drafted and independently validated by a
Logic Judge. Your job: produce the corrected final product.

## Inputs

Original intelligence product (argument map):
{argument_map}

Logic judge verdict (JSON):
{production_verdict}

The JSON verdict has this structure:
  confirmed_valid   — argument elements that follow the logic rules. Keep these.
  unverified        — elements that violate rules, with suggested corrections. Apply fixes.
  missing_critical  — structural elements the agent missed. Add these.
  verdict           — PASS / PARTIAL / FAIL overall assessment.
  summary           — one-sentence description of the verdict.

## Objective
Produce a corrected intelligence product following these rules exactly:
- Keep all entries in confirmed_valid — preserve their full detail.
- For each entry in unverified: apply the suggested_alternative correction
  (add missing evidence citations, recalibrate strength, extract embedded
  assumptions into explicit nodes, add alternative hypotheses).
- Add all entries in missing_critical with full structural detail
  (assumption nodes with impact-if-wrong, alternative hypotheses with
  rejection rationale, missing product sections).
- Preserve the eight-section structure and node ID conventions.
- If a conclusion's evidence chain was strengthened, update its confidence.

## Style
Match the Argument Mapping Agent's analytical register. Apply corrections
precisely — this is a rule-following edit task, not creative generation.

## Tone
Direct, operational — no hedging, no commentary on the corrections.
Apply them and produce the final product.

## Audience
The dissemination team in Stage 6 who will route this to stakeholders.
The corrected product must be self-contained.

## Response Format
The corrected intelligence product. Structure with these eight sections:

### 1. Executive Summary
### 2. Key Findings
### 3. Evidence Summary
### 4. Analytical Reasoning
### 5. Assumptions and Limitations
### 6. Alternative Hypotheses
### 7. Recommendations
### 8. Appendix: Source List with TLP Markings
"""


def make_verification_agent(before_agent_callback=None, after_agent_callback=None) -> Agent:
    """Build a Verification_Agent instance.

    Uses temperature=0.0 (greedy decoding) — top_p and top_k are not set
    because they have no effect when temperature is zero.
    """
    return Agent(
        name="Verification_Agent",
        description=(
            "Applies Logic Judge corrections to produce the final verified intelligence "
            "product: preserves confirmed-valid elements, fixes unverified elements per "
            "suggested_alternative, and adds all missing_critical structural nodes "
            "(assumptions, alternatives, product sections)."
        ),
        model="gemini-2.5-flash",
        instruction=VERIFICATION_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
        ),
        output_key="verified_product",
        before_agent_callback=before_agent_callback,
        after_agent_callback=after_agent_callback,
        # The verification agent only needs argument_map and
        # production_verdict from state — its instruction already has both
        # via template substitution. Dropping conversation history reduces
        # token consumption on every verification call without loss of context.
        include_contents="none",
    )


# ---------------------------------------------------------------------------
# Loop exit logic — deterministic, no LLM call
#
# The previous Loop_Controller used a full LLM Agent
# (gemini-2.5-flash) just to call check_verdict_and_escalate — a purely
# deterministic operation (read JSON, compare string, set flag). This
# wasted tokens, added latency, and introduced a failure mode where the
# LLM might not call the tool.
#
# Current approach: an after_agent_callback on the LAST agent in the
# SequentialAgent (the Verification_Agent) re-checks THIS iteration's
# verdict and, on a genuine PASS, sets escalate=True so the LoopAgent
# exits. No LLM call needed. See _get_root_agent() for the wiring.
#
# The old tool function below is kept for backward compatibility only;
# it is unused in both shipped paths (run_pipeline uses its own
# post-iteration checks, and the web path uses the after-callback).
# ---------------------------------------------------------------------------


def check_verdict_and_escalate(tool_context: ToolContext) -> dict:
    """
    Read production_verdict from session state.
    If verdict is PASS, set tool_context.actions.escalate = True so the
    enclosing LoopAgent exits after this iteration.

    NOTE: This is kept for backward compatibility but is no longer used in
    the web path. The web path uses _check_loop_exit_callback instead.
    """
    verdict_raw = tool_context.state.get("production_verdict", {})
    try:
        verdict = (
            verdict_raw if isinstance(verdict_raw, dict)
            else json.loads(verdict_raw)
        )
        if verdict.get("verdict") == "PASS":
            tool_context.actions.escalate = True
            return {"status": "PASS", "escalating": True}
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return {"status": "CONTINUING", "escalating": False}


def _check_loop_exit_callback(callback_context) -> None:
    """Deterministic loop exit check — runs as an after_agent_callback on the
    Verification_Agent (the last pipeline agent). No LLM call needed; replaces
    the LLM-based Loop_Controller (~3 Gemini calls saved per pipeline run).

    Reads production_verdict from session state. If verdict is PASS, signals the
    enclosing LoopAgent to exit.

    Two ADK details make the naive version silently fail.
    (1) CallbackContext has NO public `.actions` accessor (only ToolContext does),
        so the previous `callback_context.actions.escalate = True` raised
        AttributeError, which the old broad `except (..., AttributeError)` swallowed.
        We set escalate on `_event_actions` directly — the same EventActions object
        that ADK attaches to any event this callback emits.
    (2) ADK's after_agent_callback handler only emits an event (the carrier for
        escalate) if the callback returns content OR writes to state. escalate
        alone yields no event and is dropped. We write an exit marker to state so
        the event is emitted with the escalate attached.
    Both were why the web loop ran to max_iterations even after a first-pass PASS.
    """
    state = callback_context.state
    verdict_raw = state.get("production_verdict", "")
    if not verdict_raw:
        return None  # No verdict in state yet — nothing to exit on.
    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
    except (json.JSONDecodeError, TypeError):
        return None  # Malformed verdict — continue iterating.
    if isinstance(verdict, dict) and verdict.get("verdict") == "PASS":
        callback_context._event_actions.escalate = True   # (1) set on the real EventActions
        state["loop_exit_verdict"] = "PASS"                # (2) force the event to be emitted
    return None

# ---------------------------------------------------------------------------
# Web-path guardrails — mirrors batch-path post-iteration checks
#
# The batch path (run_pipeline) runs check_verdict_rules()
# and validate_product_tlp() after every iteration, downgrading the verdict
# in state before the next pass. The web path previously had no equivalent —
# a PASS verdict that failed programmatic rule checks would escape undetected.
#
# _apply_web_path_guardrails() closes the gap. It runs as part of
# the after_agent_callback on the Verification_Agent (the last pipeline agent),
# which fires at the END of every LoopAgent iteration. It reads this iteration's
# verdict and argument_map from state, runs the same rule check and TLP
# validation as the batch path, and rewrites production_verdict in state if a
# downgrade is needed. _check_loop_exit_callback then reads the corrected verdict
# and only escalates if it is still PASS. (Previously this ran as a
# before_agent_callback on the Argument_Mapping_Agent, one iteration late and
# with an escalate the LoopAgent never saw.)
# ---------------------------------------------------------------------------


def _apply_web_path_guardrails(callback_context) -> None:
    """
    Apply deterministic guardrails to the web path — mirrors run_pipeline().

    Reads production_verdict and argument_map from session state. If the
    verdict is non-empty (iteration 2+), runs check_verdict_rules() and
    validate_product_tlp(). Downgrades the verdict in state from PASS to
    FAIL if rule violations are detected. Returns None in all cases so the
    LoopAgent iteration proceeds normally after the callback chain completes.
    """
    state = callback_context.state
    verdict_raw = state.get("production_verdict", "")
    if not verdict_raw:
        return None  # No verdict in state (judge did not emit one) — nothing to check.

    try:
        verdict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
    except (json.JSONDecodeError, TypeError):
        return None  # Malformed verdict — let _check_loop_exit_callback handle it.

    argument_map    = state.get("argument_map", "")
    verified_product = state.get("verified_product", "")

    # Deterministic rule check — same logic as batch path.
    rule_issues = check_verdict_rules(verdict, argument_map=argument_map)
    if rule_issues:
        for issue in rule_issues:
            print(f"  [WEB RULE CHECK] {issue}")
        if verdict.get("verdict") == "PASS":
            verdict["verdict"] = "FAIL"
            verdict["summary"] = (
                f"Deterministic rule check failed: {len(rule_issues)} issue(s). "
                f"Verdict downgraded from PASS to FAIL."
            )
            # Write corrected verdict back to state so _check_loop_exit_callback
            # reads the downgraded value and does not trigger early exit.
            state["production_verdict"] = json.dumps(verdict)

    # TLP validation — same logic as batch path. Logged only; does not affect verdict.
    tlp_issues = validate_product_tlp(verified_product)
    if tlp_issues:
        for issue in tlp_issues:
            print(f"  [WEB TLP CHECK] {issue}")

    return None


# ---------------------------------------------------------------------------
# Module-level pipeline + root_agent (for adk web)
#
# TWO EXECUTION TOPOLOGIES EXIST (by design):
#
#   Web path (adk web):
#     LoopAgent wraps SequentialAgent. Loop exit is driven by
#     _check_loop_exit_callback (after_agent_callback on Verification_Agent, the
#     last pipeline agent). Guardrails (_apply_web_path_guardrails) run in the
#     same after-callback, before the exit check, mirroring the batch path's
#     post-iteration sequence and ensuring parity with it.
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
# Lazy initialization — agents and session service are constructed on first
# access, not at import time. This prevents eval scripts (which only need
# factories and Pydantic models) from triggering full pipeline construction
# and SQLite session loading.
# ---------------------------------------------------------------------------

_root_agent = None
_session_service = None


def _get_root_agent() -> LoopAgent:
    """Lazily construct the web pipeline and root_agent on first access.

    Loop exit is handled deterministically by
    _check_loop_exit_callback (no LLM-based Loop_Controller agent needed,
    saving one Gemini call per iteration).

    The web loop previously ran to max_iterations even after a
    first-pass PASS (diverging from the batch path, which breaks on the first
    PASS). Two independent causes, both fixed here and in
    _check_loop_exit_callback:
      (1) escalate was set via `callback_context.actions`, an attribute that does
          NOT exist on CallbackContext (only ToolContext has it), raising
          AttributeError that a broad `except` swallowed — so escalate was never
          set. It is now set on `_event_actions` directly, plus a state write so
          ADK actually emits the escalate-carrying event.
      (2) the check ran as a before_agent_callback on Argument_Mapping_Agent,
          reading the PREVIOUS iteration's verdict, so the earliest possible exit
          was after iteration 2. Moving it to an after_agent_callback on the LAST
          agent (Verification) lets it read THIS iteration's verdict and exit
          after iteration 1, mirroring run_pipeline()'s post-iteration sequence
          and restoring web/batch parity on iteration count.
    """
    global _root_agent
    if _root_agent is None:
        # Before the first agent each iteration: seed any missing state keys.
        def _seed_state_before_callback(callback_context):
            _init_session_state(callback_context)

        # After the last agent each iteration: mirror run_pipeline()'s
        # post-iteration checks. Order is deliberate:
        # 1. _apply_web_path_guardrails — re-check THIS iteration's verdict against
        #    the deterministic rules; downgrade PASS -> FAIL in state on violations.
        # 2. _check_loop_exit_callback  — read the (possibly downgraded) verdict and
        #    set escalate=True only on a genuine PASS, exiting the LoopAgent.
        def _post_iteration_after_callback(callback_context):
            _apply_web_path_guardrails(callback_context)
            _check_loop_exit_callback(callback_context)

        _argument = make_argument_mapping_agent(
            before_agent_callback=_seed_state_before_callback
        )
        _judge = make_judge_agent()
        _verification = make_verification_agent(
            before_agent_callback=_validate_verdict_before_verification,
            after_agent_callback=_post_iteration_after_callback,
        )
        _web_pipeline = SequentialAgent(
            name="Production_Pipeline",
            sub_agents=[_argument, _judge, _verification],
        )
        _root_agent = LoopAgent(
            name="Production_Loop",
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


# Module-level name for adk web discovery. Uses __getattr__ so the LoopAgent
# is only constructed when adk web actually accesses `root_agent`.
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
    verified_analysis: str,
    max_iterations: int = 3,
    production_temp: float = DEFAULT_TEMP,
    production_model: str = DEFAULT_MODEL,
    threat_context: str = "",
    progress_callback=None,
    session_service=None,
) -> tuple[str, list[dict]]:
    """
    Run the self-refining production pipeline against a verified analysis.

    Args:
        verified_analysis: The verified analysis from Stage 4.
        max_iterations:    Maximum number of refinement passes (default 3).
        production_temp:   Sampling temperature for the Argument_Mapping_Agent.
        production_model:  Model ID for the Argument_Mapping_Agent.
        threat_context:    Reserved for future prompt context; accepted but currently unused.
        session_service:   ADK session service to use. If None (default), the
                           lazy singleton is used (persistent SQLite). Pass an
                           InMemorySessionService for batch eval / grid search
                           to avoid SQLite WAL write-lock contention under high
                           concurrency — eval sessions do not need to persist
                           across process restarts.

    Returns:
        (session_id, iterations) where iterations is a list of per-pass dicts:
            {
              "iteration":       int,
              "argument_map":    str,
              "verdict":         dict,
              "verified_product": str,
            }
    """
    _argument_agent     = make_argument_mapping_agent(model=production_model, temperature=production_temp)
    _judge_agent        = make_judge_agent()
    _verification_agent = make_verification_agent()

    _pipeline = SequentialAgent(
        name="Production_Pipeline",
        sub_agents=[_argument_agent, _judge_agent, _verification_agent],
    )
    # Use caller-supplied session service if provided, otherwise fall back to the
    # module-level lazy singleton (persistent SQLite). Callers running many
    # concurrent pipelines (e.g., config_search) should supply InMemorySessionService
    # to avoid SQLite WAL write-lock contention.
    _svc = session_service if session_service is not None else _get_session_service()
    _runner = Runner(
        agent=_pipeline,
        app_name=APP_NAME,
        session_service=_svc,
    )

    session_id = f"stage5_{uuid.uuid4().hex}"

    await _svc.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "verified_analysis":  verified_analysis,
            "argument_map":       "",
            "production_verdict": "",
            "verified_product":   "",
        },
    )

    MAX_RETRIES = 3
    # Per-iteration wall-clock timeout: 3 agents × ~2 min each ≈ 6 min worst case.
    # 10 min is generous; a hung TCP connection to the Gemini API will never raise
    # on its own — asyncio.wait_for() is the only mechanism that unblocks it.
    # asyncio.TimeoutError is a subclass of Exception, so it is caught by the
    # transient-failure handler below and retried with jittered backoff, exactly
    # like API errors and rate-limit responses.
    _ITER_TIMEOUT_S = 600
    iterations: list[dict] = []

    for iteration in range(1, max_iterations + 1):
        # First iteration: send the full analysis as the user message.
        # Subsequent iterations: analysis is already in state; send a minimal trigger.
        user_text = (
            verified_analysis if iteration == 1
            else "Refine the intelligence product based on the judge's feedback in session state."
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
                # Jittered exponential backoff to prevent thundering herd.
                wait = 2 ** attempt * 5 * (0.5 + random.random())
                print(
                    f"  [RETRY {attempt}/{MAX_RETRIES}] Iteration {iteration} "
                    f"failed: {type(exc).__name__}: {exc} — waiting {wait:.0f}s"
                )
                await asyncio.sleep(wait)

        session = await _svc.get_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=session_id,
        )
        verdict_raw = session.state.get("production_verdict", {})
        try:
            # ADK stores output_schema results as dicts when Pydantic decoding
            # succeeds, and as JSON strings when the agent writes raw text.
            # Handle both so json.loads() doesn't raise TypeError on a dict.
            verdict_dict = (
                verdict_raw if isinstance(verdict_raw, dict)
                else json.loads(verdict_raw)
            )
            validated = ProductionVerdict.model_validate(verdict_dict)
            verdict = validated.model_dump()
        except (json.JSONDecodeError, TypeError):
            # Populate unverified with a meaningful entry so the
            # Verification Agent receives actionable feedback instead of an empty
            # verdict that degrades the pipeline to a pass-through.
            print("  [WARN] Judge returned invalid JSON — treating as FAIL")
            verdict = {
                "confirmed_valid": [],
                "unverified": [{
                    "source": "entire argument map",
                    "reason": "Judge returned invalid JSON — full re-validation required.",
                    "suggested_alternative": "Re-generate the argument map with stricter "
                    "adherence to the 8-section format and node ID conventions.",
                }],
                "missing_critical": [],
                "verdict": "FAIL",
                "summary": "Judge output was not valid JSON — Verification Agent "
                "should re-validate the full argument map.",
            }
        except ValidationError as e:
            print(f"  [WARN] Judge verdict failed schema validation: {e}")
            verdict = {
                "confirmed_valid": [],
                "unverified": [{
                    "source": "entire argument map",
                    "reason": f"Judge verdict failed Pydantic schema validation: "
                    f"{str(e)[:200]}. Full re-validation required.",
                    "suggested_alternative": "Re-generate the argument map ensuring "
                    "all structural elements follow logic rules LR-001 through LR-005.",
                }],
                "missing_critical": [],
                "verdict": "FAIL",
                "summary": "Judge output failed Pydantic validation — Verification "
                "Agent should re-validate the full argument map.",
            }

        # Fetch argument map once — used by both rule checker and iterations record.
        argument_map_text = session.state.get("argument_map", "")

        # Deterministic rule check — catches logical errors the LLM judge misses.
        # Passes argument_map_text so LR-001/002/004/005 can be checked against
        # the raw argument map text, not just the verdict fields.
        rule_issues = check_verdict_rules(verdict, argument_map=argument_map_text)
        if rule_issues:
            for issue in rule_issues:
                print(f"  [RULE CHECK] {issue}")
            if verdict.get("verdict") == "PASS":
                verdict["verdict"] = "FAIL"
                verdict["summary"] = (
                    f"Deterministic rule check failed: {len(rule_issues)} issue(s). "
                    f"Verdict downgraded from PASS to FAIL."
                )
                # Write the corrected verdict back to session state.
                # session.state returned by get_session() is a copy — mutating the
                # local `verdict` dict does not update the stored session. Without
                # this write-back, the next iteration's Argument_Mapping_Agent reads
                # {production_verdict} from state and sees the original PASS verdict,
                # causing it to apply Rule 4 ("no new structural changes") and skip
                # the corrections that the rule checker just demanded.
                # append_event with a state_delta is the ADK-supported mechanism for
                # updating session state outside of an agent callback.
                await _svc.append_event(
                    session,
                    _AdkEvent(
                        author="rule_checker",
                        actions=_AdkEventActions(
                            state_delta={"production_verdict": json.dumps(verdict)}
                        ),
                    ),
                )

        # TLP validation — programmatic enforcement of TLP marking rules.
        verified_product_text = session.state.get("verified_product", "")
        tlp_issues = validate_product_tlp(verified_product_text)
        if tlp_issues:
            for issue in tlp_issues:
                print(f"  [TLP CHECK] {issue}")

        # Track convergence dynamics per iteration.
        # The self-refining loop assumes each pass reduces violations, but this
        # is not guaranteed — the Verification_Agent may introduce new violations
        # while fixing old ones, or the judge may re-flag previously confirmed
        # elements. Detect non-monotone regression so callers can observe it.
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

        iterations.append(
            {
                "iteration":             iteration,
                "argument_map":          argument_map_text,
                "verdict":               verdict,
                "verified_product":      verified_product_text,
                "tlp_issues":            tlp_issues,
                "n_unverified":          curr_n_unverified,
                "convergence_regressed": convergence_regressed,
            }
        )

        verdict_label = verdict.get("verdict", "UNKNOWN")
        tlp_tag = f" | TLP issues: {len(tlp_issues)}" if tlp_issues else ""
        print(f"  Iteration {iteration}/{max_iterations}: {verdict_label}{tlp_tag} — {verdict.get('summary', '')}")

        if verdict_label == "PASS":
            break

    return session_id, iterations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Sample input — shared across agent.py and visualize.py to avoid duplication.
# ---------------------------------------------------------------------------

SAMPLE_VERIFIED_ANALYSIS = (
    "## Stage 4 Analysis Results — AiTM Session Hijacking via Evilginx2\n\n"
    "### Structured Analytic Technique: Analysis of Competing Hypotheses (ACH)\n\n"
    "**Hypotheses Evaluated:**\n"
    "- H1: Adversary-in-the-Middle (AiTM) session hijacking via Evilginx2 phishing\n"
    "- H2: Legitimate partner employee using VPN/proxy from unusual location\n"
    "- H3: Credential stuffing using previously breached credentials\n\n"
    "**Evidence Assessment:**\n"
    "- E-001: Okta System Log — user.session.start reusing the partner developer's existing "
    "Okta session from Tor exit node IP 185.220.101.42, an anonymizing exit node not "
    "previously tied to this account. Source: identity_provider. "
    "Timestamp: 2025-03-15 08:00–09:30 UTC. Confidence: HIGH.\n"
    "- E-002: SpyCloud — Recaptured Okta session cookie for partner user matching "
    "active session format. Source: breach_intelligence. "
    "Timestamp: 2025-03-14 (stealer log date). Confidence: HIGH.\n"
    "- E-003: Proofpoint Email Security — click.permitted on URL matching Evilginx2 "
    "phishing page pattern targeting partner company domain. Source: email_security. "
    "Timestamp: 2025-03-14 16:30 UTC. Confidence: HIGH.\n"
    "- E-004: GitHub Audit Log — git.clone of the two Project Phoenix repos (/phoenix-core, "
    "/phoenix-api) from IP 185.220.101.42 within 45 minutes of Okta session start, with no "
    "comparable clone of the other 40-plus accessible repos. Source: version_control. "
    "Timestamp: 2025-03-15 08:45–09:30 UTC. Confidence: HIGH.\n"
    "- E-005: CrowdStrike Falcon — No endpoint detection triggered, suggesting "
    "session-level access without malware deployment. Source: edr_xdr. "
    "Timestamp: 2025-03-15. Confidence: MEDIUM (absence of evidence).\n\n"
    "**ACH Matrix Result:**\n"
    "- H1 (AiTM via Evilginx2): CONSISTENT with all 5 evidence items. "
    "Strongest support from E-001 + E-002 + E-003 temporal sequence.\n"
    "- H2 (Legitimate VPN): INCONSISTENT with E-002 (stolen cookie in stealer log) "
    "and E-003 (phishing click). Partner confirmed no Tor VPN policy.\n"
    "- H3 (Credential stuffing): INCONSISTENT with E-002 (a recaptured session cookie "
    "indicates cookie replay, not password guessing) and E-003 (a targeted Evilginx2 "
    "phishing click, not indiscriminate credential replay).\n\n"
    "**Key Assumptions Identified:**\n"
    "- The Okta session from the Tor exit IP was not legitimately established\n"
    "- SpyCloud stealer log data is current and not from a historical dump\n"
    "- Partner organization does not authorize Tor exit node usage\n\n"
    "**Impact Assessment:**\n"
    "- The two Project Phoenix repositories cloned — targeted source code exfiltration\n"
    "- Session cookie reuse suggests adversary has persistent access capability\n"
    "- No MFA bypass needed — session-level access is the evasion technique\n\n"
    "**Recommended Confidence: HIGH** — Three independent evidence streams from "
    "three source categories converge on H1.\n"
)


async def main() -> None:

    print("=" * 70)
    print("PRODUCTION PIPELINE — Stage 5: Intel Cycle")
    print("ApexCode Solutions | Threat Intelligence")
    print("=" * 70)
    print()

    _, iterations = await run_pipeline(
        SAMPLE_VERIFIED_ANALYSIS,
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
        print(f"ITERATION {n} — Argument Map")
        print("=" * 70)
        print(it["argument_map"][:2000])

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
