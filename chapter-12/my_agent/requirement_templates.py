"""
QIR templates and transformation rules for the Feedback Pipeline.

Defines the closed universe of follow-on QIR fields, scope classifications,
priority levels, and transformation rules. The Compliance Judge validates
every generated QIR against these templates.

Catalog sections:
  QIR_TEMPLATE           -- required fields for every follow-on QIR
  SCOPE_TYPES            -- 4 scope classifications with definitions and examples
  PRIORITY_LEVELS        -- 3 priority tiers with justification criteria
  TRANSFORMATION_RULES   -- 6 rules governing feedback-to-QIR decomposition

Total: 9 required fields, 4 scope types, 3 priority levels, 6 transformation rules.

Schema versioning:
  TEMPLATE_VERSION is embedded in best_config.json (the only artifact currently
  version-checked at load time). Any change to QIR_TEMPLATE, SCOPE_TYPES,
  PRIORITY_LEVELS, or TRANSFORMATION_RULES requires a version bump so stale
  artifacts can be detected and invalidated. Bump the patch segment for additive
  changes (new fields, new rules); bump minor for behavioral changes (field
  renames, rule threshold changes); bump major for structural rewrites.
"""

import re

# Schema version for the feedback pipeline templates.
# Increment when QIR_TEMPLATE, SCOPE_TYPES, PRIORITY_LEVELS, or
# TRANSFORMATION_RULES change. best_config.json embeds this value so a
# config produced under an old schema is detectable at load time.
TEMPLATE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# QIR Template — required fields for every follow-on QIR
# ---------------------------------------------------------------------------

QIR_TEMPLATE = {
    "qir_id": {
        "name": "QIR Identifier",
        "type": "str",
        "description": (
            "Unique identifier for the follow-on QIR. Format: FP-NNN where NNN "
            "is a zero-padded sequence number. The prefix FP distinguishes "
            "follow-on QIRs from original QIRs (which use QIR- prefix)."
        ),
        "format": "FP-NNN",
        "example": "FP-001",
    },
    "originator": {
        "name": "Originator",
        "type": "str",
        "description": (
            "Who asked the question or raised the concern. Must be a role "
            "title (e.g., 'CISO', 'SOC Manager', 'General Counsel') or a "
            "named individual. Generic attributions like 'stakeholder' or "
            "'leadership' are insufficient."
        ),
        "example": "CISO",
    },
    "raw_feedback": {
        "name": "Raw Feedback",
        "type": "str",
        "description": (
            "Verbatim stakeholder question or concern, preserved exactly as "
            "received. No paraphrasing, no cleanup. This is the audit trail "
            "linking the follow-on QIR to the original feedback."
        ),
        "example": "Could 50 other vendors be compromised the same way?",
    },
    "refined_requirement": {
        "name": "Refined Requirement",
        "type": "str",
        "description": (
            "Structured intelligence requirement derived from the raw feedback. "
            "Must be a formal requirement statement, not a paraphrase of the "
            "question. Should specify: what intelligence is needed, what entity "
            "or scope it covers, and what the output should enable the consumer "
            "to decide or act on."
        ),
        "example": (
            "Determine whether the AiTM session hijacking technique used against "
            "DevPartner, Inc has been employed against any of the remaining 49 partner "
            "development firms with Okta SSO integration, using a 90-day "
            "retroactive hunt across authentication telemetry."
        ),
    },
    "scope": {
        "name": "Scope Classification",
        "type": "Literal['EXPANSION', 'DEEPENING', 'PIVOT', 'VALIDATION']",
        "description": (
            "Classification of how this follow-on QIR relates to the original "
            "investigation. Must be one of the four defined scope types. "
            "Classification must match the actual nature of the question — "
            "see SCOPE_TYPES for definitions and distinguishing criteria."
        ),
        "example": "EXPANSION",
    },
    "temporal_window": {
        "name": "Temporal Window",
        "type": "str",
        "description": (
            "Explicit time scope for the intelligence requirement. Must specify "
            "either a retroactive hunt window (e.g., '90-day retroactive hunt') "
            "or a continuous monitoring mandate (e.g., 'continuous monitoring, "
            "30-day review cycle'). Implied or vague temporal references like "
            "'recent' or 'ongoing' are insufficient."
        ),
        "example": "90-day retroactive hunt across partner authentication logs",
    },
    "priority": {
        "name": "Priority",
        "type": "Literal['IMMEDIATE', 'ROUTINE', 'DEFERRED']",
        "description": (
            "Urgency classification for the follow-on QIR. Must be one of "
            "IMMEDIATE, ROUTINE, or DEFERRED. Every priority assignment must "
            "include an explicit justification grounded in operational impact "
            "— see PRIORITY_LEVELS for justification criteria."
        ),
        "example": "IMMEDIATE",
    },
    "priority_justification": {
        "name": "Priority Justification",
        "type": "str",
        "description": (
            "Explicit justification for the priority assignment, grounded in "
            "operational impact. Must cite at least one criterion from the "
            "corresponding PRIORITY_LEVELS entry. Unjustified priorities "
            "are invalid — 'because the CISO asked' is not a justification; "
            "'active threat actor with ongoing access to partner SSO' is."
        ),
        "example": (
            "Active threat actor with ongoing access — the same AiTM technique "
            "may be in use against other partners, and each day without a "
            "retroactive hunt extends the window of undetected compromise."
        ),
    },
    "linked_qir": {
        "name": "Linked QIR",
        "type": "str",
        "description": (
            "The original QIR this follow-on traces to. Must reference a valid "
            "QIR identifier from the preceding intelligence cycle, using the "
            "QIR- prefix format. This field maintains the audit chain from "
            "feedback back through the cycle."
        ),
        "format": "QIR-YYYY-NNNN",
        "example": "QIR-2025-0042",
    },
}

REQUIRED_FIELDS = list(QIR_TEMPLATE.keys())

# ---------------------------------------------------------------------------
# Scope Types — 4 classifications
# ---------------------------------------------------------------------------

SCOPE_TYPES = {
    "EXPANSION": {
        "label": "EXPANSION",
        "description": (
            "Broader scope — extends the investigation to additional entities, "
            "systems, or populations not covered by the original QIR. The "
            "original finding is taken as established; the question is whether "
            "it applies more widely."
        ),
        "distinguishing_criteria": (
            "The question asks about MORE of something — more vendors, more "
            "systems, more users, more time periods. The analytical method "
            "stays the same; the target set grows."
        ),
        "example_questions": [
            "Could 50 other vendors be compromised the same way?",
            "Are there other attack vectors we haven't monitored?",
            "What's our exposure if the stolen code is published?",
        ],
        "typical_temporal_window": "Retroactive hunt (30-90 days)",
        "typical_priority": "IMMEDIATE or ROUTINE depending on blast radius",
    },
    "DEEPENING": {
        "label": "DEEPENING",
        "description": (
            "More detail — drills into a specific finding from the original "
            "investigation to extract additional information. The scope stays "
            "the same; the resolution increases."
        ),
        "distinguishing_criteria": (
            "The question asks HOW or HOW LONG about something already known. "
            "It does not expand the target set or change direction — it asks "
            "for more granularity on an existing finding."
        ),
        "example_questions": [
            "How long did the attacker have access before we detected it?",
            "Can we detect if the attacker planted backdoors in our repos?",
            "What specific data was accessed during the compromised session?",
        ],
        "typical_temporal_window": "Retroactive analysis (full incident window)",
        "typical_priority": "IMMEDIATE if active threat, ROUTINE otherwise",
    },
    "PIVOT": {
        "label": "PIVOT",
        "description": (
            "New direction — changes the investigation focus to a different "
            "domain, stakeholder group, or concern not addressed by the "
            "original QIR. The original finding may be the trigger, but the "
            "new question addresses a fundamentally different problem space."
        ),
        "distinguishing_criteria": (
            "The question introduces a new domain (legal, regulatory, business, "
            "communications) or asks about a consequence rather than the "
            "technical finding itself. The analytical techniques and data "
            "sources required are substantially different from the original QIR."
        ),
        "example_questions": [
            "Do we need to notify affected customers under GDPR?",
            "Should we delay the Q3 release for a security audit?",
            "What do we say if a journalist asks about the breach?",
            "Should we terminate the partner relationship or remediate?",
        ],
        "typical_temporal_window": "Time-bounded assessment (specific decision deadline)",
        "typical_priority": "Varies — legal/regulatory may be IMMEDIATE",
    },
    "VALIDATION": {
        "label": "VALIDATION",
        "description": (
            "Confirm or deny — tests a specific claim, hypothesis, or proposed "
            "countermeasure. The question has a binary or bounded answer: does "
            "this work, is this true, can this be done."
        ),
        "distinguishing_criteria": (
            "The question asks WHETHER something is true or WHETHER a specific "
            "action would be effective. It proposes a testable hypothesis or "
            "countermeasure and asks for evaluation."
        ),
        "example_questions": [
            "Can we prevent session hijacking entirely with FIDO2?",
            "Is our current MFA implementation vulnerable to AiTM?",
            "Would network segmentation have prevented lateral movement?",
        ],
        "typical_temporal_window": "Evaluation period (technology assessment or hypothesis test)",
        "typical_priority": "ROUTINE unless blocking an active remediation",
    },
}

# ---------------------------------------------------------------------------
# Priority Levels — 3 tiers with justification criteria
# ---------------------------------------------------------------------------

PRIORITY_LEVELS = {
    "IMMEDIATE": {
        "label": "IMMEDIATE",
        "description": (
            "Active threat, ongoing exposure, or regulatory deadline requires "
            "this QIR to be processed before routine work. The delay cost is "
            "measured in continued compromise or missed compliance windows."
        ),
        "justification_criteria": [
            "Active threat actor with ongoing access",
            "Regulatory notification deadline within 72 hours",
            "Confirmed data exposure with unknown blast radius",
            "Countermeasure decision blocking active incident response",
            "Executive decision pending on this intelligence",
        ],
        "action_guidance": (
            "Enter Stage 1 immediately. Assign dedicated analyst. "
            "Results expected within current operational period."
        ),
    },
    "ROUTINE": {
        "label": "ROUTINE",
        "description": (
            "Important but not time-critical. The threat is contained or the "
            "question is strategic rather than operational. Can be queued behind "
            "IMMEDIATE QIRs without increasing risk."
        ),
        "justification_criteria": [
            "Threat contained but root cause analysis incomplete",
            "Strategic question about defensive posture improvement",
            "Technology evaluation for future countermeasure deployment",
            "Broader scope assessment with no active exposure",
            "Post-incident lesson learned investigation",
        ],
        "action_guidance": (
            "Queue for next available analyst cycle. Results expected within "
            "standard processing SLA."
        ),
    },
    "DEFERRED": {
        "label": "DEFERRED",
        "description": (
            "Low urgency — informational, speculative, or dependent on other "
            "QIRs completing first. Can be scheduled for future cycles without "
            "operational impact."
        ),
        "justification_criteria": [
            "Speculative scenario with no current indicators",
            "Dependent on results from another active QIR",
            "Long-term strategic planning question",
            "Historical analysis with no active threat component",
            "Nice-to-know rather than need-to-know",
        ],
        "action_guidance": (
            "Schedule for future intelligence cycle. May be promoted to "
            "ROUTINE if dependencies resolve or new indicators emerge."
        ),
    },
}

# ---------------------------------------------------------------------------
# Transformation Rules — governing feedback-to-QIR decomposition
# ---------------------------------------------------------------------------

TRANSFORMATION_RULES = [
    {
        "rule_id": "TR-001",
        "name": "Atomic Decomposition",
        "description": (
            "Each distinct question or concern in the stakeholder feedback "
            "becomes a separate QIR. A single piece of feedback may produce "
            "multiple QIRs if it contains multiple distinct questions."
        ),
        "violation_example": (
            "Stakeholder asks 'How long did the attacker have access AND do "
            "we need to notify customers?' — this must be split into two QIRs: "
            "one DEEPENING (dwell time) and one PIVOT (notification obligation)."
        ),
    },
    {
        "rule_id": "TR-002",
        "name": "Linked QIR Requirement",
        "description": (
            "Every follow-on QIR must link to the original QIR it extends. "
            "The linked_qir field must reference a valid QIR identifier from "
            "the preceding intelligence cycle. Orphaned QIRs that do not trace "
            "back to an original requirement break the audit chain."
        ),
        "violation_example": (
            "Follow-on QIR about vendor compromise has linked_qir set to "
            "empty string or 'N/A' instead of the actual original QIR ID."
        ),
    },
    {
        "rule_id": "TR-003",
        "name": "Scope Classification Required",
        "description": (
            "Every follow-on QIR must be classified into exactly one scope "
            "type: EXPANSION, DEEPENING, PIVOT, or VALIDATION. The scope must "
            "match the actual nature of the question — see SCOPE_TYPES for "
            "distinguishing criteria. Misclassification distorts downstream "
            "prioritization and analyst assignment."
        ),
        "violation_example": (
            "Question 'Do we need to notify customers under GDPR?' classified "
            "as EXPANSION when it is clearly a PIVOT — the question introduces "
            "a legal/regulatory domain not covered by the original technical QIR."
        ),
    },
    {
        "rule_id": "TR-004",
        "name": "Priority Justification",
        "description": (
            "Every priority assignment must include explicit justification "
            "grounded in operational impact. The justification must cite at "
            "least one criterion from the corresponding PRIORITY_LEVELS entry. "
            "Unjustified priorities default to ROUTINE."
        ),
        "violation_example": (
            "QIR set to IMMEDIATE priority with no justification, or with "
            "justification like 'because the CISO asked' rather than citing "
            "operational impact (active threat, regulatory deadline, etc.)."
        ),
    },
    {
        "rule_id": "TR-005",
        "name": "Temporal Window Explicitness",
        "description": (
            "Every QIR must specify an explicit temporal window: either a "
            "retroactive hunt window with a specific duration (e.g., '90-day "
            "retroactive hunt') or a continuous monitoring mandate with a "
            "review cycle (e.g., 'continuous monitoring, 30-day review cycle'). "
            "Vague references like 'recent' or 'ongoing' are insufficient."
        ),
        "violation_example": (
            "Temporal window set to 'ongoing monitoring' without specifying "
            "a review cycle, or 'look at recent logs' without defining the "
            "time boundary."
        ),
    },
    {
        "rule_id": "TR-006",
        "name": "Non-Actionable Feedback Filter",
        "description": (
            "Feedback that contains no actionable question or intelligence "
            "requirement (e.g., praise, acknowledgments, status updates) should "
            "produce zero QIRs. The transformation agent must not fabricate "
            "requirements from non-actionable input."
        ),
        "violation_example": (
            "Stakeholder says 'Great work on the briefing, very thorough' — "
            "this should produce 0 QIRs. Generating a QIR like 'Validate "
            "briefing thoroughness' from praise is fabrication."
        ),
    },
]


# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------


def format_templates_for_prompt() -> str:
    """
    Format QIR_TEMPLATE, SCOPE_TYPES, PRIORITY_LEVELS, and
    TRANSFORMATION_RULES as a structured text block for injection into
    agent instructions.
    """
    lines: list[str] = []

    lines.append("QIR TEMPLATE — REQUIRED FIELDS")
    lines.append("-" * 60)
    for field_id, field in QIR_TEMPLATE.items():
        lines.append(f"* {field['name']} ({field_id}) [{field['type']}]")
        lines.append(f"  {field['description']}")
        lines.append(f"  Example: {field['example']}")
        lines.append("")

    lines.append("SCOPE TYPES")
    lines.append("-" * 60)
    for scope_id, scope in SCOPE_TYPES.items():
        lines.append(f"* {scope['label']}: {scope['description']}")
        lines.append(f"  Distinguishing criteria: {scope['distinguishing_criteria']}")
        lines.append(f"  Typical temporal window: {scope['typical_temporal_window']}")
        lines.append(f"  Typical priority: {scope['typical_priority']}")
        lines.append("  Example questions:")
        for q in scope["example_questions"]:
            lines.append(f"    - {q}")
        lines.append("")

    lines.append("PRIORITY LEVELS")
    lines.append("-" * 60)
    for level in PRIORITY_LEVELS.values():
        lines.append(f"* {level['label']}: {level['description']}")
        lines.append(f"  Action guidance: {level['action_guidance']}")
        lines.append("  Justification criteria:")
        for crit in level["justification_criteria"]:
            lines.append(f"    - {crit}")
        lines.append("")

    lines.append("TRANSFORMATION RULES")
    lines.append("-" * 60)
    for rule in TRANSFORMATION_RULES:
        lines.append(f"* {rule['rule_id']}: {rule['name']}")
        lines.append(f"  {rule['description']}")
        lines.append(f"  Violation example: {rule['violation_example']}")
        lines.append("")

    return "\n".join(lines)


# Compiled patterns for format validation.
_QIR_ID_PATTERN = re.compile(r"^FP-\d{3}$")
_LINKED_QIR_PATTERN = re.compile(r"^QIR-\d{4}-\d{4}$")


def validate_qir_fields(qir: dict) -> list[str]:
    """
    Deterministic check: validates that a QIR dict contains all required
    fields, that constrained fields have valid values, and that formatted
    fields match their expected patterns.

    Args:
        qir: A dict representing a single follow-on QIR.

    Returns:
        List of violation strings. Empty = all required fields present and valid.
    """
    violations = []

    # Check required fields are present and non-empty.
    for field_id in REQUIRED_FIELDS:
        value = qir.get(field_id)
        if value is None or (isinstance(value, str) and not value.strip()):
            violations.append(
                f"Missing required field: '{field_id}' "
                f"({QIR_TEMPLATE[field_id]['name']})"
            )

    # Check qir_id format (FP-NNN).
    qir_id = qir.get("qir_id", "")
    if qir_id and not _QIR_ID_PATTERN.match(qir_id):
        violations.append(
            f"Invalid qir_id format: '{qir_id}' — must match FP-NNN "
            f"(e.g., 'FP-001')"
        )

    # Check linked_qir format (QIR-YYYY-NNNN).
    linked_qir = qir.get("linked_qir", "")
    if linked_qir and not linked_qir.startswith("QIR-"):
        violations.append(
            f"Invalid linked_qir format: '{linked_qir}' — must start with "
            f"'QIR-' prefix (e.g., 'QIR-2025-0042')"
        )

    # Check scope is a valid value.
    scope = qir.get("scope", "")
    if scope and scope not in SCOPE_TYPES:
        violations.append(
            f"Invalid scope: '{scope}' — must be one of "
            f"{', '.join(SCOPE_TYPES.keys())}"
        )

    # Check priority is a valid value.
    priority = qir.get("priority", "")
    if priority and priority not in PRIORITY_LEVELS:
        violations.append(
            f"Invalid priority: '{priority}' — must be one of "
            f"{', '.join(PRIORITY_LEVELS.keys())}"
        )

    return violations


def get_scope_type(scope_id: str) -> dict | None:
    """Look up a scope type by its ID. Returns None if not found."""
    return SCOPE_TYPES.get(scope_id)


def get_priority_level(level: str) -> dict | None:
    """Look up a priority level by its label. Returns None if not found."""
    return PRIORITY_LEVELS.get(level)


# ---------------------------------------------------------------------------
# Shared metrics computation — single source of truth for P/C/F1
#
# Used by the notebook's gs-run cell (grid-search per-run F1). Kept here as
# shared infrastructure so a formula change lives in exactly one place.
# ---------------------------------------------------------------------------


def compute_verdict_metrics(verdict: dict) -> dict:
    """Compute judge-compliance metrics from a single verdict dict.

    Args:
        verdict: A JudgeVerdict-shaped dict with confirmed_valid,
                 unverified, missing_critical, and verdict fields.

    Returns:
        Dict with precision, coverage, f1, relevance (all as percentages),
        and counts n_valid, n_unverified, n_missing.
    """
    n_v = len(verdict.get("confirmed_valid", []))
    n_u = len(verdict.get("unverified", []))
    n_m = len(verdict.get("missing_critical", []))

    precision = round(n_v / (n_v + n_u) * 100, 1) if (n_v + n_u) > 0 else 0.0
    coverage = round(n_v / (n_v + n_m) * 100, 1) if (n_v + n_m) > 0 else 0.0
    f1 = (
        round(2 * precision * coverage / (precision + coverage), 1)
        if (precision + coverage) > 0
        else 0.0
    )

    n_relevant = sum(
        1
        for s in verdict.get("confirmed_valid", [])
        if s.get("relevance") in ("ESSENTIAL", "USEFUL")
    )
    relevance = round(n_relevant / n_v * 100, 1) if n_v > 0 else 0.0

    return {
        "precision": precision,
        "coverage": coverage,
        "f1": f1,
        "relevance": relevance,
        "n_valid": n_v,
        "n_unverified": n_u,
        "n_missing": n_m,
    }


if __name__ == "__main__":
    n_fields = len(QIR_TEMPLATE)
    n_scopes = len(SCOPE_TYPES)
    n_priorities = len(PRIORITY_LEVELS)
    n_rules = len(TRANSFORMATION_RULES)
    print(
        f"Feedback schemas: {n_fields} QIR fields, "
        f"{n_scopes} scope types, {n_priorities} priority levels, "
        f"{n_rules} transformation rules"
    )
