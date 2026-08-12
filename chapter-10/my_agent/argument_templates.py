"""
Argument mapping templates and logic rules for the Production Pipeline.

Defines the closed universe of argument node types, inference strength levels,
structural logic rules, and required product sections. The Logic Judge validates
every evidence chain, inference strength, and structural element against these
templates.

Catalog sections:
  NODE_TYPES         — 4 node types with required fields and validation rules
  STRENGTH_LEVELS    — WEAK / MODERATE / STRONG with minimum evidence requirements
  LOGIC_RULES        — 5 rules governing argument structure and completeness
  PRODUCT_SECTIONS   — required sections in the final intelligence product

Total: 4 node types, 3 strength levels, 5 logic rules, 8 product sections.

Schema versioning:
  TEMPLATE_VERSION is embedded in best_config.json when the grid search runs
  (no result artifacts ship with the repo). Any change to NODE_TYPES, STRENGTH_LEVELS,
  LOGIC_RULES, or PRODUCT_SECTIONS requires a version bump so stale artifacts
  can be detected and invalidated. Bump the patch segment for additive changes
  (new fields, new sections); bump minor for behavioral changes (rule threshold
  changes, field renames); bump major for structural rewrites.
"""

# Schema version for the argument mapping templates.
# Increment when NODE_TYPES, STRENGTH_LEVELS, LOGIC_RULES, or PRODUCT_SECTIONS
# change. best_config.json (written when the grid search runs) embeds this
# value so stale results from an old schema are detectable at load time.
TEMPLATE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Node Types
# ---------------------------------------------------------------------------

NODE_TYPES = {
    "evidence_node": {
        "name": "Evidence Node",
        "description": (
            "Atomic observed fact from collection and processing stages. "
            "Represents a single piece of evidence tied to a specific source "
            "and time window. Evidence nodes are the foundation of all "
            "inferences and conclusions — nothing can be asserted without "
            "tracing back to at least one evidence node."
        ),
        "required_fields": ["source", "timestamp_range", "description", "confidence"],
        "confidence_values": ["HIGH", "MEDIUM", "LOW"],
        "example": {
            "source": "Okta System Log",
            "timestamp_range": "2025-03-15 08:00 – 2025-03-15 09:30 UTC",
            "description": (
                "user.session.start reusing an existing Okta session from IP "
                "185.220.101.42 (Tor exit node), an anonymizing exit node not "
                "previously tied to this account."
            ),
            "confidence": "HIGH",
        },
    },
    "inference_node": {
        "name": "Inference Node",
        "description": (
            "Logical step connecting one or more evidence nodes to a claim. "
            "Each inference must explicitly cite the evidence that supports it "
            "and state the reasoning chain. Strength is determined by the "
            "number and diversity of supporting evidence nodes."
        ),
        "required_fields": ["claim", "supporting_evidence", "reasoning", "strength"],
        "strength_values": ["STRONG", "MODERATE", "WEAK"],
        "example": {
            "claim": (
                "The Okta session was established via stolen session cookie "
                "from an AiTM phishing attack, not through legitimate authentication."
            ),
            "supporting_evidence": [
                "E-001: Okta session reuse from Tor exit node",
                "E-002: SpyCloud stealer log with Okta session cookie",
                "E-003: Proofpoint click.permitted on Evilginx2 phishing URL",
            ],
            "reasoning": (
                "Three independent signals from three source categories "
                "(identity_provider, breach_intelligence, email_security) "
                "converge on AiTM session hijacking. The temporal sequence "
                "(phishing click → cookie theft → session reuse) is consistent "
                "with documented Evilginx2 attack flow."
            ),
            "strength": "STRONG",
        },
    },
    "conclusion_node": {
        "name": "Conclusion Node",
        "description": (
            "Top-level assessment synthesizing inferences into an actionable "
            "finding. Every conclusion must trace to at least two independent "
            "evidence nodes through its supporting inferences. Key assumptions "
            "and alternative hypotheses must be stated explicitly."
        ),
        "required_fields": [
            "assessment", "confidence", "supporting_inferences",
            "key_assumptions", "alternatives_considered",
        ],
        "confidence_values": ["HIGH", "MEDIUM", "LOW"],
        "example": {
            "assessment": (
                "With HIGH confidence, a threat actor used Evilginx2 AiTM proxy "
                "phishing to steal an active Okta session cookie from a partner "
                "developer, then reused it to access GitHub repositories without "
                "triggering a new authentication event."
            ),
            "confidence": "HIGH",
            "supporting_inferences": [
                "I-001: AiTM session hijacking via stolen cookie",
                "I-002: Unauthorized GitHub access from hijacked session",
            ],
            "key_assumptions": [
                "A-001: The Okta session was not a legitimate session "
                "from the partner employee using a VPN or proxy.",
            ],
            "alternatives_considered": [
                "ALT-001: Legitimate partner employee using VPN — rejected: "
                "the IP is a known Tor exit node, partner confirmed no "
                "authorized VPN policy allowing Tor usage.",
            ],
        },
    },
    "assumption_node": {
        "name": "Assumption Node",
        "description": (
            "Unstated belief the argument depends on. Must be made explicit "
            "so consumers can evaluate whether the argument holds if the "
            "assumption is wrong. Each assumption states what would change "
            "in the assessment if it were false."
        ),
        "required_fields": ["assumption", "if_wrong_impact", "testable"],
        "example": {
            "assumption": (
                "The Okta session from the Tor exit IP was not a legitimate "
                "session from the partner employee using an anonymization tool."
            ),
            "if_wrong_impact": (
                "If the session was legitimate, the entire AiTM finding "
                "collapses. The GitHub access would be authorized, and the "
                "SpyCloud credential hit would be a coincidental breach "
                "exposure unrelated to this incident."
            ),
            "testable": True,
        },
    },
}

# ---------------------------------------------------------------------------
# Inference Strength Levels
# ---------------------------------------------------------------------------

STRENGTH_LEVELS = {
    "WEAK": {
        "label": "WEAK",
        "description": (
            "Single evidence source, single source category. Inference is "
            "plausible but unconfirmed. Requires additional evidence before "
            "the supported conclusion can be acted upon."
        ),
        "minimum_evidence_nodes": 1,
        "minimum_source_categories": 1,
        "action_guidance": (
            "Flag for continued collection. Do not base conclusions solely "
            "on WEAK inferences without explicit caveat."
        ),
    },
    "MODERATE": {
        "label": "MODERATE",
        "description": (
            "Two independent evidence nodes from at least two different source "
            "categories. Inference is supported but would benefit from "
            "additional corroboration."
        ),
        "minimum_evidence_nodes": 2,
        "minimum_source_categories": 2,
        "action_guidance": (
            "Supports a MEDIUM-confidence conclusion. Brief threat hunt team. "
            "Initiate targeted collection on related signals."
        ),
    },
    "STRONG": {
        "label": "STRONG",
        "description": (
            "Three or more corroborating evidence nodes from three or more "
            "different source categories. Inference is well-supported and "
            "the supported conclusion can drive operational decisions."
        ),
        "minimum_evidence_nodes": 3,
        "minimum_source_categories": 3,
        "action_guidance": (
            "Supports a HIGH-confidence conclusion. Escalate to incident "
            "response. Initiate containment assessment."
        ),
    },
}

# ---------------------------------------------------------------------------
# Logic Rules
# ---------------------------------------------------------------------------

LOGIC_RULES = [
    {
        "rule_id": "LR-001",
        "name": "Evidence Chain Completeness",
        "description": (
            "Every conclusion must trace to at least 2 independent evidence "
            "nodes through its supporting inferences. A conclusion supported "
            "by a single evidence node — even through multiple inferences — "
            "does not meet the minimum evidence standard."
        ),
        "violation_example": (
            "Conclusion 'AiTM attack confirmed with HIGH confidence' supported "
            "by one inference which itself cites only one evidence node (the "
            "Okta session anomaly). Missing independent corroboration."
        ),
    },
    {
        "rule_id": "LR-002",
        "name": "Source Citation Requirement",
        "description": (
            "Every inference must cite its supporting evidence by source name "
            "and evidence node identifier. Inferences without explicit source "
            "citations are analytically ungrounded and cannot support conclusions."
        ),
        "violation_example": (
            "Inference states 'credential theft is likely' without citing "
            "which evidence node or source supports this claim."
        ),
    },
    {
        "rule_id": "LR-003",
        "name": "Strength Calibration",
        "description": (
            "Inference strength must match the evidence base. STRONG requires "
            "3+ corroborating evidence nodes from 3+ different source categories. "
            "MODERATE requires 2+ from 2+ categories. WEAK is 1 from 1. "
            "Overclaiming strength inflates downstream conclusion confidence."
        ),
        "violation_example": (
            "Inference labeled STRONG but supported by only 2 evidence nodes "
            "from 2 source categories. Should be MODERATE at best."
        ),
    },
    {
        "rule_id": "LR-004",
        "name": "Assumption Explicitness",
        "description": (
            "Key assumptions must be stated as explicit assumption nodes, not "
            "embedded in inference reasoning. If an inference's validity depends "
            "on an unstated condition, that condition must be extracted into a "
            "separate assumption node with its impact-if-wrong documented."
        ),
        "violation_example": (
            "Inference reasoning contains 'assuming the IP is not a corporate "
            "VPN exit point' without a corresponding assumption node that "
            "documents what happens to the conclusion if this assumption is wrong."
        ),
    },
    {
        "rule_id": "LR-005",
        "name": "Alternative Hypothesis Consideration",
        "description": (
            "Each conclusion must consider at least one alternative hypothesis "
            "and state the reason for its rejection. Alternative hypotheses "
            "must be plausible explanations for the same evidence, not "
            "strawman alternatives. Rejection reasons must cite specific "
            "evidence or logical grounds."
        ),
        "violation_example": (
            "Conclusion states 'AiTM attack confirmed' without considering "
            "the alternative that the session anomaly is a legitimate VPN "
            "usage pattern by the partner organization."
        ),
    },
]

# ---------------------------------------------------------------------------
# Required Product Sections
# ---------------------------------------------------------------------------

PRODUCT_SECTIONS = [
    {
        "section_id": "executive_summary",
        "name": "Executive Summary",
        "description": (
            "2-3 sentence overview: what happened, confidence level, "
            "recommended action. Written for decision-makers, not analysts."
        ),
        "required": True,
    },
    {
        "section_id": "key_findings",
        "name": "Key Findings",
        "description": (
            "Numbered list of conclusion nodes with confidence levels. "
            "Each finding references its supporting inferences by ID."
        ),
        "required": True,
    },
    {
        "section_id": "evidence_summary",
        "name": "Evidence Summary",
        "description": (
            "All evidence nodes grouped by source. Each entry includes "
            "source name, timestamp range, description, and confidence."
        ),
        "required": True,
    },
    {
        "section_id": "analytical_reasoning",
        "name": "Analytical Reasoning",
        "description": (
            "Inference chains from evidence to conclusions. Each inference "
            "cites supporting evidence nodes, states reasoning, and declares "
            "strength level (STRONG/MODERATE/WEAK)."
        ),
        "required": True,
    },
    {
        "section_id": "assumptions_limitations",
        "name": "Assumptions and Limitations",
        "description": (
            "All assumption nodes listed with their if-wrong impact. "
            "Flags which assumptions are testable vs. untestable."
        ),
        "required": True,
    },
    {
        "section_id": "alternative_hypotheses",
        "name": "Alternative Hypotheses",
        "description": (
            "Alternative explanations for the observed evidence. Each "
            "alternative states why it was rejected (with evidence citation) "
            "or why it remains plausible."
        ),
        "required": True,
    },
    {
        "section_id": "recommendations",
        "name": "Recommendations",
        "description": (
            "Actionable next steps derived from conclusions. Each recommendation "
            "ties back to a specific conclusion node and states the operational "
            "action, owner, and urgency."
        ),
        "required": True,
    },
    {
        "section_id": "source_appendix",
        "name": "Appendix: Source List with TLP Markings",
        "description": (
            "All sources referenced in the product, with their TLP marking. "
            "The product's overall TLP is the most restrictive source TLP."
        ),
        "required": True,
    },
]

# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------


def format_templates_for_prompt() -> str:
    """
    Format NODE_TYPES, STRENGTH_LEVELS, LOGIC_RULES, and PRODUCT_SECTIONS
    as a structured text block for injection into agent instructions.
    """
    lines: list[str] = []

    lines.append("ARGUMENT NODE TYPES")
    lines.append("-" * 60)
    for node_id, node in NODE_TYPES.items():
        lines.append(f"* {node['name']} ({node_id})")
        lines.append(f"  {node['description']}")
        lines.append(f"  Required fields: {', '.join(node['required_fields'])}")
        if "confidence_values" in node:
            lines.append(f"  Confidence values: {', '.join(node['confidence_values'])}")
        if "strength_values" in node:
            lines.append(f"  Strength values: {', '.join(node['strength_values'])}")
        lines.append("")

    lines.append("INFERENCE STRENGTH LEVELS")
    lines.append("-" * 60)
    for level in STRENGTH_LEVELS.values():
        lines.append(f"* {level['label']}: {level['description']}")
        lines.append(f"  Action guidance: {level['action_guidance']}")
        lines.append(
            f"  Minimum: {level['minimum_evidence_nodes']} evidence node(s) from "
            f"{level['minimum_source_categories']} source category/categories"
        )
        lines.append("")

    lines.append("LOGIC RULES")
    lines.append("-" * 60)
    for rule in LOGIC_RULES:
        lines.append(f"* {rule['rule_id']}: {rule['name']}")
        lines.append(f"  {rule['description']}")
        lines.append(f"  Violation example: {rule['violation_example']}")
        lines.append("")

    lines.append("REQUIRED PRODUCT SECTIONS")
    lines.append("-" * 60)
    for section in PRODUCT_SECTIONS:
        req = "REQUIRED" if section["required"] else "OPTIONAL"
        lines.append(f"* {section['name']} [{req}]")
        lines.append(f"  {section['description']}")
        lines.append("")

    return "\n".join(lines)


def get_node_type(type_id: str) -> dict | None:
    """Look up a node type by its ID. Returns None if not found."""
    return NODE_TYPES.get(type_id)


# ---------------------------------------------------------------------------
# Shared metrics computation — single source of truth for P/C/F1
#
# Used by the simulation notebook; kept here as the single source of
# truth for P/C/F1 so a formula change lands in exactly one place.
# ---------------------------------------------------------------------------


def compute_verdict_metrics(verdict: dict) -> dict:
    """Compute judge-compliance metrics from a single verdict dict.

    Args:
        verdict: A ProductionVerdict-shaped dict with confirmed_valid,
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
    f1 = round(2 * precision * coverage / (precision + coverage), 1) if (precision + coverage) > 0 else 0.0

    n_relevant = sum(
        1 for s in verdict.get("confirmed_valid", [])
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
    n_types = len(NODE_TYPES)
    n_levels = len(STRENGTH_LEVELS)
    n_rules = len(LOGIC_RULES)
    n_sections = len(PRODUCT_SECTIONS)
    print(
        f"Production schemas: {n_types} node types, "
        f"{n_levels} strength levels, {n_rules} logic rules, "
        f"{n_sections} product sections"
    )
