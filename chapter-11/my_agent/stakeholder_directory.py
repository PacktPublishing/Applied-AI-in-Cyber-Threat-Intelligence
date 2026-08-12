from __future__ import annotations

"""
Stakeholder directory, routing rules, and classification mapping for the
Dissemination Pipeline.

Defines the closed universe of stakeholder roles, their scopes, allowed
actions, clearance levels, delivery channels, and the routing rules that
govern which stakeholders receive which intel products. The Routing Judge
validates every routing decision against this directory.

Catalog sections:
  STAKEHOLDERS           -- 10 stakeholder roles with scope, actions, clearance, channels
  ROUTING_RULES          -- hard routing rules the judge checks against
  NOTIFICATION_ORDER     -- static notification sequencing (hardcoded)
  CLASSIFICATION_MAP     -- TLP to internal classification tier mapping
  CONFIDENCE_ROUTING     -- confidence-gated routing thresholds

Total: 10 stakeholder roles, 8 routing rules, 4 TLP levels, 3 confidence tiers.
"""

# ---------------------------------------------------------------------------
# Classification Map — TLP to internal tier
# ---------------------------------------------------------------------------

CLASSIFICATION_MAP = {
    "TLP:RED":   "RESTRICTED",    # Named recipients only (SOC Manager, CISO)
    "TLP:AMBER": "CONFIDENTIAL",  # Organization-internal, need-to-know
    "TLP:GREEN": "INTERNAL",      # Any employee
    "TLP:CLEAR": "PUBLIC",        # Unrestricted
}

CLASSIFICATION_HIERARCHY = {
    "RESTRICTED": 4,
    "CONFIDENTIAL": 3,
    "INTERNAL": 2,
    "PUBLIC": 1,
}

# Reverse map for display.
_TIER_TO_TLP = {v: k for k, v in CLASSIFICATION_MAP.items()}


# ---------------------------------------------------------------------------
# Stakeholder Directory — 10 roles
# ---------------------------------------------------------------------------

STAKEHOLDERS = {
    "soc_manager": {
        "role": "SOC Manager",
        "scope": [
            "detection rules", "monitoring", "incident response",
            "alert triage", "threat hunting coordination", "SIEM",
            "endpoint detection", "network monitoring",
        ],
        "allowed_actions": [
            "deploy detection rule", "initiate threat hunt",
            "escalate to incident response", "update threat model",
            "brief analysts on new TTP", "tune existing detections",
            "coordinate with partner SOC", "create SOAR playbook",
        ],
        "clearance": "RESTRICTED",
        "channels": ["siem_ticket", "soar_case", "war_room", "secure_portal"],
        "intel_types": ["operational", "tactical"],
        "description": (
            "Runs the SOC shift, manages analysts, coordinates detection "
            "deployment and incident escalation. Always receives operational "
            "intelligence regardless of scenario."
        ),
    },
    "ciso": {
        "role": "CISO",
        "scope": [
            "strategic risk", "board reporting", "program decisions",
            "budget authorization", "incident declaration", "cyber insurance",
            "regulatory posture", "executive communication",
        ],
        "allowed_actions": [
            "approve incident response plan", "authorize budget",
            "brief board of directors", "activate incident response plan",
            "engage external IR firm", "invoke cyber insurance",
            "declare security incident", "authorize public disclosure",
        ],
        "clearance": "RESTRICTED",
        "channels": ["secure_portal", "in_person", "encrypted_video"],
        "intel_types": ["strategic", "operational"],
        "description": (
            "Strategic risk owner. Authorizes major response actions, "
            "budget, and external engagements. Receives all HIGH confidence "
            "intelligence and any incident requiring executive decision."
        ),
    },
    "threat_hunt_lead": {
        "role": "Threat Hunt Lead",
        "scope": [
            "threat hunting", "hypothesis-driven investigation",
            "retrospective analysis", "TTP mapping", "MITRE ATT&CK",
            "behavioral analytics", "adversary tradecraft",
        ],
        "allowed_actions": [
            "scope retrospective hunt", "develop hunt hypothesis",
            "analyze endpoint telemetry", "map adversary TTPs",
            "produce hunt findings report", "recommend detection gaps",
        ],
        "clearance": "RESTRICTED",
        "channels": ["siem_ticket", "secure_portal", "war_room"],
        "intel_types": ["operational", "tactical"],
        "description": (
            "Converts finished intel products into proactive hunt hypotheses. "
            "Receives operational and tactical intelligence with full IOC detail "
            "for retrospective hunting across endpoint and network telemetry."
        ),
    },
    "vp_cloud_engineering": {
        "role": "VP Cloud Engineering",
        "scope": [
            "cloud infrastructure", "API keys", "secrets management",
            "IAM permissions", "production databases", "CI/CD pipelines",
            "container orchestration", "cloud provider accounts",
        ],
        "allowed_actions": [
            "rotate credentials", "revoke access", "patch vulnerability",
            "scope blast radius", "review IAM permissions",
            "engage cloud provider support", "isolate workload",
        ],
        "clearance": "CONFIDENTIAL",
        "channels": ["encrypted_email", "secure_portal", "encrypted_video"],
        "intel_types": ["tactical", "operational"],
        "description": (
            "Owns cloud infrastructure, secrets, and IAM. Receives intel "
            "involving infrastructure compromise, credential exposure, or "
            "cloud resource abuse."
        ),
    },
    "general_counsel": {
        "role": "General Counsel",
        "scope": [
            "legal liability", "partner contracts", "MSA obligations",
            "regulatory compliance", "litigation", "law enforcement",
            "evidence preservation", "contractual breach",
        ],
        "allowed_actions": [
            "review contract obligations", "assess legal liability",
            "prepare disclosure", "initiate legal hold",
            "assess notification obligations", "engage outside counsel",
            "coordinate with law enforcement",
        ],
        "clearance": "CONFIDENTIAL",
        "channels": ["encrypted_email", "secure_portal", "in_person"],
        "intel_types": ["strategic", "legal"],
        "description": (
            "Legal advisor. Must be routed whenever partner contracts, "
            "regulatory obligations, or legal liability are implicated. "
            "Receives redacted briefs without raw technical IOCs."
        ),
    },
    "head_of_product": {
        "role": "Head of Product",
        "scope": [
            "product roadmap", "release schedule", "customer impact",
            "feature audit", "product security", "customer-facing services",
        ],
        "allowed_actions": [
            "delay product launch", "scope security audit",
            "assess customer exposure", "issue customer advisory",
            "review feature dependencies",
        ],
        "clearance": "INTERNAL",
        "channels": ["encrypted_email", "secure_portal"],
        "intel_types": ["strategic"],
        "description": (
            "Product owner. Receives intel when product roadmap, release "
            "schedule, or customer-facing services are affected. Gets "
            "business impact summaries, not technical details."
        ),
    },
    "corporate_comms": {
        "role": "Corporate Communications",
        "scope": [
            "public disclosure", "media relations", "customer notification",
            "investor relations", "brand reputation", "social media monitoring",
        ],
        "allowed_actions": [
            "draft holding statement", "prepare external messaging",
            "coordinate with investor relations", "prepare employee communication",
            "monitor media coverage",
        ],
        "clearance": "INTERNAL",
        "channels": ["encrypted_email", "secure_portal"],
        "intel_types": ["strategic"],
        "description": (
            "Only routed when public disclosure is possible or has occurred. "
            "Receives business impact summary without any technical IOCs or "
            "classified operational details."
        ),
    },
    "third_party_risk": {
        "role": "Third-Party Risk Manager",
        "scope": [
            "vendor security", "partner access lifecycle", "SOC 2 compliance",
            "third-party assessments", "supply chain risk",
            "partner access management",
        ],
        "allowed_actions": [
            "restrict partner access", "request vendor security assessment",
            "review third-party access logs", "escalate to vendor management",
            "update vendor risk rating", "terminate partner access",
        ],
        "clearance": "CONFIDENTIAL",
        "channels": ["encrypted_email", "secure_portal"],
        "intel_types": ["tactical", "strategic"],
        "description": (
            "Manages partner and vendor security relationships. Routed when "
            "a partner or supply chain entity is involved in the incident."
        ),
    },
    "privacy_dpo": {
        "role": "Privacy / Data Protection Officer",
        "scope": [
            "PII exposure", "GDPR notification", "CCPA compliance",
            "data breach notification", "supervisory authority reporting",
            "data subject rights", "cross-border data transfer",
        ],
        "allowed_actions": [
            "assess notification obligations", "report to supervisory authority",
            "prepare data subject notification", "document data breach",
            "assess jurisdiction-specific timelines",
        ],
        "clearance": "CONFIDENTIAL",
        "channels": ["encrypted_email", "secure_portal", "in_person"],
        "intel_types": ["legal", "strategic"],
        "description": (
            "Data protection officer. Must be routed when PII is exposed, "
            "when breach notification obligations may apply, or when "
            "cross-border data transfer is implicated."
        ),
    },
    "hr_operations": {
        "role": "HR / People Operations",
        "scope": [
            "insider threat", "employee investigation", "access suspension",
            "employment law", "workplace investigation", "termination",
        ],
        "allowed_actions": [
            "suspend employee access", "initiate workplace investigation",
            "coordinate with legal on employment law",
            "document employee conduct", "manage separation process",
        ],
        "clearance": "CONFIDENTIAL",
        "channels": ["encrypted_email", "in_person"],
        "intel_types": ["operational", "legal"],
        "description": (
            "Routed when an insider threat or employee-related investigation "
            "is indicated. Manages employee access suspension and coordinates "
            "with legal on employment law implications."
        ),
    },
}


# ---------------------------------------------------------------------------
# Routing Rules — hard constraints
# ---------------------------------------------------------------------------

ROUTING_RULES = [
    {
        "rule_id": "RR-001",
        "name": "SOC Manager Always Receives Operational Intel",
        "description": (
            "SOC Manager must be included in the routing manifest for any "
            "intel product with operational or tactical content. There is "
            "no scenario where operational intelligence is produced without "
            "the SOC being informed."
        ),
        "mandatory_for": ["operational", "tactical"],
    },
    {
        "rule_id": "RR-002",
        "name": "General Counsel on Legal / Contractual Implications",
        "description": (
            "General Counsel must be routed whenever the intel product "
            "implicates partner contracts, regulatory obligations, legal "
            "liability, or potential litigation."
        ),
        "trigger_keywords": [
            "contract", "MSA", "liability", "regulatory", "legal",
            "disclosure", "compliance", "litigation", "law enforcement",
        ],
    },
    {
        "rule_id": "RR-003",
        "name": "Corporate Comms Only on Public Disclosure Risk",
        "description": (
            "Corporate Communications is ONLY routed when the incident has "
            "public disclosure risk, media attention, customer notification "
            "requirements, or is already public. Routing Corporate Comms "
            "for a purely internal incident is over-routing and causes "
            "unnecessary organizational noise."
        ),
        "trigger_keywords": [
            "public disclosure", "media", "customer notification",
            "press", "investor", "public", "brand", "reputation",
        ],
    },
    {
        "rule_id": "RR-004",
        "name": "Classification Must Not Exceed Recipient Clearance",
        "description": (
            "The classification tier of a brief must not exceed the "
            "recipient's clearance level. A RESTRICTED brief cannot be "
            "sent to a CONFIDENTIAL or INTERNAL recipient. Violations "
            "require either content redaction or recipient exclusion."
        ),
    },
    {
        "rule_id": "RR-005",
        "name": "No Technical IOCs to Non-Technical Stakeholders",
        "description": (
            "Raw technical indicators (IP addresses, hashes, C2 domains, "
            "API keys, session tokens) must not appear in briefs sent to "
            "non-technical stakeholders (General Counsel, Head of Product, "
            "Corporate Comms, HR, Privacy/DPO). These recipients receive "
            "contextual impact summaries instead."
        ),
        "non_technical_roles": [
            "general_counsel", "head_of_product", "corporate_comms",
            "privacy_dpo", "hr_operations",
        ],
    },
    {
        "rule_id": "RR-006",
        "name": "Privacy/DPO on PII Exposure",
        "description": (
            "Privacy / Data Protection Officer must be routed whenever "
            "PII is exposed, breach notification obligations may apply, "
            "or cross-border data transfer is implicated."
        ),
        "trigger_keywords": [
            "PII", "personal data", "GDPR", "CCPA", "breach notification",
            "data subject", "customer data", "employee data",
        ],
    },
    {
        "rule_id": "RR-007",
        "name": "HR on Insider Threat",
        "description": (
            "HR / People Operations must be routed when the intel product "
            "indicates insider threat activity, employee investigation, "
            "or employee access abuse."
        ),
        "trigger_keywords": [
            "insider threat", "employee", "exfiltration by employee",
            "bulk download by user", "resignation", "termination",
            "workplace investigation",
        ],
    },
    {
        "rule_id": "RR-008",
        "name": "Confidence-Gated Routing",
        "description": (
            "Routing breadth is gated by the intel product's confidence level. "
            "LOW confidence: SOC Manager + Threat Hunt Lead only. "
            "MEDIUM confidence: add technical stakeholders (VP Cloud Eng, "
            "Third-Party Risk) and triggered mandatory stakeholders. "
            "HIGH confidence: full routing cascade per scope overlap."
        ),
    },
]


# ---------------------------------------------------------------------------
# Notification Order — static sequencing
# ---------------------------------------------------------------------------

NOTIFICATION_ORDER = [
    "soc_manager",          # 1. Immediate containment
    "threat_hunt_lead",     # 2. Proactive hunting
    "ciso",                 # 3. Executive authorization
    "vp_cloud_engineering", # 4. Technical remediation
    "third_party_risk",     # 5. Vendor/partner management
    "general_counsel",      # 6. Legal assessment
    "privacy_dpo",          # 7. Regulatory notification
    "hr_operations",        # 8. Employee investigation
    "head_of_product",      # 9. Product impact
    "corporate_comms",      # 10. External communication (last)
]


# ---------------------------------------------------------------------------
# Confidence-Gated Routing Tiers
# ---------------------------------------------------------------------------

CONFIDENCE_ROUTING = {
    "LOW": {
        "description": "SOC Manager + Threat Hunt Lead only. Insufficient evidence for broader distribution.",
        "always_include": ["soc_manager", "threat_hunt_lead"],
        "conditionally_include": [],
    },
    "MEDIUM": {
        "description": (
            "Add technical stakeholders and triggered mandatory stakeholders. "
            "Sufficient evidence for targeted remediation but not full cascade."
        ),
        "always_include": ["soc_manager", "threat_hunt_lead"],
        "conditionally_include": [
            "ciso", "vp_cloud_engineering", "third_party_risk",
            "general_counsel", "privacy_dpo", "hr_operations",
        ],
    },
    "HIGH": {
        "description": "Full routing cascade. All stakeholders with scope overlap are included.",
        "always_include": ["soc_manager", "threat_hunt_lead", "ciso"],
        "conditionally_include": [
            "vp_cloud_engineering", "general_counsel", "head_of_product",
            "corporate_comms", "third_party_risk", "privacy_dpo",
            "hr_operations",
        ],
    },
}


# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------


def format_directory_for_prompt() -> str:
    """
    Format STAKEHOLDERS, ROUTING_RULES, NOTIFICATION_ORDER, and
    CLASSIFICATION_MAP as a structured text block for injection into
    agent instructions.
    """
    lines: list[str] = []

    lines.append("STAKEHOLDER DIRECTORY")
    lines.append("-" * 60)
    for role_id, role in STAKEHOLDERS.items():
        lines.append(f"* {role['role']} ({role_id})")
        lines.append(f"  Scope: {', '.join(role['scope'])}")
        lines.append(f"  Allowed actions: {', '.join(role['allowed_actions'])}")
        lines.append(f"  Clearance: {role['clearance']}")
        lines.append(f"  Channels: {', '.join(role['channels'])}")
        lines.append(f"  Intel types: {', '.join(role['intel_types'])}")
        lines.append(f"  {role['description']}")
        lines.append("")

    lines.append("ROUTING RULES")
    lines.append("-" * 60)
    for rule in ROUTING_RULES:
        lines.append(f"* {rule['rule_id']}: {rule['name']}")
        lines.append(f"  {rule['description']}")
        if "trigger_keywords" in rule:
            lines.append(f"  Trigger keywords: {', '.join(rule['trigger_keywords'])}")
        if "mandatory_for" in rule:
            lines.append(f"  Mandatory for intel types: {', '.join(rule['mandatory_for'])}")
        lines.append("")

    lines.append("NOTIFICATION ORDER (static)")
    lines.append("-" * 60)
    for i, role_id in enumerate(NOTIFICATION_ORDER, 1):
        role_name = STAKEHOLDERS[role_id]["role"]
        lines.append(f"  {i}. {role_name} ({role_id})")
    lines.append("")

    lines.append("CLASSIFICATION MAP (TLP → Internal Tier)")
    lines.append("-" * 60)
    for tlp, tier in CLASSIFICATION_MAP.items():
        level = CLASSIFICATION_HIERARCHY[tier]
        lines.append(f"  {tlp} → {tier} (level {level})")
    lines.append("")

    lines.append("CONFIDENCE-GATED ROUTING")
    lines.append("-" * 60)
    for conf, spec in CONFIDENCE_ROUTING.items():
        lines.append(f"  {conf}: {spec['description']}")
        lines.append(f"    Always include: {', '.join(spec['always_include'])}")
        if spec["conditionally_include"]:
            lines.append(f"    Conditionally include: {', '.join(spec['conditionally_include'])}")
        lines.append("")

    return "\n".join(lines)


def get_stakeholder(role_id: str) -> dict | None:
    """Look up a stakeholder by role_id. Returns None if not found."""
    return STAKEHOLDERS.get(role_id)


# ---------------------------------------------------------------------------
# Deterministic classification compliance checker
# ---------------------------------------------------------------------------


def check_classification_compliance(briefs: list[dict]) -> list[str]:
    """
    Deterministic check: validates each brief's classification against the
    recipient's clearance and allowed channels.

    Args:
        briefs: list of dicts, each with at minimum:
            - stakeholder_id: str
            - classification: str (RESTRICTED / CONFIDENTIAL / INTERNAL / PUBLIC)
            - delivery_channel: str

    Returns:
        List of violation strings. Empty = compliant.
    """
    violations = []
    valid_roles = set(STAKEHOLDERS.keys())

    for brief in briefs:
        sid = brief.get("stakeholder_id", "")
        classification = brief.get("classification", "")
        channel = brief.get("delivery_channel", "")

        # Unknown stakeholder.
        if sid not in valid_roles:
            violations.append(
                f"Unknown stakeholder: '{sid}' is not in the stakeholder directory"
            )
            continue

        stakeholder = STAKEHOLDERS[sid]

        # Classification exceeds clearance (RR-004).
        brief_level = CLASSIFICATION_HIERARCHY.get(classification, 0)
        clearance_level = CLASSIFICATION_HIERARCHY.get(stakeholder["clearance"], 0)
        if brief_level > clearance_level:
            violations.append(
                f"Classification violation (RR-004): {stakeholder['role']} has "
                f"{stakeholder['clearance']} clearance but received "
                f"{classification} brief"
            )

        # IOC policy (RR-005): non-technical stakeholders must not receive raw IOCs.
        ioc_included = brief.get("ioc_included", False)
        if ioc_included:
            rr005 = next(
                (r for r in ROUTING_RULES if r.get("rule_id") == "RR-005"), {}
            )
            non_technical = rr005.get("non_technical_roles", [])
            if sid in non_technical:
                violations.append(
                    f"IOC violation (RR-005): {stakeholder['role']} is a non-technical "
                    f"stakeholder — raw IOCs must not be included in their brief"
                )

        # Channel not allowed.
        if channel and channel not in stakeholder["channels"]:
            violations.append(
                f"Channel violation: {stakeholder['role']} cannot receive "
                f"via '{channel}' (allowed: {', '.join(stakeholder['channels'])})"
            )

    return violations


# ---------------------------------------------------------------------------
# Deterministic over-routing checker
# ---------------------------------------------------------------------------


def check_over_routing(manifest: dict) -> list[str]:
    """
    Deterministic check: identifies stakeholders in the routing manifest who
    cannot be justified by at least one routing rule given the product's
    confidence level and rationale fields.

    Catches two over-routing patterns the LLM judge under-penalizes:
      - RR-008: any stakeholder beyond soc_manager / threat_hunt_lead at LOW confidence
      - RR-003: corporate_comms routed with no public disclosure trigger in rationale

    Args:
        manifest: parsed dissemination plan dict with at minimum:
            - product_confidence: str (HIGH / MEDIUM / LOW)
            - routed_stakeholders: list of dicts, each with stakeholder_id,
              rationale, and optionally brief_summary

    Returns:
        List of over-routing violation strings. Empty = no violations detected.
    """
    violations = []
    confidence = manifest.get("product_confidence", "HIGH").upper()
    routed = manifest.get("routed_stakeholders", [])
    routed_ids = {entry.get("stakeholder_id", "") for entry in routed}

    # RR-008: LOW confidence gate — only soc_manager and threat_hunt_lead permitted.
    if confidence == "LOW":
        low_conf_allowed = set(CONFIDENCE_ROUTING["LOW"]["always_include"])
        for entry in routed:
            sid = entry.get("stakeholder_id", "")
            if sid and sid not in low_conf_allowed:
                violations.append(
                    f"Over-routing violation (RR-008): '{sid}' is routed at LOW "
                    f"confidence — only {sorted(low_conf_allowed)} are permitted "
                    f"at this confidence tier"
                )

    # RR-003: Corporate Comms requires a public disclosure trigger in the rationale.
    if "corporate_comms" in routed_ids:
        rr003 = next((r for r in ROUTING_RULES if r.get("rule_id") == "RR-003"), {})
        trigger_keywords = rr003.get("trigger_keywords", [])
        cc_entry = next(
            (e for e in routed if e.get("stakeholder_id") == "corporate_comms"), {}
        )
        rationale = (
            cc_entry.get("rationale", "") + " " + cc_entry.get("brief_summary", "")
        ).lower()
        has_trigger = any(kw.lower() in rationale for kw in trigger_keywords)
        if not has_trigger:
            violations.append(
                "Over-routing violation (RR-003): corporate_comms is routed but no "
                "public disclosure trigger keyword found in rationale — routing "
                "Corporate Communications for a purely internal incident is over-routing"
            )

    return violations


if __name__ == "__main__":
    n_stakeholders = len(STAKEHOLDERS)
    n_rules = len(ROUTING_RULES)
    n_tiers = len(CLASSIFICATION_MAP)
    n_conf = len(CONFIDENCE_ROUTING)
    print(
        f"Dissemination schemas: {n_stakeholders} stakeholders, "
        f"{n_rules} routing rules, {n_tiers} TLP mappings, "
        f"{n_conf} confidence tiers"
    )
