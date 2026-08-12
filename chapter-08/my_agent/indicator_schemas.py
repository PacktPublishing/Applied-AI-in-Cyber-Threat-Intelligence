"""
Signal type catalog and corroboration rules for the Processing Pipeline.

Defines the closed universe of signal types, confidence assignment rules,
and corroboration relationships. The Processing Validation Judge validates
every confidence level and correlation link against these schemas.

Catalog sections:
  SIGNAL_TYPES         — 10 signal types with confidence rules and corroboration graph
  SOURCE_CATEGORY_MAP  — maps signal source categories to collection catalog source names
  CONFIDENCE_LEVELS    — LOW / MEDIUM / HIGH with minimum signal and category counts
  CORROBORATION_RULES  — 5 rules governing when signals corroborate each other

Total: 10 signal types, 24 source categories, 3 confidence levels, 5 rules.
"""

# ---------------------------------------------------------------------------
# Signal Types
# ---------------------------------------------------------------------------

SIGNAL_TYPES = {
    "authentication_anomaly": {
        "name": "Authentication Anomaly",
        "description": (
            "Unusual authentication pattern: impossible travel, an already-authenticated "
            "session token replayed from a new IP/ASN/device, anomalous device/IP, "
            "failed MFA followed by successful session from a different source."
        ),
        "source_categories": ["identity_provider", "mfa", "siem"],
        "isolated_confidence": "LOW",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "credential_exposure", "infrastructure_match", "phishing_indicator",
            "repository_access_anomaly", "data_movement",
            "endpoint_compromise", "privilege_escalation",
        ],
        "example_indicators": [
            "Okta user.session.start reusing an existing session/device token from a new IP/ASN/device (original sign-in already passed MFA)",
            "Entra ID interactiveUserSignIn from IP in country X while prior session active from country Y",
            "Duo auth.result=deny followed by successful Okta session from different IP within 30min",
        ],
    },
    "credential_exposure": {
        "name": "Credential Exposure",
        "description": (
            "Partner or employee credentials found in breach data, stealer logs, "
            "or dark web marketplaces. Indicates pre-compromise material available "
            "to threat actors."
        ),
        "source_categories": ["breach_intelligence", "dark_web"],
        "isolated_confidence": "MEDIUM",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "authentication_anomaly", "dark_web_mention", "phishing_indicator",
            "repository_access_anomaly", "data_movement", "privilege_escalation",
        ],
        "example_indicators": [
            "HIBP breach hit for partner email domain in recent stealer log dump",
            "SpyCloud recaptured session cookie for partner user matching Okta session format",
            "DeHashed result showing cleartext password for partner admin account",
        ],
    },
    "repository_access_anomaly": {
        "name": "Repository Access Anomaly",
        "description": (
            "Unusual code repository activity: bulk cloning, access from new IP/device, "
            "PAT creation followed by clone, access outside normal working hours."
        ),
        "source_categories": ["version_control", "casb"],
        "isolated_confidence": "LOW",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "authentication_anomaly", "credential_exposure", "data_movement",
        ],
        "example_indicators": [
            "GitHub git.clone of 10+ private repos within 1 hour from a new IP",
            "GitLab repository_download from IP not seen in prior 90 days",
            "GitHub personal_access_token.create followed by bulk clone within 15min",
        ],
    },
    "infrastructure_match": {
        "name": "Infrastructure Match",
        "description": (
            "IP address, domain, or certificate associated with known threat actor "
            "infrastructure, C2 servers, or malicious hosting. Match from threat "
            "intelligence feeds against observed network or authentication telemetry."
        ),
        "source_categories": ["threat_intelligence", "network_security", "dns_security"],
        "isolated_confidence": "MEDIUM",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "authentication_anomaly", "domain_permutation", "phishing_indicator",
            "dark_web_mention", "endpoint_compromise",
        ],
        "example_indicators": [
            "GreyNoise-tagged IP appearing in Okta sign-in logs (not mass scanner)",
            "Palo Alto THREAT event matching known C2 IP from ThreatFox",
            "Certificate on phishing domain matches known Evilginx2 deployment pattern",
        ],
    },
    "domain_permutation": {
        "name": "Domain Permutation",
        "description": (
            "Newly registered or recently activated domain that is a typosquat, "
            "homoglyph, or lookalike of a partner or ApexCode domain. May host "
            "credential harvesting or AiTM proxy infrastructure."
        ),
        "source_categories": ["domain_recon", "url_phishing"],
        "isolated_confidence": "LOW",
        "corroborated_confidence": "MEDIUM",
        "corroborates_with": ["infrastructure_match", "phishing_indicator"],
        "example_indicators": [
            "dnstwist: apexcode-dev.com registered 3 days ago, A record points to VPS",
            "urlscan.io: page at apex-code.io contains login form mimicking Okta SSO",
            "Certificate Transparency log showing cert for apexcodesolutions.net",
        ],
    },
    "dark_web_mention": {
        "name": "Dark Web Mention",
        "description": (
            "ApexCode, partner company, or related infrastructure mentioned in "
            "dark web forums, paste sites, or initial access broker listings."
        ),
        "source_categories": ["dark_web", "breach_intelligence"],
        "isolated_confidence": "LOW",
        "corroborated_confidence": "MEDIUM",
        "corroborates_with": ["credential_exposure", "infrastructure_match"],
        "example_indicators": [
            "IntelligenceX: paste mentioning ApexCode VPN endpoint in access broker listing",
            "Dark web forum post offering 'SaaS access to software dev company' matching ApexCode profile",
        ],
    },
    "phishing_indicator": {
        "name": "Phishing Indicator",
        "description": (
            "Evidence of phishing delivery: blocked or permitted click on suspicious URL, "
            "email with impostor characteristics, attachment detonation result, or URL "
            "matching known phishing kit signatures."
        ),
        "source_categories": ["email_security", "url_phishing", "dns_security"],
        "isolated_confidence": "LOW",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "authentication_anomaly", "domain_permutation",
            "infrastructure_match", "credential_exposure",
        ],
        "example_indicators": [
            "Proofpoint click.permitted on URL matching Evilginx2 phishing page pattern",
            "Proofpoint impostor.detected for email spoofing partner company domain",
            "Cisco Umbrella dns.blocked for domain categorized as phishing",
        ],
    },
    "data_movement": {
        "name": "Data Movement / Exfiltration Indicator",
        "description": (
            "Anomalous data transfer pattern: bulk download, large upload to external "
            "service, DLP policy trigger, or abnormal API call volume suggesting "
            "data staging or exfiltration."
        ),
        "source_categories": ["casb", "cloud_audit", "saas_monitoring", "dlp"],
        "isolated_confidence": "LOW",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "repository_access_anomaly", "authentication_anomaly", "credential_exposure",
            "endpoint_compromise",
        ],
        "example_indicators": [
            "Netskope bulk_download event: 500+ files from SharePoint in 30min",
            "Zscaler dlp_incident: sensitive file pattern match on outbound upload",
            "Salesforce ReportEvent: report with 10,000+ rows exported by service account",
        ],
    },
    "endpoint_compromise": {
        "name": "Endpoint Compromise Indicator",
        "description": (
            "EDR/XDR detection on a managed endpoint: suspicious process execution, "
            "lateral movement tool, defense evasion technique, or malware detection "
            "that may indicate post-access adversary activity."
        ),
        "source_categories": ["edr_xdr", "mdm"],
        "isolated_confidence": "MEDIUM",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "authentication_anomaly", "infrastructure_match", "data_movement",
            "privilege_escalation",
        ],
        "example_indicators": [
            "CrowdStrike DetectionSummaryEvent: Cobalt Strike beacon process tree",
            "Defender for Endpoint: DeviceProcessEvents showing LSASS access from unsigned binary",
            "SentinelOne threat.detected: info-stealer classification with HIGH confidence",
        ],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation Indicator",
        "description": (
            "Unauthorized or anomalous privilege grant: group membership change, "
            "role assignment, PAM checkout anomaly, or OAuth consent grant that "
            "expands an account's access beyond baseline."
        ),
        "source_categories": ["identity_provider", "pam", "cloud_audit"],
        "isolated_confidence": "MEDIUM",
        "corroborated_confidence": "HIGH",
        "corroborates_with": [
            "authentication_anomaly", "credential_exposure", "endpoint_compromise",
        ],
        "example_indicators": [
            "Okta user added to 'Production-Admin' group outside change window",
            "CyberArk PSM.Session.Start for high-value safe by account not in approved list",
            "AWS AssumeRole to admin role from IP not in corporate CIDR",
        ],
    },
}

# ---------------------------------------------------------------------------
# Source Category Map
# Maps signal source categories to actual source names from the collection
# catalog (Chapter 7's my_agent/sources.py). Used by the judge to verify that
# corroboration comes from different source categories.
# ---------------------------------------------------------------------------

SOURCE_CATEGORY_MAP = {
    "identity_provider": [
        "Okta System Log",
        "Microsoft Entra ID Sign-In Logs",
        "Microsoft Entra ID Audit Logs",
    ],
    "mfa": ["Duo Security"],
    "version_control": ["GitHub Audit Log", "GitLab Audit Events"],
    "project_management": ["Jira Audit Log"],
    "edr_xdr": [
        "CrowdStrike Falcon",
        "SentinelOne Singularity",
        "Microsoft Defender for Endpoint",
        "Palo Alto Cortex XDR",
    ],
    "siem": ["Microsoft Sentinel"],
    "network_security": [
        "Palo Alto Networks Firewall (PAN-OS)",
        "Fortinet FortiGate",
    ],
    "dns_security": ["Cisco Umbrella", "Cloudflare Gateway (Zero Trust)"],
    "casb": [
        "Zscaler Internet Access (CASB)",
        "Netskope CASB",
        "Skyhigh Security (CASB)",
    ],
    "cloud_audit": [
        "AWS CloudTrail",
        "Azure Activity Log",
        "Google Cloud Audit Logs",
    ],
    "pam": ["CyberArk Privileged Access Manager", "HashiCorp Vault"],
    "email_security": ["Proofpoint Email Security"],
    "collaboration": [
        "Slack Enterprise Audit API",
        "Microsoft 365 Unified Audit Log",
    ],
    "saas_monitoring": ["Salesforce Event Monitoring", "ServiceNow"],
    "mdm": ["Jamf Pro", "Jamf Protect", "Microsoft Intune", "Kandji MDM"],
    "rmm": ["Kaseya VSA", "ConnectWise Automate", "NinjaRMM (NinjaOne)"],
    "breach_intelligence": ["HaveIBeenPwned API", "DeHashed", "SpyCloud"],
    "dark_web": ["IntelligenceX", "SpyCloud"],
    "domain_recon": [
        "urlscan.io", "dnstwist", "Shodan", "Censys",
        "Microsoft Defender Threat Intelligence",
    ],
    "url_phishing": ["PhishTank / CheckPhish", "URLhaus (abuse.ch)"],
    "threat_intelligence": [
        "Abuse.ch ThreatFox",
        "AlienVault OTX (Open Threat Exchange)",
        "Mandiant Advantage (Google Threat Intelligence)",
        "Pulsedive",
        "VirusTotal",
        "Shadowserver Foundation",
        "CISA Known Exploited Vulnerabilities (KEV) Feed",
    ],
    "ip_reputation": ["GreyNoise"],
    "code_exposure": ["GitHub Public Events API"],
    "dlp": [
        "Netskope CASB",
        "Zscaler Internet Access (CASB)",
        "Skyhigh Security (CASB)",
    ],
}

# ---------------------------------------------------------------------------
# Confidence Levels
# ---------------------------------------------------------------------------

CONFIDENCE_LEVELS = {
    "LOW": {
        "label": "LOW",
        "description": (
            "Single uncorroborated signal from one source category. "
            "Requires additional collection before action."
        ),
        "action_guidance": "Flag for continued monitoring. Do not escalate without corroboration.",
        "minimum_signals": 1,
        "minimum_categories": 1,
    },
    "MEDIUM": {
        "label": "MEDIUM",
        "description": (
            "Two independent signals from different source categories, or one "
            "high-fidelity indicator (e.g., known C2 IP match)."
        ),
        "action_guidance": "Initiate targeted collection on related signals. Brief threat hunt team.",
        "minimum_signals": 2,
        "minimum_categories": 2,
    },
    "HIGH": {
        "label": "HIGH",
        "description": (
            "Three or more corroborating signals from three or more source categories, "
            "or one confirmed high-fidelity match with supporting context."
        ),
        "action_guidance": "Escalate to incident response. Initiate containment assessment.",
        "minimum_signals": 3,
        "minimum_categories": 3,
    },
}

# ---------------------------------------------------------------------------
# Corroboration Rules
# ---------------------------------------------------------------------------

CORROBORATION_RULES = [
    {
        "rule_id": "CR-001",
        "name": "Cross-Category Requirement",
        "description": (
            "Signals from the same source category do not corroborate each other. "
            "Two CrowdStrike alerts are one signal from one category, not two "
            "independent signals."
        ),
        "violation_example": (
            "Assigning HIGH confidence from CrowdStrike DetectionSummaryEvent + "
            "CrowdStrike ProcessRollup2 — both are edr_xdr category."
        ),
    },
    {
        "rule_id": "CR-002",
        "name": "Temporal Proximity (Tiered)",
        "description": (
            "Corroborating signals are weighted by temporal distance. "
            "Tier 1 (within 24h): full corroboration — confidence level applies as defined. "
            "Tier 2 (1-7 days): reduced weight — corroboration valid but cannot elevate "
            "beyond MEDIUM on its own. "
            "Tier 3 (7-30 days): temporally distant — noted in the brief as a potential "
            "link but not treated as direct corroboration without additional evidence. "
            "Tier 4 (beyond 30 days): not corroborative without explicit evidence of "
            "delayed exploitation (e.g., access broker purchase timeline)."
        ),
        "violation_example": (
            "Assigning HIGH confidence from a breach hit 14 days ago + Okta anomaly "
            "today with no other signals — Tier 2 caps at MEDIUM. Or treating a "
            "45-day-old credential dump as corroborative without linking evidence."
        ),
        "tiers": {
            "tier_1": {"window": "0-24h", "weight": "full", "max_confidence": "HIGH"},
            "tier_2": {"window": "1-7d", "weight": "reduced", "max_confidence": "MEDIUM"},
            "tier_3": {"window": "7-30d", "weight": "flagged", "max_confidence": "LOW"},
            "tier_4": {"window": ">30d", "weight": "none", "max_confidence": "N/A"},
        },
    },
    {
        "rule_id": "CR-003",
        "name": "Geographic Consistency",
        "description": (
            "Conflicting geographic indicators reduce confidence rather than "
            "increase it. If signal A says the actor is in Eastern Europe and "
            "signal B says Southeast Asia, the conflict is itself a signal "
            "(VPN/proxy use) but does not constitute straightforward corroboration."
        ),
        "violation_example": (
            "Assigning HIGH confidence when Okta shows login from Ukraine and "
            "CrowdStrike shows process execution from endpoint in Singapore — "
            "the geographic conflict should be flagged, not treated as corroboration."
        ),
    },
    {
        "rule_id": "CR-004",
        "name": "Corroborates-With Constraint",
        "description": (
            "A signal can only corroborate another if the pair appears in each "
            "other's corroborates_with list. authentication_anomaly + "
            "credential_exposure is valid (mutual). authentication_anomaly + "
            "dark_web_mention is NOT valid (not in each other's lists)."
        ),
        "violation_example": (
            "Claiming corroboration between domain_permutation and "
            "repository_access_anomaly — they do not appear in each other's "
            "corroborates_with lists."
        ),
    },
    {
        "rule_id": "CR-005",
        "name": "Attribution Evidence Standard",
        "description": (
            "Attributing activity to a specific threat actor requires at least "
            "one infrastructure_match with a known actor TTP, or a "
            "credential_exposure linked to a known actor campaign. Behavioral "
            "similarity alone is insufficient for attribution."
        ),
        "violation_example": (
            "Attributing activity to APT29 based solely on 'they also target "
            "developers' — no infrastructure or tooling overlap cited."
        ),
    },
]

# ---------------------------------------------------------------------------
# TLP (Traffic Light Protocol) Handling Markings
# ---------------------------------------------------------------------------

TLP_LEVELS = {
    "TLP:RED": {
        "description": "Named recipients only. No further sharing beyond the specified individuals.",
        "sharing": "No sharing outside named recipients",
        "color": "#FF0000",
    },
    "TLP:AMBER": {
        "description": (
            "Limited sharing within the recipient's organization on a need-to-know basis. "
            "May not be shared outside the organization without source permission."
        ),
        "sharing": "Organization-internal, need-to-know",
        "color": "#FFC000",
    },
    "TLP:GREEN": {
        "description": (
            "Sharing within the community (e.g., sector ISAC, partner organizations). "
            "May not be shared publicly."
        ),
        "sharing": "Community sharing, not public",
        "color": "#33FF00",
    },
    "TLP:CLEAR": {
        "description": "No restrictions on sharing. May be shared publicly.",
        "sharing": "Unrestricted",
        "color": "#FFFFFF",
    },
}

# Maps source categories to their default TLP marking. The brief inherits
# the most restrictive TLP of any source it references.
# Ordered most restrictive → least restrictive: RED > AMBER > GREEN > CLEAR.
SOURCE_CATEGORY_TLP = {
    # Commercial / paid sources — typically received under sharing agreements
    "breach_intelligence":   "TLP:AMBER",   # SpyCloud, DeHashed, HIBP (paid tiers)
    "dark_web":              "TLP:AMBER",   # IntelligenceX
    "threat_intelligence":   "TLP:AMBER",   # Mandiant, Pulsedive, OTX
    # Internal enterprise sources — organization-internal
    "identity_provider":     "TLP:AMBER",
    "mfa":                   "TLP:AMBER",
    "edr_xdr":               "TLP:AMBER",
    "siem":                  "TLP:AMBER",
    "pam":                   "TLP:AMBER",
    "cloud_audit":           "TLP:AMBER",
    "collaboration":         "TLP:AMBER",
    "saas_monitoring":       "TLP:AMBER",
    "mdm":                   "TLP:AMBER",
    "rmm":                   "TLP:AMBER",
    "email_security":        "TLP:AMBER",
    "network_security":      "TLP:AMBER",
    "dns_security":          "TLP:AMBER",
    "casb":                  "TLP:AMBER",
    "dlp":                   "TLP:AMBER",
    "version_control":       "TLP:AMBER",
    "project_management":    "TLP:AMBER",
    # Public / open sources
    "domain_recon":          "TLP:GREEN",   # urlscan.io, dnstwist, Shodan, Censys
    "url_phishing":          "TLP:GREEN",   # PhishTank, URLhaus
    "ip_reputation":         "TLP:GREEN",   # GreyNoise
    "code_exposure":         "TLP:GREEN",   # GitHub Public Events API
}

TLP_ASSIGNMENT_RULES = [
    "The brief's TLP marking is the MOST RESTRICTIVE TLP of any source category referenced.",
    "If any finding uses breach_intelligence or dark_web sources, the brief is at least TLP:AMBER.",
    "If all sources are public/open (domain_recon, url_phishing, ip_reputation, code_exposure), the brief may be TLP:GREEN.",
    "TLP:RED is reserved for briefs containing named individual indicators or active investigation details shared by a specific source under TLP:RED agreement.",
    "The TLP marking must appear at the top of the brief before any findings.",
]

# Restrictiveness order for determining the most restrictive TLP.
_TLP_RESTRICTIVENESS = {"TLP:RED": 4, "TLP:AMBER": 3, "TLP:GREEN": 2, "TLP:CLEAR": 1}


def get_brief_tlp(source_categories: list[str]) -> str:
    """
    Determine the TLP marking for a brief based on its source categories.
    Returns the most restrictive TLP of any referenced source.
    """
    if not source_categories:
        return "TLP:AMBER"  # default to AMBER when unknown

    max_level = 0
    max_tlp = "TLP:CLEAR"
    for cat in source_categories:
        tlp = SOURCE_CATEGORY_TLP.get(cat, "TLP:AMBER")
        level = _TLP_RESTRICTIVENESS.get(tlp, 3)
        if level > max_level:
            max_level = level
            max_tlp = tlp
    return max_tlp


# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------


def format_schemas_for_prompt() -> str:
    """
    Format SIGNAL_TYPES, CONFIDENCE_LEVELS, and CORROBORATION_RULES as a
    structured text block for injection into agent instructions.
    """
    lines: list[str] = []

    lines.append("SIGNAL TYPES")
    lines.append("-" * 60)
    for sig_id, sig in SIGNAL_TYPES.items():
        lines.append(f"* {sig['name']} ({sig_id})")
        lines.append(f"  {sig['description']}")
        lines.append(f"  Source categories: {', '.join(sig['source_categories'])}")
        lines.append(f"  Isolated confidence: {sig['isolated_confidence']}")
        lines.append(f"  Corroborated confidence: {sig['corroborated_confidence']}")
        lines.append(f"  Corroborates with: {', '.join(sig['corroborates_with'])}")
        lines.append("  Example indicators:")
        for ex in sig["example_indicators"]:
            lines.append(f"    - {ex}")
        lines.append("")

    lines.append("CONFIDENCE LEVELS")
    lines.append("-" * 60)
    for level in CONFIDENCE_LEVELS.values():
        lines.append(f"* {level['label']}: {level['description']}")
        lines.append(f"  Action guidance: {level['action_guidance']}")
        lines.append(
            f"  Minimum: {level['minimum_signals']} signal(s) from "
            f"{level['minimum_categories']} category/categories"
        )
        lines.append("")

    lines.append("CORROBORATION RULES")
    lines.append("-" * 60)
    for rule in CORROBORATION_RULES:
        lines.append(f"* {rule['rule_id']}: {rule['name']}")
        lines.append(f"  {rule['description']}")
        lines.append(f"  Violation example: {rule['violation_example']}")
        lines.append("")

    lines.append("TLP (TRAFFIC LIGHT PROTOCOL) MARKINGS")
    lines.append("-" * 60)
    for tlp_id, tlp in TLP_LEVELS.items():
        lines.append(f"* {tlp_id}: {tlp['description']}")
        lines.append(f"  Sharing: {tlp['sharing']}")
        lines.append("")
    lines.append("TLP Assignment Rules:")
    for rule in TLP_ASSIGNMENT_RULES:
        lines.append(f"  - {rule}")
    lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    n_types = len(SIGNAL_TYPES)
    n_cats = len(SOURCE_CATEGORY_MAP)
    n_levels = len(CONFIDENCE_LEVELS)
    n_rules = len(CORROBORATION_RULES)
    print(
        f"Processing schemas: {n_types} signal types, "
        f"{n_cats} source categories, {n_levels} confidence levels, "
        f"{n_rules} corroboration rules"
    )
