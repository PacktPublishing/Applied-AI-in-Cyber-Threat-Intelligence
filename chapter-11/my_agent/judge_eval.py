"""
Independent Judge Calibration Evaluation — Dissemination Stage
Intel Cycle AI — ApexCode Solutions

Tests the Routing Judge against dissemination plans with known-correct verdicts.
Measures whether the judge correctly identifies classification violations,
routing rule violations, missing mandatory stakeholders, over-routing, and
confidence-gated routing errors.

Usage (from project root):
    python "Stage 6 Dissemination/judge_eval.py"
"""

import asyncio
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

try:
    from .agent import (
        JUDGE_INSTRUCTION,
        DisseminationVerdict,
        APP_NAME,
        USER_ID,
        make_judge_agent,
    )
    from .stakeholder_directory import (
        STAKEHOLDERS,
        ROUTING_RULES,
        NOTIFICATION_ORDER,
        CLASSIFICATION_MAP,
        CLASSIFICATION_HIERARCHY,
        CONFIDENCE_ROUTING,
        check_classification_compliance,
    )
except ImportError:
    from agent import (
        JUDGE_INSTRUCTION,
        DisseminationVerdict,
        APP_NAME,
        USER_ID,
        make_judge_agent,
    )
    from stakeholder_directory import (
        STAKEHOLDERS,
        ROUTING_RULES,
        NOTIFICATION_ORDER,
        CLASSIFICATION_MAP,
        CLASSIFICATION_HIERARCHY,
        CONFIDENCE_ROUTING,
        check_classification_compliance,
    )
from pydantic import ValidationError
from google.adk import Agent, Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Eval uses non-persistent sessions — no disk accumulation, no data mixing
# with production sessions.
session_service = InMemorySessionService()


# ---------------------------------------------------------------------------
# Test cases — dissemination plans with known-correct verdicts
# ---------------------------------------------------------------------------

TEST_CASES = [
    # ------------------------------------------------------------------
    # PASS cases (3)
    # ------------------------------------------------------------------
    {
        "name": "clean_aitm_routing",
        "description": "AiTM scenario, HIGH confidence, 5 stakeholders correctly routed with proper classification and actions",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["deploy detection rule", "escalate to incident response"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Operational intel on AiTM session hijacking requires SOC triage and detection deployment.",
                    "ioc_included": True,
                    "brief_summary": "AiTM proxy phishing compromised partner Okta session. Evilginx2 infrastructure identified at 185.220.101.42. Deploy detection for Tor exit node authentication and session cookie reuse patterns."
                },
                {
                    "stakeholder_id": "ciso",
                    "classification": "CONFIDENTIAL",
                    "actions": ["activate incident response plan", "authorize public disclosure"],
                    "delivery_channel": "secure_portal",
                    "rationale": "HIGH confidence incident requiring executive authorization for IR plan activation and partner notification.",
                    "ioc_included": False,
                    "brief_summary": "Partner developer account compromised via AiTM phishing. 12 private repositories accessed. Recommend activating IR plan and authorizing partner notification."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "CONFIDENTIAL",
                    "actions": ["scope retrospective hunt", "map adversary TTPs"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Tactical intel with IOCs for retrospective hunting across endpoint and network telemetry.",
                    "ioc_included": True,
                    "brief_summary": "AiTM session hijacking via Evilginx2. Hunt for additional compromised sessions from 185.220.101.42 and related Tor exit nodes. Map TTPs to MITRE ATT&CK T1557.003."
                },
                {
                    "stakeholder_id": "vp_cloud_engineering",
                    "classification": "CONFIDENTIAL",
                    "actions": ["rotate credentials", "revoke access"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "GitHub repository access compromise requires credential rotation and access revocation for affected repos.",
                    "ioc_included": True,
                    "brief_summary": "12 private GitHub repositories cloned via compromised partner session. Rotate all PATs and deploy keys for affected repos. Review IAM permissions for partner service accounts."
                },
                {
                    "stakeholder_id": "third_party_risk",
                    "classification": "CONFIDENTIAL",
                    "actions": ["restrict partner access", "request vendor security assessment"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Partner account was the attack vector. Third-party risk assessment and access restriction required.",
                    "ioc_included": False,
                    "brief_summary": "Partner developer account compromised via AiTM phishing. Restrict partner access pending security assessment. Update vendor risk rating."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "general_counsel", "reason": "No contractual breach or legal liability indicated at this time."},
                {"stakeholder_id": "head_of_product", "reason": "No product roadmap or customer-facing service impact."},
                {"stakeholder_id": "corporate_comms", "reason": "No public disclosure risk — internal incident with partner."},
                {"stakeholder_id": "privacy_dpo", "reason": "No PII exposure detected."},
                {"stakeholder_id": "hr_operations", "reason": "No insider threat — external threat actor."}
            ],
            "notification_sequence": ["soc_manager", "threat_hunt_lead", "ciso", "vp_cloud_engineering", "third_party_risk"]
        }, indent=2),
        "expected_verdict": "PASS",
        "expected_reason": "All 5 stakeholders correctly routed with classification at or below clearance, valid actions, proper channels, and IOC handling per RR-005.",
    },
    {
        "name": "low_confidence_minimal_routing",
        "description": "LOW confidence single-signal phishing — only SOC Manager + Threat Hunt Lead (RR-008 compliant)",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "LOW",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["brief analysts on new TTP", "tune existing detections"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "LOW confidence phishing signal requires SOC awareness but not full escalation.",
                    "ioc_included": True,
                    "brief_summary": "Single blocked phishing email with impostor classification targeting engineering team. No click or delivery confirmed. Monitor for follow-on activity."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "CONFIDENTIAL",
                    "actions": ["develop hunt hypothesis", "recommend detection gaps"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "LOW confidence signal warrants hunt hypothesis development for proactive detection.",
                    "ioc_included": True,
                    "brief_summary": "Newly registered lookalike domain detected 1 day before phishing attempt. Develop hunt hypothesis for additional infrastructure and delivery attempts."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "ciso", "reason": "LOW confidence — insufficient evidence for executive escalation per RR-008."},
                {"stakeholder_id": "vp_cloud_engineering", "reason": "LOW confidence — no infrastructure compromise confirmed."},
                {"stakeholder_id": "general_counsel", "reason": "LOW confidence — no legal implications confirmed."},
                {"stakeholder_id": "head_of_product", "reason": "LOW confidence — no product impact."},
                {"stakeholder_id": "corporate_comms", "reason": "LOW confidence — no public disclosure risk."},
                {"stakeholder_id": "third_party_risk", "reason": "LOW confidence — no partner involvement confirmed."},
                {"stakeholder_id": "privacy_dpo", "reason": "LOW confidence — no PII exposure."},
                {"stakeholder_id": "hr_operations", "reason": "LOW confidence — no insider threat."}
            ],
            "notification_sequence": ["soc_manager", "threat_hunt_lead"]
        }, indent=2),
        "expected_verdict": "PASS",
        "expected_reason": "LOW confidence correctly limits routing to SOC Manager and Threat Hunt Lead per RR-008 confidence-gated routing.",
    },
    {
        "name": "restricted_product_restricted_only",
        "description": "RESTRICTED product routed only to RESTRICTED-cleared recipients — not penalized for missing lower-clearance stakeholders",
        "dissemination_plan": json.dumps({
            "product_classification": "RESTRICTED",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "RESTRICTED",
                    "actions": ["escalate to incident response", "deploy detection rule"],
                    "delivery_channel": "war_room",
                    "rationale": "RESTRICTED operational intel on active APT compromise requires immediate SOC escalation.",
                    "ioc_included": True,
                    "brief_summary": "Active APT intrusion detected in production environment. Nation-state actor with custom tooling. Escalate to IR immediately."
                },
                {
                    "stakeholder_id": "ciso",
                    "classification": "RESTRICTED",
                    "actions": ["declare security incident", "engage external IR firm"],
                    "delivery_channel": "in_person",
                    "rationale": "Active APT compromise requires CISO declaration and external IR engagement.",
                    "ioc_included": False,
                    "brief_summary": "Nation-state APT confirmed in production environment. Recommend declaring security incident and engaging external IR firm."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "RESTRICTED",
                    "actions": ["scope retrospective hunt", "analyze endpoint telemetry"],
                    "delivery_channel": "war_room",
                    "rationale": "Full IOC set for retrospective hunting across all endpoint telemetry.",
                    "ioc_included": True,
                    "brief_summary": "APT tooling signatures and C2 infrastructure identified. Scope retrospective hunt across all endpoints for lateral movement indicators."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "vp_cloud_engineering", "reason": "CONFIDENTIAL clearance cannot receive RESTRICTED product. Redacted brief will follow via separate channel."},
                {"stakeholder_id": "general_counsel", "reason": "CONFIDENTIAL clearance cannot receive RESTRICTED product."},
                {"stakeholder_id": "head_of_product", "reason": "INTERNAL clearance cannot receive RESTRICTED product."},
                {"stakeholder_id": "corporate_comms", "reason": "INTERNAL clearance cannot receive RESTRICTED product."},
                {"stakeholder_id": "third_party_risk", "reason": "CONFIDENTIAL clearance cannot receive RESTRICTED product."},
                {"stakeholder_id": "privacy_dpo", "reason": "CONFIDENTIAL clearance cannot receive RESTRICTED product."},
                {"stakeholder_id": "hr_operations", "reason": "CONFIDENTIAL clearance cannot receive RESTRICTED product."}
            ],
            "notification_sequence": ["soc_manager", "threat_hunt_lead", "ciso"]
        }, indent=2),
        "expected_verdict": "PASS",
        "expected_reason": "RESTRICTED product correctly limits distribution to RESTRICTED-cleared recipients only; excluding lower-clearance stakeholders is compliant with RR-004.",
    },

    # ------------------------------------------------------------------
    # Classification FAIL cases (3)
    # ------------------------------------------------------------------
    {
        "name": "restricted_to_confidential_recipient",
        "description": "RESTRICTED brief sent to VP Cloud Engineering (CONFIDENTIAL clearance) — violates RR-004",
        "dissemination_plan": json.dumps({
            "product_classification": "RESTRICTED",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "RESTRICTED",
                    "actions": ["escalate to incident response"],
                    "delivery_channel": "war_room",
                    "rationale": "Active APT requires immediate SOC escalation.",
                    "ioc_included": True,
                    "brief_summary": "Active APT in production. Escalate immediately."
                },
                {
                    "stakeholder_id": "ciso",
                    "classification": "RESTRICTED",
                    "actions": ["declare security incident"],
                    "delivery_channel": "in_person",
                    "rationale": "CISO must declare incident.",
                    "ioc_included": False,
                    "brief_summary": "Nation-state APT confirmed. Declare security incident."
                },
                {
                    "stakeholder_id": "vp_cloud_engineering",
                    "classification": "RESTRICTED",
                    "actions": ["rotate credentials", "isolate workload"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Cloud infrastructure compromised — credential rotation needed.",
                    "ioc_included": True,
                    "brief_summary": "APT accessed production cloud infrastructure via compromised IAM role. Rotate all credentials and isolate affected workloads."
                }
            ],
            "excluded_stakeholders": [],
            "notification_sequence": ["soc_manager", "ciso", "vp_cloud_engineering"]
        }, indent=2),
        "expected_verdict": "FAIL",
        "expected_reason": "VP Cloud Engineering has CONFIDENTIAL clearance but received a RESTRICTED brief, violating RR-004.",
    },
    {
        "name": "restricted_to_internal_recipient",
        "description": "RESTRICTED brief sent to Head of Product (INTERNAL clearance) — violates RR-004",
        "dissemination_plan": json.dumps({
            "product_classification": "RESTRICTED",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "RESTRICTED",
                    "actions": ["escalate to incident response"],
                    "delivery_channel": "war_room",
                    "rationale": "Operational intel requires SOC escalation.",
                    "ioc_included": True,
                    "brief_summary": "Active compromise detected. Escalate to IR."
                },
                {
                    "stakeholder_id": "head_of_product",
                    "classification": "RESTRICTED",
                    "actions": ["delay product launch"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Product launch delay due to security incident in release pipeline.",
                    "ioc_included": False,
                    "brief_summary": "Security incident affecting CI/CD pipeline. Recommend delaying product launch until remediation complete."
                }
            ],
            "excluded_stakeholders": [],
            "notification_sequence": ["soc_manager", "head_of_product"]
        }, indent=2),
        "expected_verdict": "FAIL",
        "expected_reason": "Head of Product has INTERNAL clearance but received a RESTRICTED brief, violating RR-004.",
    },
    {
        "name": "confidential_to_internal_recipient",
        "description": "CONFIDENTIAL brief sent to Corporate Comms (INTERNAL clearance) — violates RR-004",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["deploy detection rule", "escalate to incident response"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "SOC needs detection updates for BEC campaign.",
                    "ioc_included": True,
                    "brief_summary": "BEC campaign targeting finance team. Deploy inbox rule detection and escalate."
                },
                {
                    "stakeholder_id": "corporate_comms",
                    "classification": "CONFIDENTIAL",
                    "actions": ["draft holding statement", "prepare external messaging"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "BEC campaign may become public if customer payments are redirected.",
                    "ioc_included": False,
                    "brief_summary": "Business email compromise targeting finance. Customer payment redirection risk. Prepare holding statement for potential media inquiries."
                }
            ],
            "excluded_stakeholders": [],
            "notification_sequence": ["soc_manager", "corporate_comms"]
        }, indent=2),
        "expected_verdict": "FAIL",
        "expected_reason": "Corporate Comms has INTERNAL clearance but received a CONFIDENTIAL brief, violating RR-004.",
    },

    # ------------------------------------------------------------------
    # Routing FAIL cases (3)
    # ------------------------------------------------------------------
    {
        "name": "iocs_to_general_counsel",
        "description": "Technical IOCs (IP addresses, hashes) included in General Counsel brief — violates RR-005",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["deploy detection rule", "escalate to incident response"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Operational intel for SOC triage.",
                    "ioc_included": True,
                    "brief_summary": "Partner data breach via compromised API key. Deploy detection for exfiltration from 185.220.101.42."
                },
                {
                    "stakeholder_id": "general_counsel",
                    "classification": "CONFIDENTIAL",
                    "actions": ["review contract obligations", "assess legal liability"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Partner contract breach implications require legal review.",
                    "ioc_included": True,
                    "brief_summary": "Partner data accessed from malicious IP 185.220.101.42 using stolen API key a]1b2c3d4e5f6. SHA256 hash of exfiltrated payload: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Review MSA Section 8.2 for breach notification obligations."
                }
            ],
            "excluded_stakeholders": [],
            "notification_sequence": ["soc_manager", "general_counsel"]
        }, indent=2),
        "expected_verdict": "FAIL",
        "expected_reason": "General Counsel is a non-technical stakeholder but received a brief with ioc_included=true containing raw IPs and hashes, violating RR-005.",
    },
    {
        "name": "wrong_action_types",
        "description": "SOC Manager given General Counsel's actions — wrong action types for the stakeholder",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["review contract obligations", "assess legal liability"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "SOC Manager needs to review partner contract for breach notification.",
                    "ioc_included": True,
                    "brief_summary": "Partner account compromised. Review contract obligations for notification timeline."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "CONFIDENTIAL",
                    "actions": ["scope retrospective hunt"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Hunt for additional compromised sessions.",
                    "ioc_included": True,
                    "brief_summary": "Hunt for additional indicators of AiTM phishing across email telemetry."
                }
            ],
            "excluded_stakeholders": [],
            "notification_sequence": ["soc_manager", "threat_hunt_lead"]
        }, indent=2),
        "expected_verdict": "FAIL",
        "expected_reason": "SOC Manager was assigned 'review contract obligations' and 'assess legal liability' which are General Counsel actions, not in SOC Manager's allowed_actions list.",
    },
    {
        "name": "corporate_comms_no_public_risk",
        "description": "Corporate Comms included for purely internal incident with no public disclosure risk — violates RR-003",
        "dissemination_plan": json.dumps({
            "product_classification": "INTERNAL",
            "product_confidence": "MEDIUM",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "INTERNAL",
                    "actions": ["deploy detection rule", "tune existing detections"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Internal detection rule needs tuning for false positive reduction.",
                    "ioc_included": True,
                    "brief_summary": "Internal SIEM rule generating false positives on legitimate developer activity. Tune threshold and deploy updated rule."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "INTERNAL",
                    "actions": ["recommend detection gaps"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Hunt lead can identify detection gaps exposed by the false positive pattern.",
                    "ioc_included": True,
                    "brief_summary": "False positive pattern reveals gap in developer activity baselining. Recommend updated detection logic."
                },
                {
                    "stakeholder_id": "corporate_comms",
                    "classification": "INTERNAL",
                    "actions": ["draft holding statement"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Keeping comms informed of internal security tuning activities.",
                    "ioc_included": False,
                    "brief_summary": "Internal security detection tuning in progress. No customer or external impact."
                }
            ],
            "excluded_stakeholders": [],
            "notification_sequence": ["soc_manager", "threat_hunt_lead", "corporate_comms"]
        }, indent=2),
        "expected_verdict": "FAIL",
        "expected_reason": "Corporate Comms was routed for a purely internal detection tuning activity with no public disclosure risk, violating RR-003.",
    },

    # ------------------------------------------------------------------
    # PARTIAL cases (3)
    # ------------------------------------------------------------------
    {
        "name": "missing_soc_manager",
        "description": "Operational intel product missing SOC Manager — violates RR-001 mandatory routing",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "ciso",
                    "classification": "CONFIDENTIAL",
                    "actions": ["activate incident response plan"],
                    "delivery_channel": "secure_portal",
                    "rationale": "HIGH confidence incident requiring CISO authorization.",
                    "ioc_included": False,
                    "brief_summary": "Credential compromise via supply chain attack. Activate IR plan."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "CONFIDENTIAL",
                    "actions": ["scope retrospective hunt", "map adversary TTPs"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Hunt for additional supply chain compromise indicators.",
                    "ioc_included": True,
                    "brief_summary": "Supply chain compromise via malicious npm package. Hunt for additional infected dependencies across CI/CD."
                },
                {
                    "stakeholder_id": "vp_cloud_engineering",
                    "classification": "CONFIDENTIAL",
                    "actions": ["rotate credentials", "revoke access"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Compromised CI/CD pipeline requires credential rotation.",
                    "ioc_included": True,
                    "brief_summary": "Malicious npm package deployed via CI/CD. Rotate all pipeline credentials and revoke compromised service account."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "soc_manager", "reason": "CISO handling directly."}
            ],
            "notification_sequence": ["ciso", "threat_hunt_lead", "vp_cloud_engineering"]
        }, indent=2),
        "expected_verdict": "PARTIAL",
        "expected_reason": "SOC Manager omitted from operational intel routing, violating RR-001 which mandates SOC Manager for all operational/tactical products.",
    },
    {
        "name": "missing_general_counsel_contract_breach",
        "description": "Partner contract breach indicated but General Counsel not routed — violates RR-002",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["escalate to incident response", "coordinate with partner SOC"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Partner account compromise requires SOC coordination.",
                    "ioc_included": True,
                    "brief_summary": "Partner developer account used to exfiltrate proprietary source code. Coordinate with partner SOC for joint investigation."
                },
                {
                    "stakeholder_id": "ciso",
                    "classification": "CONFIDENTIAL",
                    "actions": ["activate incident response plan"],
                    "delivery_channel": "secure_portal",
                    "rationale": "Source code exfiltration via partner breach requires IR activation.",
                    "ioc_included": False,
                    "brief_summary": "Partner MSA Section 12.1 breach — proprietary source code exfiltrated via compromised partner credentials. Partner contractual obligations for breach notification apply."
                },
                {
                    "stakeholder_id": "third_party_risk",
                    "classification": "CONFIDENTIAL",
                    "actions": ["restrict partner access", "request vendor security assessment"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Partner access must be restricted pending investigation.",
                    "ioc_included": False,
                    "brief_summary": "Partner security controls failed. Restrict all partner access and request immediate vendor security assessment."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "general_counsel", "reason": "Not needed — third-party risk handling partner relationship."}
            ],
            "notification_sequence": ["soc_manager", "ciso", "third_party_risk"]
        }, indent=2),
        "expected_verdict": "PARTIAL",
        "expected_reason": "General Counsel omitted despite explicit partner MSA breach and contractual notification obligations, violating RR-002.",
    },
    {
        "name": "missing_privacy_dpo_pii_exposure",
        "description": "PII exposure indicated but Privacy/DPO not routed — violates RR-006",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "HIGH",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["escalate to incident response", "deploy detection rule"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Database exfiltration with PII requires immediate SOC response.",
                    "ioc_included": True,
                    "brief_summary": "Production database containing 50,000 customer PII records (names, emails, SSNs) exfiltrated via SQL injection. Deploy WAF rules and escalate."
                },
                {
                    "stakeholder_id": "ciso",
                    "classification": "CONFIDENTIAL",
                    "actions": ["declare security incident", "invoke cyber insurance"],
                    "delivery_channel": "secure_portal",
                    "rationale": "PII breach with regulatory notification implications requires CISO declaration.",
                    "ioc_included": False,
                    "brief_summary": "50,000 customer PII records exfiltrated. GDPR Article 33 requires supervisory authority notification within 72 hours. Declare incident and invoke cyber insurance."
                },
                {
                    "stakeholder_id": "vp_cloud_engineering",
                    "classification": "CONFIDENTIAL",
                    "actions": ["patch vulnerability", "revoke access"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "SQL injection vulnerability in production database requires immediate patching.",
                    "ioc_included": True,
                    "brief_summary": "SQL injection in customer API endpoint /api/v2/users. Patch vulnerability and revoke compromised database credentials."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "privacy_dpo", "reason": "CISO handling regulatory notification."}
            ],
            "notification_sequence": ["soc_manager", "ciso", "vp_cloud_engineering"]
        }, indent=2),
        "expected_verdict": "PARTIAL",
        "expected_reason": "Privacy/DPO omitted despite 50,000 PII records exfiltrated and GDPR notification obligations, violating RR-006.",
    },

    # ------------------------------------------------------------------
    # Edge cases (3)
    # ------------------------------------------------------------------
    {
        "name": "insider_threat_missing_hr",
        "description": "Insider threat scenario with employee data exfiltration but HR not routed — violates RR-007",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "MEDIUM",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["escalate to incident response", "deploy detection rule"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Insider data exfiltration requires SOC monitoring and escalation.",
                    "ioc_included": True,
                    "brief_summary": "Employee bulk-downloaded 500+ engineering documents and exported 10,000 Salesforce records 2 days after submitting resignation. Deploy DLP alerts for additional exfiltration."
                },
                {
                    "stakeholder_id": "ciso",
                    "classification": "CONFIDENTIAL",
                    "actions": ["activate incident response plan"],
                    "delivery_channel": "secure_portal",
                    "rationale": "Insider threat with potential IP theft requires CISO awareness.",
                    "ioc_included": False,
                    "brief_summary": "Departing employee exfiltrating proprietary data. Recommend activating insider threat response plan."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "CONFIDENTIAL",
                    "actions": ["scope retrospective hunt", "analyze endpoint telemetry"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Retrospective hunt for additional exfiltration channels.",
                    "ioc_included": True,
                    "brief_summary": "Hunt for USB transfers, personal cloud storage uploads, and email forwarding rules for the departing employee over the past 30 days."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "hr_operations", "reason": "Security team handling directly."}
            ],
            "notification_sequence": ["soc_manager", "threat_hunt_lead", "ciso"]
        }, indent=2),
        "expected_verdict": "PARTIAL",
        "expected_reason": "HR Operations omitted for an insider threat scenario involving a departing employee, violating RR-007.",
    },
    {
        "name": "all_stakeholders_low_confidence",
        "description": "All 10 stakeholders routed for LOW confidence scenario — over-routing violates RR-008",
        "dissemination_plan": json.dumps({
            "product_classification": "INTERNAL",
            "product_confidence": "LOW",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "INTERNAL",
                    "actions": ["brief analysts on new TTP"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "SOC awareness of low-confidence signal.",
                    "ioc_included": True,
                    "brief_summary": "Single anomalous DNS query to newly registered domain. Low confidence, monitoring only."
                },
                {
                    "stakeholder_id": "ciso",
                    "classification": "INTERNAL",
                    "actions": ["approve incident response plan"],
                    "delivery_channel": "secure_portal",
                    "rationale": "Executive awareness.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence DNS anomaly detected. No action required at this time."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "INTERNAL",
                    "actions": ["develop hunt hypothesis"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Hunt lead to develop hypothesis.",
                    "ioc_included": True,
                    "brief_summary": "Anomalous DNS query. Develop hunt hypothesis for related infrastructure."
                },
                {
                    "stakeholder_id": "vp_cloud_engineering",
                    "classification": "INTERNAL",
                    "actions": ["review IAM permissions"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Informational awareness.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence DNS anomaly. No infrastructure action needed."
                },
                {
                    "stakeholder_id": "general_counsel",
                    "classification": "INTERNAL",
                    "actions": ["review contract obligations"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Keeping legal informed.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence signal. No legal implications at this time."
                },
                {
                    "stakeholder_id": "head_of_product",
                    "classification": "INTERNAL",
                    "actions": ["assess customer exposure"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Product awareness.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence DNS anomaly. No product impact."
                },
                {
                    "stakeholder_id": "corporate_comms",
                    "classification": "INTERNAL",
                    "actions": ["monitor media coverage"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Comms awareness.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence signal. No public disclosure risk."
                },
                {
                    "stakeholder_id": "third_party_risk",
                    "classification": "INTERNAL",
                    "actions": ["review third-party access logs"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Third-party awareness.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence DNS anomaly. No partner involvement indicated."
                },
                {
                    "stakeholder_id": "privacy_dpo",
                    "classification": "INTERNAL",
                    "actions": ["assess notification obligations"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "Privacy awareness.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence signal. No PII exposure."
                },
                {
                    "stakeholder_id": "hr_operations",
                    "classification": "INTERNAL",
                    "actions": ["document employee conduct"],
                    "delivery_channel": "encrypted_email",
                    "rationale": "HR awareness.",
                    "ioc_included": False,
                    "brief_summary": "Low-confidence DNS anomaly. No insider threat indicated."
                }
            ],
            "excluded_stakeholders": [],
            "notification_sequence": [
                "soc_manager", "threat_hunt_lead", "ciso", "vp_cloud_engineering",
                "third_party_risk", "general_counsel", "privacy_dpo", "hr_operations",
                "head_of_product", "corporate_comms"
            ]
        }, indent=2),
        "expected_verdict": "FAIL",
        "expected_reason": "All 10 stakeholders routed for a LOW confidence signal that should only go to SOC Manager + Threat Hunt Lead per RR-008, massive over-routing.",
    },
    {
        "name": "no_matching_scope_fallback",
        "description": "Product about a system not in any stakeholder's scope — only SOC + Hunt Lead as fallback",
        "dissemination_plan": json.dumps({
            "product_classification": "CONFIDENTIAL",
            "product_confidence": "MEDIUM",
            "routed_stakeholders": [
                {
                    "stakeholder_id": "soc_manager",
                    "classification": "CONFIDENTIAL",
                    "actions": ["brief analysts on new TTP", "update threat model"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "No specific stakeholder scope matches the affected HVAC control system, but SOC must receive all operational intel per RR-001.",
                    "ioc_included": True,
                    "brief_summary": "Anomalous network traffic from building HVAC control system to external IP. No stakeholder directly owns OT/ICS scope. SOC monitoring as fallback."
                },
                {
                    "stakeholder_id": "threat_hunt_lead",
                    "classification": "CONFIDENTIAL",
                    "actions": ["develop hunt hypothesis", "scope retrospective hunt"],
                    "delivery_channel": "siem_ticket",
                    "rationale": "Hunt lead to investigate potential OT/ICS compromise vector despite no direct scope match.",
                    "ioc_included": True,
                    "brief_summary": "HVAC control system communicating with unknown external endpoint. Develop hunt hypothesis for lateral movement from OT to IT network."
                }
            ],
            "excluded_stakeholders": [
                {"stakeholder_id": "ciso", "reason": "MEDIUM confidence, no direct scope match — will escalate if hunt confirms compromise."},
                {"stakeholder_id": "vp_cloud_engineering", "reason": "OT/ICS system, not cloud infrastructure."},
                {"stakeholder_id": "general_counsel", "reason": "No legal implications identified."},
                {"stakeholder_id": "head_of_product", "reason": "No product impact."},
                {"stakeholder_id": "corporate_comms", "reason": "No public disclosure risk."},
                {"stakeholder_id": "third_party_risk", "reason": "No partner involvement confirmed."},
                {"stakeholder_id": "privacy_dpo", "reason": "No PII exposure."},
                {"stakeholder_id": "hr_operations", "reason": "No insider threat."}
            ],
            "notification_sequence": ["soc_manager", "threat_hunt_lead"]
        }, indent=2),
        "expected_verdict": "PARTIAL",
        "expected_reason": "No stakeholder scope covers OT/ICS systems; SOC + Hunt Lead is the correct fallback but CISO should arguably be notified for MEDIUM confidence infrastructure anomalies.",
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def run_judge_on_dissemination_plan(dissemination_plan_text: str) -> dict:
    """Run the judge on a synthetic dissemination plan and return the parsed verdict."""
    judge = make_judge_agent()
    runner = Runner(agent=judge, app_name=APP_NAME, session_service=session_service)

    session_id = f"judge_eval_{uuid.uuid4().hex}"
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={"dissemination_plan": dissemination_plan_text, "dissemination_verdict": ""},
    )

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=session_id,
        new_message=types.Content(
            role="user",
            parts=[types.Part(text="Validate this dissemination plan.")],
        ),
    ):
        pass

    session = await session_service.get_session(
        app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
    )
    verdict_raw = session.state.get("dissemination_verdict", "{}")

    try:
        verdict_dict = json.loads(verdict_raw) if isinstance(verdict_raw, str) else verdict_raw
        validated = DisseminationVerdict.model_validate(verdict_dict)
        return {"valid": True, "verdict": validated.model_dump(), "raw": verdict_raw}
    except (json.JSONDecodeError, TypeError) as e:
        return {"valid": False, "error": f"JSON parse failed: {e}", "raw": verdict_raw}
    except ValidationError as e:
        return {"valid": False, "error": f"Schema validation failed: {e}", "raw": verdict_raw}


def _score_case(case: dict, result: dict) -> dict:
    """Score a single test case against expected outcomes."""
    scores = {"name": case["name"], "passed_checks": [], "failed_checks": []}

    if not result["valid"]:
        scores["failed_checks"].append(f"Judge output invalid: {result['error']}")
        return scores

    verdict = result["verdict"]

    if "expected_verdict" in case:
        if verdict["verdict"] == case["expected_verdict"]:
            scores["passed_checks"].append(f"Verdict correct: {verdict['verdict']}")
        else:
            scores["failed_checks"].append(
                f"Verdict wrong: got {verdict['verdict']}, expected {case['expected_verdict']}"
            )

    # Check structural consistency: FAIL requires non-empty unverified,
    # PARTIAL requires non-empty missing_critical.
    n_unverified = len(verdict.get("unverified", []))
    n_missing = len(verdict.get("missing_critical", []))

    if case["expected_verdict"] == "FAIL" and n_unverified > 0:
        scores["passed_checks"].append(f"Unverified populated for FAIL: {n_unverified} entries")
    elif case["expected_verdict"] == "FAIL" and n_unverified == 0:
        scores["failed_checks"].append(
            "Expected FAIL verdict should have non-empty unverified list"
        )

    if case["expected_verdict"] == "PARTIAL" and n_missing > 0:
        scores["passed_checks"].append(f"Missing_critical populated for PARTIAL: {n_missing} entries")
    elif case["expected_verdict"] == "PARTIAL" and n_missing == 0:
        scores["failed_checks"].append(
            "Expected PARTIAL verdict should have non-empty missing_critical list"
        )

    if case["expected_verdict"] == "PASS" and n_unverified == 0 and n_missing == 0:
        scores["passed_checks"].append("PASS with clean unverified and missing_critical")
    elif case["expected_verdict"] == "PASS" and (n_unverified > 0 or n_missing > 0):
        scores["failed_checks"].append(
            f"PASS verdict but unverified={n_unverified}, missing_critical={n_missing} — should both be empty"
        )

    confirmed = verdict.get("confirmed_valid", [])
    relevance_dist = {}
    for s in confirmed:
        r = s.get("relevance", "UNKNOWN")
        relevance_dist[r] = relevance_dist.get(r, 0) + 1
    if relevance_dist:
        scores["relevance_distribution"] = relevance_dist

    return scores


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    print("=" * 70)
    print("JUDGE CALIBRATION EVALUATION — Dissemination Stage")
    print("Intel Cycle AI — ApexCode Solutions")
    print(f"Test cases: {len(TEST_CASES)}")
    print("Judge model: gemini-2.5-flash @ temp=0.0")
    print("=" * 70)

    total_passed = total_failed = total_checks = schema_failures = 0
    results_log: list[dict] = []

    for i, case in enumerate(TEST_CASES, 1):
        print(f"\n{'---'*20}")
        print(f"Case {i}/{len(TEST_CASES)}: {case['name']}")
        print(f"  {case['description']}")

        result = await run_judge_on_dissemination_plan(case["dissemination_plan"])

        if not result["valid"]:
            print(f"  SCHEMA FAILURE: {result['error'][:200]}")
            schema_failures += 1
            total_failed += 1
            total_checks += 1
            results_log.append({
                "case": case["name"],
                "expected_verdict": case["expected_verdict"],
                "actual_verdict": None,
                "schema_valid": False,
                "error": result["error"][:500],
                "passed_checks": [],
                "failed_checks": [f"Schema failure: {result['error'][:200]}"],
            })
            continue

        verdict = result["verdict"]
        scores = _score_case(case, result)

        n_p = len(scores["passed_checks"])
        n_f = len(scores["failed_checks"])
        total_passed += n_p
        total_failed += n_f
        total_checks += n_p + n_f

        print(f"  Verdict: {verdict['verdict']}  "
              f"(valid={len(verdict['confirmed_valid'])}  "
              f"unverified={len(verdict['unverified'])}  "
              f"missing={len(verdict['missing_critical'])})")

        for check in scores["passed_checks"]:
            print(f"  + {check}")
        for check in scores["failed_checks"]:
            print(f"  - {check}")

        results_log.append({
            "case": case["name"],
            "expected_verdict": case["expected_verdict"],
            "actual_verdict": verdict["verdict"],
            "schema_valid": True,
            "summary": verdict.get("summary", ""),
            "confirmed_valid_count": len(verdict["confirmed_valid"]),
            "unverified_count": len(verdict["unverified"]),
            "missing_critical_count": len(verdict["missing_critical"]),
            "passed_checks": scores["passed_checks"],
            "failed_checks": scores["failed_checks"],
            "relevance_distribution": scores.get("relevance_distribution", {}),
        })

    print(f"\n{'='*70}")
    accuracy = (total_passed / total_checks * 100) if total_checks > 0 else 0
    print(f"RESULTS: {total_passed}/{total_checks} checks passed  "
          f"({total_failed} failed, {schema_failures} schema failures)")
    print(f"Judge accuracy: {accuracy:.0f}%")

    THRESHOLD = 80.0
    if accuracy < THRESHOLD:
        print(f"BELOW THRESHOLD ({THRESHOLD:.0f}%) — FAIL")
    else:
        print(f"ABOVE THRESHOLD ({THRESHOLD:.0f}%) — PASS")
    print("=" * 70)

    # Write results to JSON for downstream analysis.
    results_path = Path(__file__).parent / "judge_eval_results.json"
    results_output = {
        "stage": "Stage 6 Dissemination",
        "total_cases": len(TEST_CASES),
        "total_checks": total_checks,
        "passed_checks": total_passed,
        "failed_checks": total_failed,
        "schema_failures": schema_failures,
        "accuracy_pct": round(accuracy, 1),
        "threshold_pct": THRESHOLD,
        "threshold_met": accuracy >= THRESHOLD,
        "cases": results_log,
    }
    results_path.write_text(json.dumps(results_output, indent=2))
    print(f"\nResults written to {results_path}")

    if accuracy < THRESHOLD:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
