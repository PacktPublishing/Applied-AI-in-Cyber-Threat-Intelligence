"""
Independent Judge Calibration Evaluation — Feedback Stage
Intel Cycle AI — ApexCode Solutions

Tests the Compliance Judge against synthetic QIR arrays with known-correct
verdicts. Measures whether the judge correctly identifies:
  - Missing required fields (template completeness)
  - Compound questions not split into atomic QIRs (TR-001)
  - Missing linked_qir references (TR-002)
  - Scope misclassification (TR-003)
  - Unjustified priority assignments (TR-004)
  - Vague temporal windows (TR-005)
  - Non-actionable feedback producing QIRs (TR-006)

Usage (from the chapter-12/ directory):
    python my_agent/judge_eval.py
"""

import asyncio
import json
import sys
import uuid
from pathlib import Path

_stage7_dir = str(Path(__file__).parent)
if _stage7_dir not in sys.path:
    sys.path.insert(0, _stage7_dir)

from dotenv import load_dotenv
load_dotenv()

try:
    from .agent import (
        FeedbackVerdict,
        APP_NAME,
        USER_ID,
        make_judge_agent,
    )
except ImportError:
    from agent import (
        FeedbackVerdict,
        APP_NAME,
        USER_ID,
        make_judge_agent,
    )
from pydantic import ValidationError
from google.adk import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Eval uses non-persistent sessions — no disk accumulation, no data mixing
# with production sessions.
session_service = InMemorySessionService()


# ---------------------------------------------------------------------------
# Shared original QIR context — all test cases trace to this QIR.
# ---------------------------------------------------------------------------

ORIGINAL_QIR = (
    "QIR-2025-0042: Determine attribution, scope, and business impact of the "
    "AiTM session hijacking incident targeting ApexCode Solutions via partner "
    "developer DevPartner, Inc, including assessment of data exfiltration from "
    "12 private GitHub repositories."
)


# ---------------------------------------------------------------------------
# Test cases — QIR arrays with known-correct verdicts
# ---------------------------------------------------------------------------

TEST_CASES = [
    # ------------------------------------------------------------------
    # Case 1: single_clear_question
    # Single question → 1 well-formed QIR with all fields → PASS
    # ------------------------------------------------------------------
    {
        "name": "single_clear_question",
        "description": "Single question producing 1 well-formed QIR with all 9 fields",
        "stakeholder_feedback": (
            "CISO: Could 50 other vendors be compromised the same way? "
            "We use the same Okta SSO integration with all partner "
            "development shops."
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "CISO",
                "raw_feedback": (
                    "Could 50 other vendors be compromised the same way? "
                    "We use the same Okta SSO integration with all partner "
                    "development shops."
                ),
                "refined_requirement": (
                    "Determine whether the AiTM session hijacking technique "
                    "used against DevPartner, Inc has been employed against any of "
                    "the remaining 49 partner development firms with Okta SSO "
                    "integration, using a 90-day retroactive hunt across "
                    "authentication telemetry."
                ),
                "scope": "EXPANSION",
                "temporal_window": "90-day retroactive hunt across partner authentication logs",
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Active threat actor with ongoing access — the same AiTM "
                    "technique may be in use against other partners, and each "
                    "day without a retroactive hunt extends the window of "
                    "undetected compromise."
                ),
                "linked_qir": "QIR-2025-0042",
            }
        ]),
        "expected_verdict": "PASS",
        "expected_violations": 0,
    },

    # ------------------------------------------------------------------
    # Case 2: compound_not_split
    # "Should we notify AND should we delay?" → compound not split → FAIL
    # ------------------------------------------------------------------
    {
        "name": "compound_not_split",
        "description": "Compound question not split into atomic QIRs — TR-001 violation",
        "stakeholder_feedback": (
            "VP Engineering: Should we notify affected customers under GDPR "
            "AND should we delay the Q3 release for a full security audit?"
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "VP Engineering",
                "raw_feedback": (
                    "Should we notify affected customers under GDPR AND "
                    "should we delay the Q3 release for a full security audit?"
                ),
                "refined_requirement": (
                    "Determine GDPR notification obligations for affected "
                    "customers and assess whether the Q3 release should be "
                    "delayed pending a comprehensive security audit."
                ),
                "scope": "PIVOT",
                "temporal_window": "Assessment within 72-hour GDPR notification window",
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Regulatory notification deadline within 72 hours — GDPR "
                    "Article 33 requires breach notification within 72 hours "
                    "of discovery."
                ),
                "linked_qir": "QIR-2025-0042",
            }
        ]),
        "expected_verdict": "FAIL",
        "expected_min_violations": 1,
        "notes": (
            "TR-001: Two distinct questions (GDPR notification + Q3 release delay) "
            "combined into one QIR. Must be split into 2 QIRs — one PIVOT (GDPR) "
            "and one PIVOT (release delay). The judge should flag the compound "
            "question in unverified and/or missing_critical."
        ),
    },

    # ------------------------------------------------------------------
    # Case 3: missing_temporal_window
    # QIR missing temporal_window field → FAIL
    # ------------------------------------------------------------------
    {
        "name": "missing_temporal_window",
        "description": "QIR missing temporal_window field — template violation",
        "stakeholder_feedback": (
            "SOC Manager: How long did the attacker have access before "
            "we detected it?"
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "SOC Manager",
                "raw_feedback": (
                    "How long did the attacker have access before we "
                    "detected it?"
                ),
                "refined_requirement": (
                    "Determine the full dwell time of the threat actor, "
                    "from initial compromise via AiTM phishing to detection "
                    "of the unauthorized GitHub repository access."
                ),
                "scope": "DEEPENING",
                "temporal_window": "",
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Active incident response in progress — dwell time "
                    "analysis is required to scope the full impact and "
                    "determine whether the attacker may still have access."
                ),
                "linked_qir": "QIR-2025-0042",
            }
        ]),
        "expected_verdict": "FAIL",
        "expected_min_violations": 1,
        "notes": (
            "temporal_window is present but empty string — equivalent to missing. "
            "Judge should identify this as a template violation."
        ),
    },

    # ------------------------------------------------------------------
    # Case 4: missing_linked_qir
    # Correct QIR but no linked_qir reference → FAIL
    # ------------------------------------------------------------------
    {
        "name": "missing_linked_qir",
        "description": "QIR with missing linked_qir — TR-002 violation",
        "stakeholder_feedback": (
            "CISO: Are there other attack vectors we haven't monitored?"
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "CISO",
                "raw_feedback": "Are there other attack vectors we haven't monitored?",
                "refined_requirement": (
                    "Identify additional attack vectors beyond AiTM session "
                    "hijacking that may have been used against ApexCode "
                    "Solutions or its partner ecosystem, and assess whether "
                    "current monitoring covers these vectors."
                ),
                "scope": "EXPANSION",
                "temporal_window": "60-day retroactive hunt across all detection telemetry",
                "priority": "ROUTINE",
                "priority_justification": (
                    "Threat contained but root cause analysis incomplete — "
                    "the primary AiTM vector is being addressed, but broader "
                    "attack surface assessment is needed for defensive posture "
                    "improvement."
                ),
                "linked_qir": "",
            }
        ]),
        "expected_verdict": "FAIL",
        "expected_min_violations": 1,
        "notes": (
            "TR-002: linked_qir is empty string — orphaned QIR that does not "
            "trace back to the original requirement. Judge must flag this."
        ),
    },

    # ------------------------------------------------------------------
    # Case 5: two_questions_properly_split
    # Two distinct questions, properly decomposed, all fields → PASS
    # ------------------------------------------------------------------
    {
        "name": "two_questions_properly_split",
        "description": "Two questions properly decomposed into 2 QIRs with all fields",
        "stakeholder_feedback": (
            "CISO: Can we prevent session hijacking entirely with FIDO2? "
            "Also, how long did the attacker have access before detection?"
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "CISO",
                "raw_feedback": "Can we prevent session hijacking entirely with FIDO2?",
                "refined_requirement": (
                    "Evaluate whether deploying FIDO2/WebAuthn hardware "
                    "security keys across all partner SSO integrations would "
                    "have prevented the AiTM session hijacking attack, and "
                    "assess the cost-benefit of enterprise-wide FIDO2 deployment."
                ),
                "scope": "VALIDATION",
                "temporal_window": (
                    "30-day technology evaluation period, including proof-of-concept "
                    "deployment with one partner organization"
                ),
                "priority": "ROUTINE",
                "priority_justification": (
                    "Strategic question about defensive posture improvement — "
                    "threat is contained and FIDO2 deployment is a medium-term "
                    "countermeasure, not an immediate incident response action."
                ),
                "linked_qir": "QIR-2025-0042",
            },
            {
                "qir_id": "FP-002",
                "originator": "CISO",
                "raw_feedback": (
                    "How long did the attacker have access before detection?"
                ),
                "refined_requirement": (
                    "Determine the full dwell time from initial AiTM session "
                    "compromise through detection, including timeline of all "
                    "authenticated actions taken with the hijacked session."
                ),
                "scope": "DEEPENING",
                "temporal_window": (
                    "Full incident window analysis — from first Evilginx2 "
                    "phishing email delivery through detection and containment"
                ),
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Active incident response in progress — dwell time "
                    "determines whether the attacker may still have "
                    "persistent access via additional compromised credentials "
                    "or implanted backdoors."
                ),
                "linked_qir": "QIR-2025-0042",
            },
        ]),
        "expected_verdict": "PASS",
        "expected_violations": 0,
    },

    # ------------------------------------------------------------------
    # Case 6: unjustified_priority
    # Priority set to IMMEDIATE without justification → FAIL
    # ------------------------------------------------------------------
    {
        "name": "unjustified_priority",
        "description": "Priority IMMEDIATE with empty justification — TR-004 violation",
        "stakeholder_feedback": (
            "General Counsel: Do we need to notify affected customers "
            "under GDPR?"
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "General Counsel",
                "raw_feedback": (
                    "Do we need to notify affected customers under GDPR?"
                ),
                "refined_requirement": (
                    "Determine whether the data accessed from the 12 "
                    "compromised GitHub repositories includes personal data "
                    "of EU residents that would trigger GDPR Article 34 "
                    "notification obligations."
                ),
                "scope": "PIVOT",
                "temporal_window": "Assessment within 72-hour GDPR notification window",
                "priority": "IMMEDIATE",
                "priority_justification": "",
                "linked_qir": "QIR-2025-0042",
            }
        ]),
        "expected_verdict": "FAIL",
        "expected_min_violations": 1,
        "notes": (
            "TR-004: Priority is IMMEDIATE but priority_justification is empty. "
            "Every priority must include explicit justification grounded in "
            "operational impact. Judge should flag this in unverified."
        ),
    },

    # ------------------------------------------------------------------
    # Case 7: wrong_scope_classification
    # Scope classified as EXPANSION when it's clearly a PIVOT → tests calibration
    # ------------------------------------------------------------------
    {
        "name": "wrong_scope_classification",
        "description": "GDPR notification classified as EXPANSION instead of PIVOT — TR-003",
        "stakeholder_feedback": (
            "General Counsel: Do we need to notify affected customers "
            "under GDPR?"
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "General Counsel",
                "raw_feedback": (
                    "Do we need to notify affected customers under GDPR?"
                ),
                "refined_requirement": (
                    "Determine whether the data accessed from the 12 "
                    "compromised GitHub repositories includes personal data "
                    "of EU residents that would trigger GDPR Article 34 "
                    "notification obligations."
                ),
                "scope": "EXPANSION",
                "temporal_window": "Assessment within 72-hour GDPR notification window",
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Regulatory notification deadline within 72 hours — "
                    "GDPR Article 33 requires breach notification within "
                    "72 hours of discovery, creating a hard deadline."
                ),
                "linked_qir": "QIR-2025-0042",
            }
        ]),
        "expected_verdict_options": ["PARTIAL", "FAIL"],
        "expected_min_violations": 1,
        "notes": (
            "TR-003: GDPR notification is a PIVOT (introduces legal/regulatory "
            "domain), not EXPANSION. EXPANSION means 'more of the same entities'; "
            "this question introduces a fundamentally different problem space. "
            "Expected verdict is PARTIAL (scope misclassification per BUILD_PLAN "
            "judge semantics) but FAIL is also acceptable if the judge treats "
            "misclassification as a more severe violation."
        ),
    },

    # ------------------------------------------------------------------
    # Case 8: praise_no_question
    # Feedback is just praise, no actionable question → should produce 0 QIRs
    # ------------------------------------------------------------------
    {
        "name": "praise_no_question",
        "description": "Non-actionable feedback (praise only) should produce 0 QIRs",
        "stakeholder_feedback": (
            "VP Engineering: Great work on the threat briefing. Very thorough "
            "analysis and the recommendations are clear. The team appreciated "
            "the detailed timeline."
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "VP Engineering",
                "raw_feedback": (
                    "Great work on the threat briefing. Very thorough "
                    "analysis and the recommendations are clear."
                ),
                "refined_requirement": (
                    "Validate that the threat briefing methodology meets "
                    "stakeholder expectations for thoroughness and clarity."
                ),
                "scope": "VALIDATION",
                "temporal_window": "Retrospective review of current briefing cycle",
                "priority": "DEFERRED",
                "priority_justification": (
                    "Nice-to-know rather than need-to-know — feedback is "
                    "positive acknowledgment, not an intelligence gap."
                ),
                "linked_qir": "QIR-2025-0042",
            }
        ]),
        "expected_verdict": "FAIL",
        "expected_min_violations": 1,
        "notes": (
            "TR-006: Feedback contains no actionable question or intelligence "
            "requirement. The transformation agent fabricated a QIR from praise. "
            "Judge should identify this as a TR-006 violation — non-actionable "
            "feedback should produce 0 QIRs."
        ),
    },

    # ------------------------------------------------------------------
    # Case 9: five_questions_decomposed
    # Five questions from CISO, properly decomposed into 5 QIRs → PASS
    # ------------------------------------------------------------------
    {
        "name": "five_questions_decomposed",
        "description": "CISO compound feedback properly decomposed into 5 atomic QIRs",
        "stakeholder_feedback": (
            "CISO compound feedback:\n"
            "1. Could 50 other vendors be compromised the same way?\n"
            "2. Can we prevent session hijacking entirely with FIDO2?\n"
            "3. How long did the attacker have access before we detected it?\n"
            "4. Can we detect if the attacker planted backdoors in our repos?\n"
            "5. What's our exposure if the stolen code is published?"
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "CISO",
                "raw_feedback": "Could 50 other vendors be compromised the same way?",
                "refined_requirement": (
                    "Determine whether the AiTM technique has been employed "
                    "against any of the remaining 49 partner firms with Okta "
                    "SSO integration."
                ),
                "scope": "EXPANSION",
                "temporal_window": "90-day retroactive hunt across partner authentication logs",
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Active threat actor with ongoing access — the same "
                    "technique may be in use against other partners."
                ),
                "linked_qir": "QIR-2025-0042",
            },
            {
                "qir_id": "FP-002",
                "originator": "CISO",
                "raw_feedback": "Can we prevent session hijacking entirely with FIDO2?",
                "refined_requirement": (
                    "Evaluate whether FIDO2/WebAuthn deployment would have "
                    "prevented the AiTM attack and assess enterprise-wide "
                    "deployment cost-benefit."
                ),
                "scope": "VALIDATION",
                "temporal_window": "30-day technology evaluation period",
                "priority": "ROUTINE",
                "priority_justification": (
                    "Strategic question about defensive posture improvement — "
                    "threat is contained, FIDO2 is a medium-term countermeasure."
                ),
                "linked_qir": "QIR-2025-0042",
            },
            {
                "qir_id": "FP-003",
                "originator": "CISO",
                "raw_feedback": (
                    "How long did the attacker have access before we detected it?"
                ),
                "refined_requirement": (
                    "Determine full dwell time from initial AiTM compromise "
                    "through detection, including timeline of authenticated "
                    "actions during the compromised session."
                ),
                "scope": "DEEPENING",
                "temporal_window": (
                    "Full incident window — from phishing email delivery "
                    "through containment"
                ),
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Active incident response — dwell time determines whether "
                    "the attacker may still have persistent access."
                ),
                "linked_qir": "QIR-2025-0042",
            },
            {
                "qir_id": "FP-004",
                "originator": "CISO",
                "raw_feedback": (
                    "Can we detect if the attacker planted backdoors in our repos?"
                ),
                "refined_requirement": (
                    "Perform code integrity analysis on the 12 compromised "
                    "repositories to identify any unauthorized modifications, "
                    "backdoors, or malicious commits introduced during the "
                    "compromised session window."
                ),
                "scope": "DEEPENING",
                "temporal_window": (
                    "Retroactive analysis of all commits during incident "
                    "window, plus continuous monitoring for 30 days post-incident"
                ),
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Confirmed data exposure with unknown blast radius — "
                    "backdoors in production repositories represent ongoing "
                    "supply chain risk."
                ),
                "linked_qir": "QIR-2025-0042",
            },
            {
                "qir_id": "FP-005",
                "originator": "CISO",
                "raw_feedback": "What's our exposure if the stolen code is published?",
                "refined_requirement": (
                    "Assess the business and security impact if the source "
                    "code exfiltrated from the 12 private repositories is "
                    "published, including IP exposure, credential leakage in "
                    "code, and competitive risk."
                ),
                "scope": "EXPANSION",
                "temporal_window": (
                    "Impact assessment within 5 business days, with continuous "
                    "monitoring of paste sites and dark web forums for 90 days"
                ),
                "priority": "IMMEDIATE",
                "priority_justification": (
                    "Confirmed data exposure with unknown blast radius — "
                    "stolen source code publication could expose credentials, "
                    "API keys, and proprietary algorithms."
                ),
                "linked_qir": "QIR-2025-0042",
            },
        ]),
        "expected_verdict": "PASS",
        "expected_violations": 0,
    },

    # ------------------------------------------------------------------
    # Case 10: already_answered_question
    # Question already addressed by existing QIR → should classify as VALIDATION
    # ------------------------------------------------------------------
    {
        "name": "already_answered_question",
        "description": "Question testing an existing finding should be VALIDATION scope",
        "stakeholder_feedback": (
            "SOC Manager: Can we confirm that the MFA bypass was specifically "
            "AiTM and not a different technique? The briefing concluded it was "
            "Evilginx2 but I want to validate that conclusion."
        ),
        "feedback_qirs": json.dumps([
            {
                "qir_id": "FP-001",
                "originator": "SOC Manager",
                "raw_feedback": (
                    "Can we confirm that the MFA bypass was specifically AiTM "
                    "and not a different technique? The briefing concluded it "
                    "was Evilginx2 but I want to validate that conclusion."
                ),
                "refined_requirement": (
                    "Validate the attribution of the MFA bypass to AiTM via "
                    "Evilginx2 by cross-referencing phishing infrastructure "
                    "indicators with known Evilginx2 signatures and ruling "
                    "out alternative MFA bypass techniques (push fatigue, "
                    "SIM swap, real-time phishing without proxy)."
                ),
                "scope": "VALIDATION",
                "temporal_window": (
                    "Focused validation within 5 business days, reviewing "
                    "existing evidence artifacts from the original investigation"
                ),
                "priority": "ROUTINE",
                "priority_justification": (
                    "Threat contained but root cause analysis incomplete — "
                    "confirming the exact technique strengthens attribution "
                    "confidence but does not change the immediate response."
                ),
                "linked_qir": "QIR-2025-0042",
            }
        ]),
        "expected_verdict": "PASS",
        "expected_violations": 0,
        "expected_scope": "VALIDATION",
        "notes": (
            "The stakeholder is explicitly asking to validate an existing "
            "conclusion from the briefing. This is a VALIDATION scope question — "
            "it asks WHETHER the attribution is correct, not for new entities "
            "(EXPANSION) or more detail (DEEPENING)."
        ),
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def run_judge_on_feedback_qirs(
    feedback_qirs_text: str,
    stakeholder_feedback: str,
) -> dict:
    """Run the judge on a synthetic QIR array and return the parsed verdict."""
    judge = make_judge_agent()
    runner = Runner(agent=judge, app_name=APP_NAME, session_service=session_service)

    session_id = f"judge_eval_{uuid.uuid4().hex}"
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "feedback_qirs": feedback_qirs_text,
            "feedback_verdict": "",
            "original_qir": ORIGINAL_QIR,
            "stakeholder_feedback": stakeholder_feedback,
        },
    )

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=session_id,
        new_message=types.Content(
            role="user",
            parts=[types.Part(text="Validate these follow-on QIRs.")],
        ),
    ):
        pass

    session = await session_service.get_session(
        app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
    )
    verdict_raw = session.state.get("feedback_verdict", {})

    try:
        verdict_dict = (
            verdict_raw if isinstance(verdict_raw, dict)
            else json.loads(verdict_raw)
        )
        validated = FeedbackVerdict.model_validate(verdict_dict)
        return {"valid": True, "verdict": validated.model_dump(), "raw": verdict_raw}
    except (json.JSONDecodeError, TypeError) as e:
        return {"valid": False, "error": f"JSON parse failed: {e}", "raw": verdict_raw}
    except ValidationError as e:
        return {"valid": False, "error": f"Schema validation failed: {e}", "raw": verdict_raw}


def _score_case(case: dict, result: dict) -> dict:
    """Score a single test case against expected outcomes.

    Supports:
      - expected_verdict (exact match)
      - expected_verdict_options (any of N acceptable verdicts)
      - expected_violations (exact count)
      - expected_min_violations (at-least count)
      - expected_scope (scope of the first confirmed QIR)
    """
    scores = {"name": case["name"], "passed_checks": [], "failed_checks": []}

    if not result["valid"]:
        scores["failed_checks"].append(f"Judge output invalid: {result['error']}")
        return scores

    verdict = result["verdict"]

    # Verdict check — exact match or options list.
    if "expected_verdict" in case:
        if verdict["verdict"] == case["expected_verdict"]:
            scores["passed_checks"].append(f"Verdict correct: {verdict['verdict']}")
        else:
            scores["failed_checks"].append(
                f"Verdict wrong: got {verdict['verdict']}, "
                f"expected {case['expected_verdict']}"
            )
    elif "expected_verdict_options" in case:
        if verdict["verdict"] in case["expected_verdict_options"]:
            scores["passed_checks"].append(
                f"Verdict acceptable: {verdict['verdict']} "
                f"(in {case['expected_verdict_options']})"
            )
        else:
            scores["failed_checks"].append(
                f"Verdict wrong: got {verdict['verdict']}, "
                f"expected one of {case['expected_verdict_options']}"
            )

    # Violation count check — count both unverified and missing_critical as
    # violations. The judge may surface issues in either bucket depending on
    # whether the problem is a malformed QIR (unverified) or an uncaptured
    # question (missing_critical). Both represent non-PASS conditions.
    n_unverified = len(verdict.get("unverified", []))
    n_missing = len(verdict.get("missing_critical", []))
    n_violations = n_unverified + n_missing

    if "expected_violations" in case:
        if n_violations == case["expected_violations"]:
            scores["passed_checks"].append(
                f"Violation count correct: {n_violations} "
                f"(unverified={n_unverified}, missing={n_missing})"
            )
        else:
            scores["failed_checks"].append(
                f"Violation count wrong: got {n_violations} "
                f"(unverified={n_unverified}, missing={n_missing}), "
                f"expected {case['expected_violations']}"
            )
    elif "expected_min_violations" in case:
        min_v = case["expected_min_violations"]
        if n_violations >= min_v:
            scores["passed_checks"].append(
                f"Violation count adequate: {n_violations} >= {min_v} "
                f"(unverified={n_unverified}, missing={n_missing})"
            )
        else:
            scores["failed_checks"].append(
                f"Violation count insufficient: got {n_violations} "
                f"(unverified={n_unverified}, missing={n_missing}), "
                f"expected >= {min_v}"
            )

    # Scope classification check — verify the judge *accepted* the scope
    # (QIR appears in confirmed_valid, not unverified for scope reasons).
    # If the input QIR has the expected scope AND the judge confirmed it,
    # the scope is validated. If the judge flagged it in unverified with
    # a scope-related reason, the scope was rejected.
    if "expected_scope" in case:
        qirs = json.loads(case["feedback_qirs"])
        input_scope = qirs[0].get("scope", "") if qirs else ""
        confirmed = verdict.get("confirmed_valid", [])
        unverified = verdict.get("unverified", [])

        # Check if the judge flagged a scope violation.
        scope_flagged = any(
            "scope" in (item.get("reason", "") or "").lower()
            or "TR-003" in (item.get("reason", "") or "")
            for item in unverified
        )

        if input_scope == case["expected_scope"] and not scope_flagged:
            scores["passed_checks"].append(
                f"Scope classification accepted by judge: {input_scope}"
            )
        elif input_scope == case["expected_scope"] and scope_flagged:
            scores["failed_checks"].append(
                f"Scope {input_scope} matches expected but judge flagged it "
                f"as a scope violation"
            )
        elif input_scope != case["expected_scope"] and scope_flagged:
            scores["passed_checks"].append(
                f"Judge correctly flagged scope mismatch: input={input_scope}, "
                f"expected={case['expected_scope']}"
            )
        else:
            scores["failed_checks"].append(
                f"Scope wrong: input has {input_scope}, expected "
                f"{case['expected_scope']}, judge did not flag"
            )

    # Relevance distribution.
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
    print("JUDGE CALIBRATION EVALUATION — Feedback Stage")
    print("Intel Cycle AI — ApexCode Solutions")
    print(f"Test cases: {len(TEST_CASES)}")
    print("Judge model: gemini-2.5-flash @ temp=0.0")
    print("=" * 70)

    total_passed = total_failed = total_checks = schema_failures = 0

    for i, case in enumerate(TEST_CASES, 1):
        print(f"\n{'─'*60}")
        print(f"Case {i}/{len(TEST_CASES)}: {case['name']}")
        print(f"  {case['description']}")

        result = await run_judge_on_feedback_qirs(
            feedback_qirs_text=case["feedback_qirs"],
            stakeholder_feedback=case["stakeholder_feedback"],
        )

        if not result["valid"]:
            print(f"  SCHEMA FAILURE: {result['error'][:200]}")
            schema_failures += 1
            total_failed += 1
            total_checks += 1
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

        if "notes" in case:
            print(f"  Note: {case['notes'][:120]}")

    print(f"\n{'='*70}")
    accuracy = (total_passed / total_checks * 100) if total_checks > 0 else 0
    print(f"RESULTS: {total_passed}/{total_checks} checks passed  "
          f"({total_failed} failed, {schema_failures} schema failures)")
    print(f"Judge accuracy: {accuracy:.0f}%")

    # JUDGE_ACCURACY_THRESHOLD = 80.0
    #   Baseline: a judge that always returns PASS scores ~40% (4/10 cases
    #   expect PASS). A judge that matches every expected verdict with correct
    #   violation counts scores 100%. 80% was chosen as "most checks pass"
    #   with headroom for LLM variance on ambiguous cases (e.g., case 7 where
    #   PARTIAL or FAIL are both acceptable for scope misclassification, and
    #   case 8 where detecting fabrication from praise is subjective).
    #   Review cadence: re-evaluate when > 2 test cases are added or when
    #   TRANSFORMATION_RULES change (schema version bump triggers re-run).
    JUDGE_ACCURACY_THRESHOLD = 80.0
    if accuracy < JUDGE_ACCURACY_THRESHOLD:
        print(f"BELOW THRESHOLD ({JUDGE_ACCURACY_THRESHOLD:.0f}%) — FAIL")
        print("=" * 70)
        sys.exit(1)
    else:
        print(f"ABOVE THRESHOLD ({JUDGE_ACCURACY_THRESHOLD:.0f}%) — PASS")
        print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
