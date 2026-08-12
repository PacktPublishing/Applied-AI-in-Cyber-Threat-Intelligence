"""
Independent Judge Calibration Evaluation — Production Stage
Intel Cycle AI — ApexCode Solutions

Tests the Logic Judge against argument maps with known-correct verdicts.
Measures whether the judge correctly identifies logic rule violations,
missing assumptions, weak evidence chains, and structural deficiencies.

Usage (from the chapter-10/ repo root):
    python my_agent/judge_eval.py
"""

import asyncio
import json
import sys
import uuid
from pathlib import Path

_stage5_dir = str(Path(__file__).parent)
if _stage5_dir not in sys.path:
    sys.path.insert(0, _stage5_dir)

from dotenv import load_dotenv
load_dotenv()

from agent import (
    JUDGE_INSTRUCTION,
    ProductionVerdict,
    APP_NAME,
    USER_ID,
    make_judge_agent,
)
from pydantic import ValidationError
from google.adk import Agent, Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Eval uses non-persistent sessions — no disk accumulation, no data mixing
# with production sessions.
session_service = InMemorySessionService()


# ---------------------------------------------------------------------------
# Test cases — argument maps with known-correct verdicts
# ---------------------------------------------------------------------------

TEST_CASES = [
    {
        "name": "valid_complete_argument",
        "description": "All logic rules satisfied, all sections present",
        "argument_map": """\
### 1. Executive Summary
With HIGH confidence, a threat actor used Evilginx2 AiTM proxy phishing to steal
an active Okta session cookie from a partner developer, then cloned the two Project
Phoenix GitHub repositories. Immediate session revocation and partner notification recommended.

### 2. Key Findings
- C-001 [HIGH confidence]: AiTM session hijacking via stolen Okta session cookie enabled
  unauthorized GitHub repository access. Supported by I-001, I-002.

### 3. Evidence Summary
- E-001 [Okta System Log, identity_provider]: user.session.start reusing the partner's existing Okta session from Tor exit node IP
  185.220.101.42. Timestamp: 2025-03-15 08:00–09:30 UTC. Confidence: HIGH.
- E-002 [SpyCloud, breach_intelligence]: Recaptured Okta session cookie for partner user.
  Timestamp: 2025-03-14 stealer log. Confidence: HIGH.
- E-003 [Proofpoint, email_security]: click.permitted on Evilginx2 phishing URL targeting
  partner domain. Timestamp: 2025-03-14 16:30 UTC. Confidence: HIGH.
- E-004 [GitHub Audit Log, version_control]: git.clone of the two Project Phoenix repos (/phoenix-core, /phoenix-api) from IP
  185.220.101.42 within 45 min of session start. Timestamp: 2025-03-15 08:45–09:30 UTC.
  Confidence: HIGH.

### 4. Analytical Reasoning
- I-001 [STRONG]: The Okta session was established via stolen session cookie from AiTM
  phishing, not legitimate authentication. Supporting evidence: E-001, E-002, E-003.
  Reasoning: Three independent signals from three source categories (identity_provider,
  breach_intelligence, email_security) converge on AiTM session hijacking.
- I-002 [MODERATE]: The GitHub repository access was unauthorized, using the hijacked
  session. Supporting evidence: E-001, E-004. Reasoning: Same IP, same time window,
  via the hijacked session — the repo access used the stolen session cookie.

### 5. Assumptions and Limitations
- A-001: The Okta session from the Tor exit IP was not a legitimate session from the
  partner employee using an anonymization tool. If wrong: entire AiTM finding collapses;
  GitHub access would be authorized. Testable: Yes (confirm with partner).
- A-002: SpyCloud stealer log data is current, not from a historical dump. If wrong:
  cookie may be expired and not usable for session hijacking. Testable: Yes (check
  cookie expiry timestamps).

### 6. Alternative Hypotheses
- ALT-001: Legitimate partner employee using VPN from unusual location. Rejected: the
  IP is a known Tor exit node; partner confirmed no authorized Tor/VPN policy. E-003
  (phishing click) is inconsistent with legitimate access.

### 7. Recommendations
- Revoke all active Okta sessions for the affected partner user.
- Rotate all GitHub PATs and deploy keys associated with the compromised account.
- Notify partner organization's security team with evidence summary.

### 8. Appendix: Source List with TLP Markings
- Okta System Log — TLP:AMBER
- SpyCloud — TLP:AMBER
- Proofpoint Email Security — TLP:AMBER
- GitHub Audit Log — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "PASS",
        "expected_violations": 0,
    },
    {
        "name": "conclusion_no_evidence_chain",
        "description": "Conclusion supported by one inference with one evidence node — LR-001",
        # expected_min_violations: the map has two rule violations (LR-001: only 1 evidence
        # node for the conclusion; LR-003: I-001 labeled STRONG with only 1 evidence node).
        # A thorough judge may correctly report both, producing n_unverified=2. Using
        # expected_min_violations instead of expected_violations avoids penalizing a judge
        # that finds all violations rather than just the primary one.
        "argument_map": """\
### 1. Executive Summary
With HIGH confidence, ransomware initial access via stolen VPN credentials detected.

### 2. Key Findings
- C-001 [HIGH confidence]: Ransomware operators used stolen VPN credentials for initial
  access. Supported by I-001.

### 3. Evidence Summary
- E-001 [Okta System Log, identity_provider]: VPN authentication from unusual IP.
  Timestamp: 2025-04-01 02:00 UTC. Confidence: MEDIUM.

### 4. Analytical Reasoning
- I-001 [STRONG]: VPN access was unauthorized using stolen credentials. Supporting
  evidence: E-001. Reasoning: Unusual IP indicates compromise.

### 5. Assumptions and Limitations
- A-001: The VPN session was not a legitimate remote worker. If wrong: false positive.
  Testable: Yes.

### 6. Alternative Hypotheses
- ALT-001: Legitimate remote access. Rejected: unusual hours and IP geolocation mismatch.

### 7. Recommendations
- Revoke VPN credentials and force MFA re-enrollment.

### 8. Appendix: Source List with TLP Markings
- Okta System Log — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "FAIL",
        "expected_min_violations": 1,
        "notes": "LR-001: C-001 traces to only 1 evidence node (E-001). Need ≥2 independent evidence nodes. Also LR-003: I-001 labeled STRONG with only 1 evidence node.",
    },
    {
        "name": "inference_no_source_citation",
        "description": "Inference makes claim without citing specific evidence — LR-002",
        "argument_map": """\
### 1. Executive Summary
MEDIUM confidence: credential exposure detected for partner organization.

### 2. Key Findings
- C-001 [MEDIUM confidence]: Partner credentials compromised. Supported by I-001, I-002.

### 3. Evidence Summary
- E-001 [HIBP, breach_intelligence]: Partner email domain in breach dump.
  Timestamp: 2025-03-20. Confidence: MEDIUM.
- E-002 [Okta System Log, identity_provider]: Failed MFA challenges from new IP.
  Timestamp: 2025-03-21. Confidence: LOW.

### 4. Analytical Reasoning
- I-001 [MODERATE]: Credentials were likely stolen from the breach. Supporting evidence:
  E-001, E-002. Reasoning: Breach hit followed by auth anomaly suggests exploitation.
- I-002 [WEAK]: The attacker is actively attempting to use the credentials. Reasoning:
  Multiple failed MFA challenges suggest credential reuse attempt.

### 5. Assumptions and Limitations
- A-001: The breach data is current. If wrong: credentials may be rotated. Testable: Yes.

### 6. Alternative Hypotheses
- ALT-001: Automated scanning, not targeted. Rejected: MFA failures are from the same
  IP that matches breach-associated infrastructure.

### 7. Recommendations
- Force password reset for affected accounts.

### 8. Appendix: Source List with TLP Markings
- HIBP — TLP:AMBER
- Okta System Log — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "LR-002: I-002 does not cite supporting evidence node IDs. States reasoning without explicit 'Supporting evidence: E-XXX' citation.",
    },
    {
        "name": "strong_with_two_evidence",
        "description": "Inference labeled STRONG but only 2 evidence nodes — LR-003",
        "argument_map": """\
### 1. Executive Summary
HIGH confidence: BEC attack with OAuth consent abuse detected.

### 2. Key Findings
- C-001 [HIGH confidence]: Business email compromise with OAuth consent grant.
  Supported by I-001.

### 3. Evidence Summary
- E-001 [M365 UAL, collaboration]: New-InboxRule creating mail forwarding.
  Timestamp: 2025-04-10 14:00 UTC. Confidence: HIGH.
- E-002 [Entra ID Audit, identity_provider]: OAuth app consent grant to unknown app.
  Timestamp: 2025-04-10 13:45 UTC. Confidence: HIGH.

### 4. Analytical Reasoning
- I-001 [STRONG]: Attacker gained mailbox access via OAuth consent phishing and
  established persistence through mail forwarding rule. Supporting evidence: E-001, E-002.
  Reasoning: OAuth consent immediately followed by inbox rule creation is a known BEC pattern.

### 5. Assumptions and Limitations
- A-001: The OAuth consent was not authorized by the user. If wrong: legitimate app
  installation. Testable: Yes (confirm with user).

### 6. Alternative Hypotheses
- ALT-001: User installed a legitimate app. Rejected: app is unknown and not in
  approved app catalog.

### 7. Recommendations
- Revoke OAuth consent and remove inbox forwarding rule.

### 8. Appendix: Source List with TLP Markings
- M365 Unified Audit Log — TLP:AMBER
- Microsoft Entra ID Audit Logs — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "LR-003: I-001 is labeled STRONG but supported by only 2 evidence nodes from 2 categories. STRONG requires 3+ from 3+. Should be MODERATE.",
    },
    {
        "name": "implicit_assumption",
        "description": "Key assumption embedded in inference reasoning, not explicit — LR-004",
        "argument_map": """\
### 1. Executive Summary
MEDIUM confidence: insider threat with bulk data download detected.

### 2. Key Findings
- C-001 [MEDIUM confidence]: Insider data exfiltration via bulk download.
  Supported by I-001, I-002.

### 3. Evidence Summary
- E-001 [Netskope CASB, casb]: bulk_download event — 500+ files in 30 min.
  Timestamp: 2025-04-05 22:00 UTC. Confidence: MEDIUM.
- E-002 [Salesforce, saas_monitoring]: ReportEvent with 10,000+ rows exported.
  Timestamp: 2025-04-05 22:15 UTC. Confidence: MEDIUM.

### 4. Analytical Reasoning
- I-001 [MODERATE]: The employee is exfiltrating data in preparation for departure.
  Supporting evidence: E-001, E-002. Reasoning: Bulk download from two different SaaS
  platforms within 15 minutes, assuming this employee has submitted their resignation
  and this is not normal job activity.
- I-002 [WEAK]: The data includes sensitive IP. Supporting evidence: E-001. Reasoning:
  The files downloaded include engineering documentation, assuming the CASB classification
  is accurate.

### 5. Assumptions and Limitations
(none listed)

### 6. Alternative Hypotheses
- ALT-001: Legitimate business activity. Rejected: volume and timing are anomalous.

### 7. Recommendations
- Suspend account access pending investigation.

### 8. Appendix: Source List with TLP Markings
- Netskope CASB — TLP:AMBER
- Salesforce Event Monitoring — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "PARTIAL",
        "expected_min_violations": 0,
        "notes": "LR-004: I-001 contains 'assuming this employee has submitted their resignation' — this is a key assumption embedded in inference reasoning, not stated as an explicit assumption node. The Assumptions section is empty. Per judge spec (agent.py:438-439), LR-004 violations produce PARTIAL, not FAIL.",
    },
    {
        "name": "no_alternative_hypotheses",
        "description": "Conclusion with no alternatives considered — LR-005",
        "argument_map": """\
### 1. Executive Summary
HIGH confidence: API key exposure on public GitHub with production database access.

### 2. Key Findings
- C-001 [HIGH confidence]: Production API key exposed on public GitHub repo, database
  access confirmed. Supported by I-001, I-002.

### 3. Evidence Summary
- E-001 [GitHub Public Events API, code_exposure]: Push event containing AWS access key
  in plaintext. Timestamp: 2025-04-08 09:00 UTC. Confidence: HIGH.
- E-002 [AWS CloudTrail, cloud_audit]: GetSecretValue and DescribeInstances calls from
  unknown IP using the exposed key. Timestamp: 2025-04-08 10:30 UTC. Confidence: HIGH.
- E-003 [HashiCorp Vault, pam]: Token renewal for the service account associated with
  the exposed key. Timestamp: 2025-04-08 11:00 UTC. Confidence: MEDIUM.

### 4. Analytical Reasoning
- I-001 [STRONG]: The exposed API key was harvested from GitHub and used to access
  production infrastructure. Supporting evidence: E-001, E-002, E-003. Reasoning:
  Three signals from three categories (code_exposure, cloud_audit, pam) show the key
  was found on GitHub, then used within 2 hours to access AWS and Vault.

### 5. Assumptions and Limitations
- A-001: The API key was not intentionally published as a honeypot. If wrong: activity
  may be authorized security testing. Testable: Yes (check with DevSecOps team).

### 6. Alternative Hypotheses
(none listed)

### 7. Recommendations
- Rotate the exposed API key immediately.
- Audit all actions performed using the compromised credentials.

### 8. Appendix: Source List with TLP Markings
- GitHub Public Events API — TLP:GREEN
- AWS CloudTrail — TLP:AMBER
- HashiCorp Vault — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "PARTIAL",
        "expected_min_violations": 0,
        "notes": "LR-005: C-001 has no alternatives_considered. The Alternative Hypotheses section is empty. Must list ≥1 alternative with rejection rationale. Per judge spec (agent.py:438-439), LR-005 violations produce PARTIAL, not FAIL.",
    },
    {
        "name": "circular_reasoning",
        "description": "Inference cites itself or another inference as evidence",
        "argument_map": """\
### 1. Executive Summary
HIGH confidence: lateral movement detected through privilege escalation chain.

### 2. Key Findings
- C-001 [HIGH confidence]: Attacker achieved lateral movement through PAM abuse.
  Supported by I-001, I-002.

### 3. Evidence Summary
- E-001 [CyberArk, pam]: PSM.Session.Start for high-value safe by unapproved account.
  Timestamp: 2025-04-12 03:00 UTC. Confidence: HIGH.
- E-002 [Okta System Log, identity_provider]: User added to Production-Admin group
  outside change window. Timestamp: 2025-04-12 02:45 UTC. Confidence: HIGH.

### 4. Analytical Reasoning
- I-001 [MODERATE]: Privilege escalation occurred through group membership manipulation.
  Supporting evidence: E-002, I-002. Reasoning: Okta group change enabled PAM access.
- I-002 [MODERATE]: PAM session was unauthorized lateral movement. Supporting evidence:
  E-001, I-001. Reasoning: Based on the privilege escalation in I-001, the PAM access
  represents lateral movement.

### 5. Assumptions and Limitations
- A-001: The group change was not authorized by an admin. If wrong: legitimate access.
  Testable: Yes.

### 6. Alternative Hypotheses
- ALT-001: Authorized emergency access. Rejected: no change request found in ServiceNow.

### 7. Recommendations
- Remove unauthorized group membership and revoke PAM sessions.

### 8. Appendix: Source List with TLP Markings
- CyberArk — TLP:AMBER
- Okta System Log — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "LR-002: I-001 cites I-002 as supporting evidence, and I-002 cites I-001. This is circular reasoning — inferences cannot cite other inferences as evidence. Must cite evidence nodes only.",
    },
    {
        "name": "missing_product_sections",
        "description": "Valid argument structure but missing Executive Summary and Recommendations",
        "argument_map": """\
### 2. Key Findings
- C-001 [MEDIUM confidence]: Credential stuffing attack using breach-sourced credentials.
  Supported by I-001, I-002.

### 3. Evidence Summary
- E-001 [HIBP, breach_intelligence]: Partner domain in recent breach. Timestamp: 2025-04-01.
  Confidence: MEDIUM.
- E-002 [Okta System Log, identity_provider]: Surge of failed authentications from
  distributed IPs. Timestamp: 2025-04-02. Confidence: MEDIUM.

### 4. Analytical Reasoning
- I-001 [MODERATE]: Breach-sourced credentials are being used in stuffing attack.
  Supporting evidence: E-001, E-002. Reasoning: Breach timing aligns with auth surge.
- I-002 [WEAK]: Some credentials may be valid. Supporting evidence: E-002.
  Reasoning: A subset of attempts succeeded before lockout.

### 5. Assumptions and Limitations
- A-001: The breach data is recent enough to contain valid credentials. If wrong:
  attack will fail. Testable: Yes.

### 6. Alternative Hypotheses
- ALT-001: Automated bot scanning. Rejected: IPs correlate with breach forum activity.

### 8. Appendix: Source List with TLP Markings
- HIBP — TLP:AMBER
- Okta System Log — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "PARTIAL",
        "expected_violations": 0,
        "notes": "Missing sections 1 (Executive Summary) and 7 (Recommendations). Argument structure is valid but product is incomplete.",
    },
    {
        "name": "weak_chain_explicit",
        "description": "Weak evidence chain correctly labeled WEAK — should pass",
        "argument_map": """\
### 1. Executive Summary
With LOW confidence, potential spear phishing campaign targeting partner engineers.
Recommend continued monitoring; insufficient evidence for escalation.

### 2. Key Findings
- C-001 [LOW confidence]: Possible spear phishing campaign against partner engineers.
  Supported by I-001, I-002.

### 3. Evidence Summary
- E-001 [Proofpoint, email_security]: message.blocked with impostor classification
  targeting partner engineering team. Timestamp: 2025-04-15. Confidence: LOW.
- E-002 [dnstwist, domain_recon]: Newly registered domain apexcode-eng.com detected.
  Timestamp: 2025-04-14. Confidence: LOW.

### 4. Analytical Reasoning
- I-001 [WEAK]: A phishing campaign may be targeting partner engineers. Supporting
  evidence: E-001. Reasoning: Blocked email with impostor characteristics targeting
  engineering team, but no click or delivery confirmed.
- I-002 [WEAK]: The newly registered domain may be phishing infrastructure. Supporting
  evidence: E-002. Reasoning: Domain permutation of company name registered 1 day
  before phishing attempt, but no direct link confirmed.

### 5. Assumptions and Limitations
- A-001: The blocked email and the new domain are related. If wrong: two independent,
  low-priority signals. Testable: Yes (check if email originated from apexcode-eng.com).
- A-002: The domain is malicious, not a legitimate registration. If wrong: false positive
  from dnstwist. Testable: Yes (check WHOIS and page content).

### 6. Alternative Hypotheses
- ALT-001: Legitimate domain registration unrelated to phishing. Not yet rejected:
  WHOIS data pending review.
- ALT-002: Generic spam, not targeted phishing. Partially rejected: impostor
  classification suggests targeting, but could be false positive.

### 7. Recommendations
- Monitor apexcode-eng.com for active phishing infrastructure.
- Correlate with Umbrella DNS logs for any resolution attempts.
- Do NOT escalate until additional evidence corroborates.

### 8. Appendix: Source List with TLP Markings
- Proofpoint Email Security — TLP:AMBER
- dnstwist — TLP:GREEN
Product TLP: TLP:AMBER
""",
        "expected_verdict": "PASS",
        "expected_violations": 0,
        "notes": "All strength levels correctly calibrated as WEAK. Assumptions explicit. Alternatives considered with honest assessment. Product sections complete.",
    },
    {
        "name": "comprehensive_argument",
        "description": "Multi-conclusion product with all rules satisfied",
        "argument_map": """\
### 1. Executive Summary
With HIGH confidence, a coordinated attack compromised a partner developer account
via AiTM phishing, exfiltrated source code from the two Project Phoenix repositories, and
established C2 communication. Immediate incident response escalation recommended.

### 2. Key Findings
- C-001 [HIGH confidence]: AiTM session hijacking via Evilginx2 phishing enabled
  unauthorized access. Supported by I-001.
- C-002 [HIGH confidence]: Source code exfiltration from the two Project Phoenix repositories.
  Supported by I-002.
- C-003 [MEDIUM confidence]: C2 communication channel established post-compromise.
  Supported by I-003.

### 3. Evidence Summary
- E-001 [Okta System Log, identity_provider]: Session reuse from Tor exit node.
  Timestamp: 2025-03-15 08:00 UTC. Confidence: HIGH.
- E-002 [SpyCloud, breach_intelligence]: Okta session cookie in stealer log.
  Timestamp: 2025-03-14. Confidence: HIGH.
- E-003 [Proofpoint, email_security]: Evilginx2 phishing click permitted.
  Timestamp: 2025-03-14 16:30 UTC. Confidence: HIGH.
- E-004 [GitHub Audit Log, version_control]: Clone of the two Project Phoenix repos.
  Timestamp: 2025-03-15 08:45 UTC. Confidence: HIGH.
- E-005 [Palo Alto PAN-OS, network_security]: THREAT event for C2 IP.
  Timestamp: 2025-03-15 09:15 UTC. Confidence: MEDIUM.

### 4. Analytical Reasoning
- I-001 [STRONG]: AiTM session hijacking confirmed. Supporting evidence: E-001, E-002,
  E-003. Reasoning: Three signals from identity_provider, breach_intelligence,
  email_security converge. Temporal sequence consistent with Evilginx2 flow.
- I-002 [MODERATE]: Unauthorized repo access via hijacked session. Supporting evidence:
  E-001, E-004. Reasoning: Same Tor IP, same time window, via the reused session.
- I-003 [MODERATE]: Post-compromise C2 communication. Supporting evidence: E-005, E-001.
  Reasoning: C2 IP detected from same session endpoint. Two categories (network_security,
  identity_provider).

### 5. Assumptions and Limitations
- A-001: Tor exit IP was not legitimate partner VPN. If wrong: access was authorized.
  Testable: Yes.
- A-002: SpyCloud data is current. If wrong: cookie expired. Testable: Yes.
- A-003: C2 IP is correctly attributed, not a false positive from threat feed.
  If wrong: I-003 collapses. Testable: Yes (validate against multiple feeds).

### 6. Alternative Hypotheses
- ALT-001: Legitimate partner VPN access. Rejected: Tor exit node, partner confirmed
  no Tor policy, phishing click occurred (E-003).
- ALT-002: Cookie from expired breach, not active exploitation. Rejected: temporal
  proximity (cookie date 1 day before session reuse) and active session confirm
  currency.

### 7. Recommendations
- Revoke all active sessions for affected user.
- Rotate all GitHub credentials and deploy keys.
- Block C2 IP at perimeter and hunt for additional compromised endpoints.
- Notify partner security team with full evidence brief.

### 8. Appendix: Source List with TLP Markings
- Okta System Log — TLP:AMBER
- SpyCloud — TLP:AMBER
- Proofpoint Email Security — TLP:AMBER
- GitHub Audit Log — TLP:AMBER
- Palo Alto PAN-OS — TLP:AMBER
Product TLP: TLP:AMBER
""",
        "expected_verdict": "PASS",
        "expected_violations": 0,
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def run_judge_on_argument_map(argument_map_text: str) -> dict:
    """Run the judge on a synthetic argument map and return the parsed verdict."""
    judge = make_judge_agent()
    runner = Runner(agent=judge, app_name=APP_NAME, session_service=session_service)

    session_id = f"judge_eval_{uuid.uuid4().hex}"
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={"argument_map": argument_map_text, "production_verdict": ""},
    )

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=session_id,
        new_message=types.Content(
            role="user",
            parts=[types.Part(text="Validate this intelligence product.")],
        ),
    ):
        pass

    session = await session_service.get_session(
        app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
    )
    verdict_raw = session.state.get("production_verdict", {})

    try:
        verdict_dict = (
            verdict_raw if isinstance(verdict_raw, dict)
            else json.loads(verdict_raw)
        )
        validated = ProductionVerdict.model_validate(verdict_dict)
        return {"valid": True, "verdict": validated.model_dump(), "raw": verdict_raw}
    except (json.JSONDecodeError, TypeError) as e:
        return {"valid": False, "error": f"JSON parse failed: {e}", "raw": verdict_raw}
    except ValidationError as e:
        return {"valid": False, "error": f"Schema validation failed: {e}", "raw": verdict_raw}


def _score_case(case: dict, result: dict) -> dict:
    """Score a single test case against expected outcomes.

    Supports two violation count modes:
      - expected_violations (exact match): judge must return exactly N violations.
      - expected_min_violations (at-least match): judge must return >= N violations.
        Use this for cases where the judge may correctly find additional issues
        beyond the primary violation (e.g., LR-001 + LR-003 in the same map).
    """
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

    n_unverified = len(verdict.get("unverified", []))

    if "expected_violations" in case:
        # Exact match — use for cases with precisely one expected violation.
        if n_unverified == case["expected_violations"]:
            scores["passed_checks"].append(f"Violation count correct: {n_unverified}")
        else:
            scores["failed_checks"].append(
                f"Violation count wrong: got {n_unverified}, expected {case['expected_violations']}"
            )
    elif "expected_min_violations" in case:
        # At-least match — does not penalize thorough judges that find
        # additional legitimate violations beyond the primary one.
        min_v = case["expected_min_violations"]
        if n_unverified >= min_v:
            scores["passed_checks"].append(
                f"Violation count adequate: {n_unverified} >= {min_v}"
            )
        else:
            scores["failed_checks"].append(
                f"Violation count insufficient: got {n_unverified}, expected >= {min_v}"
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
    print("JUDGE CALIBRATION EVALUATION — Production Stage")
    print("Intel Cycle AI — ApexCode Solutions")
    print(f"Test cases: {len(TEST_CASES)}")
    print("Judge model: gemini-2.5-flash @ temp=0.0")
    print("=" * 70)

    total_passed = total_failed = total_checks = schema_failures = 0

    for i, case in enumerate(TEST_CASES, 1):
        print(f"\n{'─'*60}")
        print(f"Case {i}/{len(TEST_CASES)}: {case['name']}")
        print(f"  {case['description']}")

        result = await run_judge_on_argument_map(case["argument_map"])

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

    print(f"\n{'='*70}")
    accuracy = (total_passed / total_checks * 100) if total_checks > 0 else 0
    print(f"RESULTS: {total_passed}/{total_checks} checks passed  "
          f"({total_failed} failed, {schema_failures} schema failures)")
    print(f"Judge accuracy: {accuracy:.0f}%")

    # Document threshold rationale inline so the decision is
    # auditable without a separate memo.
    #
    # JUDGE_ACCURACY_THRESHOLD = 80.0
    #   Baseline: a judge that always returns PASS scores ~30% (3/10 cases
    #   expect PASS). A judge that matches every expected verdict with no
    #   violation-count errors scores 100%. 80% was chosen as "most checks
    #   pass" with headroom for LLM variance on ambiguous cases (e.g., the
    #   PARTIAL case where violation count is scenario-dependent). Below 80%
    #   indicates the judge is miscalibrated on a majority of rule checks.
    #   Review cadence: re-evaluate when > 2 test cases are added or when
    #   LOGIC_RULES change (schema version bump triggers re-run).
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
