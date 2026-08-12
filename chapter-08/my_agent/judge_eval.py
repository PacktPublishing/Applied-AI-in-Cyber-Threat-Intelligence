"""
Independent Judge Calibration Evaluation — Processing Stage
Intel Cycle AI — ApexCode Solutions

Tests the Processing Validation Judge against corroboration briefs with
known-correct verdicts. Measures whether the judge correctly identifies
corroboration rule violations, missed correlations, and confidence inflation.

Usage (from the chapter-08/ root):
    cd my_agent && python judge_eval.py
"""

import asyncio
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from agent import (
    JUDGE_INSTRUCTION,
    ProcessingVerdict,
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
# Test cases — corroboration briefs with known-correct verdicts
# ---------------------------------------------------------------------------

TEST_CASES = [
    {
        "name": "valid_high_confidence",
        "description": "Three signals from three categories, all rules satisfied",
        "corroboration_brief": """\
### 1. Signal Inventory
- Okta System Log: authentication_anomaly — user.session.start from Ukraine IP, prior session from San Francisco. Source category: identity_provider.
- SpyCloud: credential_exposure — session cookie for same user found in stealer log dump posted 6 hours prior. Source category: breach_intelligence.
- Proofpoint: phishing_indicator — click.permitted on URL matching Evilginx2 page sent to same user 8 hours prior. Source category: email_security.

### 2. Corroboration Links
- authentication_anomaly (identity_provider) + credential_exposure (breach_intelligence) + phishing_indicator (email_security) = 3 signals from 3 categories → HIGH confidence.
- CR-001: satisfied (3 different categories). CR-002: all within 8 hours. CR-004: all pairs in each other's corroborates_with lists.

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| Partner account compromise via AiTM | HIGH | 3 | identity_provider, breach_intelligence, email_security |

### 4. Attribution Assessment
Attribution: Insufficient evidence. No infrastructure_match with known actor TTP (CR-005).

### 5. Intelligence Gaps
None — all signals corroborated.

**Key Finding**: Partner account compromise via AiTM session hijacking — HIGH confidence from 3 independent signals across 3 source categories.
""",
        "expected_verdict": "PASS",
        "expected_violations": 0,
    },
    {
        "name": "confidence_inflation",
        "description": "HIGH assigned from only two signals in two categories",
        "corroboration_brief": """\
### 1. Signal Inventory
- Okta System Log: authentication_anomaly — impossible travel detected. Source category: identity_provider.
- HIBP: credential_exposure — partner email in breach dump. Source category: breach_intelligence.

### 2. Corroboration Links
- authentication_anomaly + credential_exposure = HIGH confidence (two corroborating signals).

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| Partner credential compromise | HIGH | 2 | identity_provider, breach_intelligence |

### 4. Attribution Assessment
Attribution: Insufficient evidence.

### 5. Intelligence Gaps
No additional gaps identified.

**Key Finding**: Partner credential compromise — HIGH confidence.
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "HIGH requires 3+ signals from 3+ categories. This has only 2 from 2. Should be MEDIUM.",
    },
    {
        "name": "same_category_corroboration",
        "description": "Two EDR signals treated as corroborating — violates CR-001",
        "corroboration_brief": """\
### 1. Signal Inventory
- CrowdStrike Falcon: endpoint_compromise — DetectionSummaryEvent for Cobalt Strike beacon. Source category: edr_xdr.
- Microsoft Defender for Endpoint: endpoint_compromise — DeviceProcessEvents showing LSASS access. Source category: edr_xdr.

### 2. Corroboration Links
- CrowdStrike endpoint_compromise + Defender endpoint_compromise = MEDIUM confidence (two signals corroborating).

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| Endpoint compromise | MEDIUM | 2 | edr_xdr, edr_xdr |

### 4. Attribution Assessment
Attribution: Insufficient evidence.

### 5. Intelligence Gaps
No identity or network signals to corroborate.

**Key Finding**: Endpoint compromise — MEDIUM confidence from two EDR sources.
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "CR-001 violation: both signals are edr_xdr category. Should be LOW (single category).",
    },
    {
        "name": "invalid_corroboration_pair",
        "description": "Two signals linked that violate CR-004 — auth_anomaly + dark_web_mention are not mutual",
        "corroboration_brief": """\
### 1. Signal Inventory
- Okta System Log: authentication_anomaly — session from new device/IP in Eastern Europe. Source category: identity_provider.
- IntelligenceX: dark_web_mention — ApexCode VPN endpoint listed in access broker forum post 12 hours prior. Source category: dark_web.

### 2. Corroboration Links
- authentication_anomaly (identity_provider) + dark_web_mention (dark_web) = MEDIUM confidence from 2 categories.
- CR-001: satisfied (different categories). CR-002: within 12 hours.

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| VPN access broker exploitation | MEDIUM | 2 | identity_provider, dark_web |

### 4. Attribution Assessment
Attribution: Insufficient evidence.

### 5. Intelligence Gaps
No credential_exposure signal to confirm the access broker listing was exploited.

**Key Finding**: Possible access broker exploitation — MEDIUM confidence.
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": (
            "CR-004 violation: authentication_anomaly and dark_web_mention are NOT in "
            "each other's corroborates_with lists. The link is invalid despite being "
            "from different categories (CR-001 satisfied). Should be two isolated signals."
        ),
    },
    {
        "name": "temporal_violation",
        "description": "Signals 30 days apart claimed as corroborating — violates CR-002",
        "corroboration_brief": """\
### 1. Signal Inventory
- HIBP: credential_exposure — partner email in breach dump posted 30 days ago. Source category: breach_intelligence.
- Okta System Log: authentication_anomaly — anomalous session today. Source category: identity_provider.

### 2. Corroboration Links
- credential_exposure (30 days ago) + authentication_anomaly (today) = MEDIUM confidence.

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| Delayed credential exploitation | MEDIUM | 2 | breach_intelligence, identity_provider |

### 4. Attribution Assessment
Attribution: Insufficient evidence.

### 5. Intelligence Gaps
No evidence linking the 30-day-old breach to today's anomaly.

**Key Finding**: Possible delayed credential exploitation — MEDIUM confidence.
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "CR-002 Tier 3 (7-30 days): caps corroborated confidence at LOW. The brief assigns MEDIUM, which exceeds the Tier 3 cap and forces FAIL.",
    },
    {
        "name": "geographic_inconsistency",
        "description": "Conflicting geos treated as corroboration — violates CR-003",
        "corroboration_brief": """\
### 1. Signal Inventory
- Okta System Log: authentication_anomaly — login from Ukraine. Source category: identity_provider.
- CrowdStrike Falcon: endpoint_compromise — process execution on endpoint in Singapore. Source category: edr_xdr.
- SpyCloud: credential_exposure — session cookie in stealer log. Source category: breach_intelligence.

### 2. Corroboration Links
- authentication_anomaly (Ukraine) + endpoint_compromise (Singapore) + credential_exposure = HIGH confidence from 3 categories.

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| Multi-vector compromise | HIGH | 3 | identity_provider, edr_xdr, breach_intelligence |

### 4. Attribution Assessment
Attribution: Insufficient evidence.

### 5. Intelligence Gaps
Geographic conflict between Ukraine and Singapore not resolved.

**Key Finding**: Multi-vector compromise — HIGH confidence.
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "CR-003: Ukraine vs Singapore geographic conflict should reduce confidence, not support HIGH.",
    },
    {
        "name": "unsupported_attribution",
        "description": "Attribution without infrastructure match — violates CR-005",
        "corroboration_brief": """\
### 1. Signal Inventory
- Okta System Log: authentication_anomaly — session hijacking pattern. Source category: identity_provider.
- SpyCloud: credential_exposure — session cookie found. Source category: breach_intelligence.
- Proofpoint: phishing_indicator — Evilginx2-style page detected. Source category: email_security.

### 2. Corroboration Links
- 3 signals from 3 categories = HIGH confidence. All rules satisfied.

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| AiTM session hijacking | HIGH | 3 | identity_provider, breach_intelligence, email_security |

### 4. Attribution Assessment
Attribution: APT29 (Cozy Bear) — this group is known to target technology companies
and has used similar proxy phishing techniques in the past.

### 5. Intelligence Gaps
None.

**Key Finding**: AiTM session hijacking attributed to APT29 — HIGH confidence.
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "CR-005: Attribution to APT29 based on behavioral similarity only. No infrastructure_match with known APT29 TTPs.",
    },
    {
        "name": "missed_obvious_correlation",
        "description": "Brief has correlatable signals but no link made",
        "corroboration_brief": """\
### 1. Signal Inventory
- Okta System Log: authentication_anomaly — impossible travel. Source category: identity_provider. Confidence: LOW.
- SpyCloud: credential_exposure — session cookie for same user. Source category: breach_intelligence. Confidence: MEDIUM.

### 2. Corroboration Links
(none identified)

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| Okta impossible travel | LOW | 1 | identity_provider |
| Credential in stealer log | MEDIUM | 1 | breach_intelligence |

### 4. Attribution Assessment
Attribution: Insufficient evidence.

### 5. Intelligence Gaps
Both signals remain isolated.

**Key Finding**: Two isolated signals requiring further collection.
""",
        "expected_verdict": "PARTIAL",
        "expected_violations": 0,
        "notes": "authentication_anomaly and credential_exposure are in each other's corroborates_with lists. Should be linked to MEDIUM at minimum.",
    },
    {
        "name": "corroborates_with_violation",
        "description": "Two signals linked that are not in each other's corroborates_with list",
        "corroboration_brief": """\
### 1. Signal Inventory
- dnstwist: domain_permutation — apexcode-dev.com registered recently. Source category: domain_recon.
- GitHub Audit Log: repository_access_anomaly — bulk clone from new IP. Source category: version_control.

### 2. Corroboration Links
- domain_permutation + repository_access_anomaly = MEDIUM confidence from 2 categories.

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| Domain squatting + repo theft | MEDIUM | 2 | domain_recon, version_control |

### 4. Attribution Assessment
Attribution: Insufficient evidence.

### 5. Intelligence Gaps
No phishing or authentication signals to complete the chain.

**Key Finding**: Domain squatting correlated with repository access — MEDIUM.
""",
        "expected_verdict": "FAIL",
        "expected_violations": 1,
        "notes": "CR-004: domain_permutation's corroborates_with is [infrastructure_match, phishing_indicator]. repository_access_anomaly is NOT in the list.",
    },
    {
        "name": "comprehensive_brief",
        "description": "Multi-signal, multi-category brief with all rules satisfied",
        "corroboration_brief": """\
### 1. Signal Inventory
- Okta System Log: authentication_anomaly — session from Eastern Europe with no MFA. Source category: identity_provider.
- SpyCloud: credential_exposure — session cookie matching Okta format. Source category: breach_intelligence.
- Proofpoint: phishing_indicator — click.permitted on Evilginx2 page. Source category: email_security.
- GitHub Audit Log: repository_access_anomaly — bulk clone of 8 repos from same IP as Okta session. Source category: version_control.
- Palo Alto Firewall: infrastructure_match — THREAT event for C2 IP matching ThreatFox entry. Source category: network_security.

### 2. Corroboration Links
- Link 1: authentication_anomaly (identity_provider) + credential_exposure (breach_intelligence) + phishing_indicator (email_security) = HIGH (3 categories, CR-001/002/004 satisfied, all within 6 hours).
- Link 2: repository_access_anomaly (version_control) corroborates with authentication_anomaly (identity_provider) and credential_exposure (breach_intelligence) = part of HIGH finding.
- Link 3: infrastructure_match (network_security) corroborates with authentication_anomaly (identity_provider) = supporting MEDIUM signal for C2.

### 3. Confidence Assessment Summary
| Finding | Confidence | Signals | Categories |
|---|---|---|---|
| AiTM session hijacking | HIGH | 4 | identity_provider, breach_intelligence, email_security, version_control |
| C2 communication | MEDIUM | 2 | network_security, identity_provider |

### 4. Attribution Assessment
Attribution: Insufficient evidence for specific actor. Infrastructure match is with generic Evilginx2 deployment, not actor-specific C2.

### 5. Intelligence Gaps
- No endpoint_compromise signal from EDR to confirm post-access activity.
- Dark web monitoring pending.

**Key Finding**: AiTM session hijacking with post-compromise repo exfiltration — HIGH confidence from 4 source categories.
""",
        "expected_verdict": "PASS",
        "expected_violations": 0,
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


async def run_judge_on_brief(brief_text: str) -> dict:
    """Run the judge on a synthetic brief and return the parsed verdict."""
    judge = make_judge_agent()
    runner = Runner(agent=judge, app_name=APP_NAME, session_service=session_service)

    session_id = f"judge_eval_{uuid.uuid4().hex}"
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={"corroboration_brief": brief_text, "processing_verdict": ""},
    )

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=session_id,
        new_message=types.Content(
            role="user",
            parts=[types.Part(text="Validate this corroboration brief.")],
        ),
    ):
        pass

    session = await session_service.get_session(
        app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
    )
    verdict_raw = session.state.get("processing_verdict", "{}")

    try:
        verdict_dict = json.loads(verdict_raw)
        validated = ProcessingVerdict.model_validate(verdict_dict)
        return {"valid": True, "verdict": validated.model_dump(), "raw": verdict_raw}
    except json.JSONDecodeError as e:
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

    if "expected_violations" in case:
        n_unverified = len(verdict.get("unverified", []))
        if n_unverified == case["expected_violations"]:
            scores["passed_checks"].append(f"Violation count correct: {n_unverified}")
        else:
            scores["failed_checks"].append(
                f"Violation count wrong: got {n_unverified}, expected {case['expected_violations']}"
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
    print("JUDGE CALIBRATION EVALUATION — Processing Stage")
    print("Intel Cycle AI — ApexCode Solutions")
    print(f"Test cases: {len(TEST_CASES)}")
    print("Judge model: gemini-2.5-flash @ temp=0.0")
    print("=" * 70)

    total_passed = total_failed = total_checks = schema_failures = 0

    for i, case in enumerate(TEST_CASES, 1):
        print(f"\n{'─'*60}")
        print(f"Case {i}/{len(TEST_CASES)}: {case['name']}")
        print(f"  {case['description']}")

        result = await run_judge_on_brief(case["corroboration_brief"])

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

        if "expected_verdict_notes" in case:
            print(f"  Note: {case['expected_verdict_notes'][:120]}...")

    print(f"\n{'='*70}")
    accuracy = (total_passed / total_checks * 100) if total_checks > 0 else 0
    print(f"RESULTS: {total_passed}/{total_checks} checks passed  "
          f"({total_failed} failed, {schema_failures} schema failures)")
    print(f"Judge accuracy: {accuracy:.0f}%")

    THRESHOLD = 80.0
    if accuracy < THRESHOLD:
        print(f"BELOW THRESHOLD ({THRESHOLD:.0f}%) — FAIL")
        print("=" * 70)
        sys.exit(1)
    else:
        print(f"ABOVE THRESHOLD ({THRESHOLD:.0f}%) — PASS")
        print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
