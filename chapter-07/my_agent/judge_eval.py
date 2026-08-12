"""
judge_eval.py — Source Validation Judge calibration test suite.

Ten synthetic collection plans test whether the Source Validation Judge
correctly classifies known-good and known-bad plans. The cases cover four
failure modes:

  1. Hallucination detection  — real products absent from the 56-source catalog
  2. Near-miss name handling  — "Okta Logs" vs the catalog name "Okta System Log"
  3. Product disambiguation   — Zscaler Private Access vs Zscaler Internet Access (CASB)
  4. Relevance calibration    — valid catalog entries that are tangential to the threat

Eight of the ten cases have known-correct expected verdicts and contribute to
the accuracy score. Two cases (near_miss_names, relevance_tangential) test
judge behaviour on genuinely ambiguous input and are excluded from scoring.

Accuracy threshold: 80% — at least 7 of 8 scorable cases must match expected verdict.

Run:
    cd chapter-07 && python my_agent/judge_eval.py
"""

import asyncio
import json
import uuid

from dotenv import load_dotenv
from google.adk import Agent, Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

try:
    from .agent import JUDGE_INSTRUCTION, APP_NAME, USER_ID
except ImportError:
    from agent import JUDGE_INSTRUCTION, APP_NAME, USER_ID

load_dotenv()

ACCURACY_THRESHOLD = 80.0   # percent — applied to the 8 scorable cases


# ---------------------------------------------------------------------------
# Test cases
# Each dict has:
#   name                    — short identifier
#   description             — one-line summary of what is being tested
#   plan                    — synthetic collection plan text fed to the judge
#   expected_verdict        — "PASS" | "PARTIAL" | "FAIL" | None (unscored)
#   expected_unverified     — expected len(unverified) or None (unscored)
#   scorable                — whether this case contributes to the accuracy score
# ---------------------------------------------------------------------------

TEST_CASES = [

    # ── Scorable — expected PASS ─────────────────────────────────────────────

    {
        "name": "all_valid",
        "description": "Complete AiTM plan — all catalog sources, no gaps",
        "plan": """\
### 1. Internal Log Sources
Okta System Log — Correlate externalSessionId across session events; flag an active \
session presented from a new IP, ASN, or device than the one that authenticated it (cookie reuse).
Microsoft Entra ID Sign-In Logs — Flag impossible travel and anomalous-token / \
unfamiliar-sign-in-properties detections, plus conditional access policy failures on partner accounts.
Microsoft Entra ID Audit Logs — Detect post-compromise directory changes: role \
assignments, OAuth app consent grants, and guest account additions following session theft.
GitHub Audit Log — Monitor git.clone, repo.access, and org.invite events from sessions \
with anomalous IP geolocation relative to prior partner activity.
Jira Audit Log — Monitor project role changes and bulk issue exports from sessions \
following suspected cookie theft.
Duo Security — MFA authentication logs; flag TOTP code submissions from sessions that \
do not result in an Okta or Entra session (indicates Evilginx2 relayed the code).
CrowdStrike Falcon — Detect post-compromise endpoint activity on partner machines \
following session takeover.
Palo Alto Networks Firewall (PAN-OS) — Monitor outbound connections matching known \
Evilginx2 reverse-proxy C2 infrastructure patterns.
Cisco Umbrella — DNS-layer phishing detection; block and log partner employee DNS \
queries resolving to known Evilginx2 phishing infrastructure.
Microsoft Sentinel — Correlation layer across all ingested identity, endpoint, and \
network sources; build cross-source detection rules for sessionless authentication.
Microsoft 365 Unified Audit Log — Detect anomalous Exchange, SharePoint, and Teams \
access from sessions that lack a corresponding authentication event.
AWS CloudTrail — Detect console logins and role assumptions in AWS from replayed \
session tokens following partner account compromise.
Google Cloud Audit Logs — Detect GCP console logins and service account token \
generation from replayed sessions on partner-accessible GCP projects.

### 2. External / OSINT Sources
Proofpoint Email Security — Detect phishing delivery to partner employees \
(click.permitted, impostor.detected events on partner domains).
SpyCloud — Monitor stealer log exposure for partner employee session cookies.
urlscan.io — Identify Evilginx2 phishing pages via reverse-proxy URL structure analysis.
dnstwist — Detect typosquatting registrations on partner domains used as phishing lures.
PhishTank / CheckPhish — Classify discovered phishing URLs; confirm Evilginx2 pages \
against crowd-sourced and ML-based phishing verdict feeds.
URLhaus (abuse.ch) — Check discovered domains and IPs against known malware and phishing \
distribution lists; flag Evilginx2 infrastructure appearing in URLhaus feeds.
Abuse.ch ThreatFox — IOC feed for C2 domains and IPs; cross-reference Evilginx2 \
infrastructure indicators against active threat actor campaigns.
HaveIBeenPwned API — Monitor partner employee email addresses for credential exposure \
in breach datasets.

### 3. Threat Actor Tactics
Adversary-in-the-Middle (MITRE ATT&CK T1557): Evilginx2 proxies the real IdP login page, \
capturing credentials and live session cookies post-MFA. The adversary replays the stolen \
cookie — no password or MFA prompt required.

**Priority Signal**: Active Okta or Entra ID session (externalSessionId / session token) exercised from a new IP, ASN, device, or user-agent mid-session (session-cookie replay).
""",
        # Second-pass test: previous verdict flagged three missing sources.
        # The plan above now includes all three. The judge should confirm they
        # are present and return PASS (missing_critical carries forward only
        # sources that are STILL absent).
        "previous_verdict": json.dumps({
            "confirmed_valid": [
                {"source": "Okta System Log", "rationale": "Primary IdP.", "relevance": "ESSENTIAL"},
                {"source": "Microsoft Entra ID Sign-In Logs", "rationale": "Secondary IdP.", "relevance": "ESSENTIAL"},
                {"source": "GitHub Audit Log", "rationale": "Target platform.", "relevance": "ESSENTIAL"},
                {"source": "Proofpoint Email Security", "rationale": "Phishing delivery.", "relevance": "ESSENTIAL"},
            ],
            "unverified": [],
            "missing_critical": [
                {"source": "Microsoft 365 Unified Audit Log",
                 "importance": "Critical for detecting session reuse in M365 workloads."},
                {"source": "AWS CloudTrail",
                 "importance": "Critical for detecting console logins from replayed sessions in AWS."},
                {"source": "Google Cloud Audit Logs",
                 "importance": "Critical for detecting token generation from replayed sessions in GCP."},
            ],
            "verdict": "PARTIAL",
            "summary": "All recommended sources valid; three critical sources absent.",
        }),
        "expected_verdict": "PASS",
        "expected_unverified": 0,
        "scorable": True,
    },

    {
        "name": "clean_pass_ransomware",
        "description": "Complete ransomware plan — different scenario, all valid catalog sources",
        "plan": """\
### 1. Internal Log Sources
Okta System Log — VPN authentication events; flag new device or IP for service accounts \
following a credential breach window.
Microsoft Entra ID Sign-In Logs — Conditional access failures and impossible travel on \
privileged accounts.
Duo Security — MFA authentication logs; flag authentication events from new devices or \
locations immediately preceding VPN access from credential-exposed accounts.
Kaseya VSA — RMM platform audit logs; monitor for unauthorized agent deployment or \
mass-command execution consistent with ransomware lateral deployment via RMM abuse.
SpyCloud — Monitor corporate credential exposure in stealer logs and criminal marketplaces; \
identify stolen VPN credentials before they are operationalised by IABs.
Microsoft 365 Unified Audit Log — Monitor for mass file downloads, inbox rule creation, \
and SharePoint access anomalies following VPN authentication from a new device.
CrowdStrike Falcon — Lateral movement detection: process injection, PsExec usage, and \
ransomware precursor tooling (Cobalt Strike beacon activity, Mimikatz execution).
Palo Alto Networks Firewall (PAN-OS) — Anomalous east-west RDP traffic from the VPN \
concentrator segment.
Microsoft Defender for Endpoint — Ransomware execution signals: shadow copy deletion, \
volume encryption initiation, and rapid file modification events.
AWS CloudTrail — Snapshot creation, IAM privilege escalation attempts, and EC2 instance \
enumeration following initial VPN authentication.
Azure Activity Log — Resource group modifications and RBAC changes on Azure workloads \
following VPN lateral movement.
CyberArk Privileged Access Manager — Privileged session activity on jump hosts following \
VPN lateral movement; flag sessions originating from non-PAM pathways.
Microsoft Sentinel — Correlation layer across identity, endpoint, cloud, and network \
sources; cross-source detection for VPN-to-RDP-to-ransomware kill chain.
Google Cloud Audit Logs — Detect lateral movement and privilege escalation in \
GCP workloads accessed following initial VPN compromise.
Cisco Umbrella — DNS and web proxy logs for C2 communication detection and data \
exfiltration over DNS post-ransomware deployment.
HashiCorp Vault — Monitor privileged credential access and policy changes; flag \
reads of production secrets from sessions originating outside the PAM pathway.

### 2. External / OSINT Sources
HaveIBeenPwned API — Monitor partner and employee credential exposure from breach datasets.
DeHashed — Search for leaked credentials tied to corporate email domains sold by IABs.
GreyNoise — Classify inbound VPN authentication source IPs; flag mass-scanning and known \
initial access broker infrastructure.

### 3. Threat Actor Tactics
Initial access brokers sell stolen VPN and RDP credentials on criminal forums (MITRE \
ATT&CK T1078). After VPN authentication the adversary pivots to internal jump hosts via \
RDP before deploying ransomware across reachable segments.

**Priority Signal**: VPN authentication from a new IP or device for a service account, \
followed by RDP lateral movement within one hour.
""",
        # Second-pass test: previous verdict flagged three missing sources.
        # The plan above now includes all three.
        "previous_verdict": json.dumps({
            "confirmed_valid": [
                {"source": "Okta System Log", "rationale": "VPN auth events.", "relevance": "ESSENTIAL"},
                {"source": "Microsoft Entra ID Sign-In Logs", "rationale": "Identity logs.", "relevance": "ESSENTIAL"},
                {"source": "CrowdStrike Falcon", "rationale": "Endpoint detection.", "relevance": "ESSENTIAL"},
                {"source": "Palo Alto Networks Firewall (PAN-OS)", "rationale": "Network detection.", "relevance": "ESSENTIAL"},
            ],
            "unverified": [],
            "missing_critical": [
                {"source": "Google Cloud Audit Logs",
                 "importance": "Detects cloud lateral movement in GCP."},
                {"source": "Cisco Umbrella",
                 "importance": "Detects C2 communication via DNS and web proxy logs."},
                {"source": "HashiCorp Vault",
                 "importance": "Monitors privileged credential access post-compromise."},
            ],
            "verdict": "PARTIAL",
            "summary": "All recommended sources valid; three critical sources absent.",
        }),
        "expected_verdict": "PASS",
        "expected_unverified": 0,
        "scorable": True,
    },

    # ── Scorable — expected FAIL (hallucination) ─────────────────────────────

    {
        "name": "one_hallucination",
        "description": "Single hallucinated source: Splunk Enterprise Security (not in catalog)",
        "plan": """\
### 1. Internal Log Sources
Okta System Log — Correlate externalSessionId across events; flag a session presented \
from a new IP/device than the one that authenticated it (cookie reuse detection).
Microsoft Entra ID Sign-In Logs — Flag impossible travel and anomalous-token / \
unfamiliar-sign-in-properties detections.
GitHub Audit Log — Monitor git.clone and repo.access from sessions with anomalous \
geolocations.
Splunk Enterprise Security — Correlate authentication events across IdP and SaaS \
platforms using adaptive response actions and risk-based alerting.
Palo Alto Networks Firewall (PAN-OS) — Monitor C2 traffic patterns for Evilginx2 \
infrastructure.

### 2. External / OSINT Sources
Proofpoint Email Security — Phishing delivery detection targeting partner employees.
SpyCloud — Monitor stealer log exposure for session cookie theft.
urlscan.io — Identify Evilginx2 phishing pages.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Session cookie theft via Evilginx2 AiTM proxy.

**Priority Signal**: Active session (externalSessionId / session token) exercised from a new IP, ASN, device, or user-agent mid-session — the same authenticated session appearing from a new origin (session-cookie replay).
""",
        "expected_verdict": "FAIL",
        "expected_unverified": 1,
        "scorable": True,
    },

    {
        "name": "multi_hallucination",
        "description": "Three hallucinated sources: Elastic SIEM, Darktrace, Carbon Black EDR",
        "plan": """\
### 1. Internal Log Sources
Okta System Log — Flag an active session presented from a new IP/ASN/device than the one that authenticated it (externalSessionId reuse).
Microsoft Entra ID Sign-In Logs — Flag impossible travel and conditional access failures.
Elastic SIEM — Ingest and correlate identity and network logs; build detection rules \
for anomalous session patterns across all ingested sources.
Darktrace — AI-based anomaly detection across network traffic; identify unusual lateral \
movement patterns following session cookie theft.
Carbon Black EDR — Endpoint detection for post-compromise process execution on partner \
machines following account takeover.

### 2. External / OSINT Sources
Proofpoint Email Security — Phishing delivery detection for partner employees.
urlscan.io — Identify Evilginx2 phishing infrastructure.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Evilginx2 AiTM proxy captures live session cookies post-MFA.

**Priority Signal**: Active session (externalSessionId / session token) exercised from a new IP, ASN, device, or user-agent mid-session — the same authenticated session appearing from a new origin (session-cookie replay).
""",
        "expected_verdict": "FAIL",
        "expected_unverified": 3,
        "scorable": True,
    },

    {
        "name": "subtle_hallucination",
        "description": (
            "Product disambiguation: Zscaler Private Access (not in catalog) "
            "vs Zscaler Internet Access (CASB) (catalog name)"
        ),
        "plan": """\
### 1. Internal Log Sources
Okta System Log — Flag a session presented from a new IP/device than the one that authenticated it (externalSessionId reuse).
Microsoft Entra ID Sign-In Logs — Flag impossible travel and conditional access failures.
GitHub Audit Log — Monitor repository access events from anomalous sessions.
CrowdStrike Falcon — Post-compromise endpoint detection on partner machines.

### 2. External / OSINT Sources
Proofpoint Email Security — Phishing delivery detection.
Zscaler Private Access — Monitor zero-trust network access logs for anomalous session \
establishment; flag access to internal applications from unrecognised devices or locations.
SpyCloud — Session cookie and credential exposure monitoring via stealer log feeds.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Evilginx2 AiTM proxy captures live session cookies post-MFA \
completion.

**Priority Signal**: Active session (externalSessionId / session token) exercised from a new IP, ASN, device, or user-agent mid-session — the same authenticated session appearing from a new origin (session-cookie replay).
""",
        "expected_verdict": "FAIL",
        "expected_unverified": 1,
        "scorable": True,
    },

    {
        "name": "recorded_future_hallucination",
        "description": "Single hallucinated source: Recorded Future (not in catalog)",
        "plan": """\
### 1. Internal Log Sources
Okta System Log — Flag a session presented from a new IP/ASN/device than the one that \
authenticated it; externalSessionId reuse is the primary detection signal.
Microsoft Entra ID Sign-In Logs — Flag impossible travel and anomalous-token / unfamiliar-sign-in-properties detections.
GitHub Audit Log — Monitor repository access from anomalous sessions.

### 2. External / OSINT Sources
Proofpoint Email Security — Phishing delivery detection for partner employees.
Recorded Future — Monitor threat actor infrastructure associated with active Evilginx2 \
campaigns; flag newly registered domains matching partner organisation naming patterns.
urlscan.io — Identify Evilginx2 phishing pages via URL structure analysis.
SpyCloud — Session cookie and credential exposure monitoring.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Adversary-in-the-Middle session hijacking via Evilginx2 proxy.

**Priority Signal**: Active session (externalSessionId / session token) exercised from a new IP, ASN, device, or user-agent mid-session — the same authenticated session appearing from a new origin (session-cookie replay).
""",
        "expected_verdict": "FAIL",
        "expected_unverified": 1,
        "scorable": True,
    },

    # ── Scorable — expected PARTIAL ──────────────────────────────────────────

    {
        "name": "missing_critical_sources",
        "description": "Valid sources only — missing essential IdP and phishing delivery coverage",
        "plan": """\
### 1. Internal Log Sources
CrowdStrike Falcon — Post-compromise endpoint detection on partner machines.
Palo Alto Networks Firewall (PAN-OS) — Network-level C2 traffic detection.
Microsoft Sentinel — Correlation layer across all ingested log sources.

### 2. External / OSINT Sources
SpyCloud — Stealer log monitoring for session cookie exposure.
urlscan.io — Phishing infrastructure identification.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Evilginx2 AiTM proxy captures session cookies post-MFA.

**Priority Signal**: C2 outbound traffic matching Evilginx2 reverse-proxy infrastructure.
""",
        "expected_verdict": "PARTIAL",
        "expected_unverified": 0,
        "scorable": True,
    },

    {
        "name": "minimal_valid_partial",
        "description": "Only two valid sources — clearly insufficient coverage for any scenario",
        "plan": """\
### 1. Internal Log Sources
Microsoft Sentinel — SIEM correlation layer for aggregated detection across all log sources.

### 2. External / OSINT Sources
HaveIBeenPwned API — Monitor partner employee credential and session token exposure.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Adversary-in-the-Middle session hijacking.

**Priority Signal**: Credential exposure alerts for partner accounts.
""",
        "expected_verdict": "PARTIAL",
        "expected_unverified": 0,
        "scorable": True,
    },

    # ── Unscored — ambiguous behaviour cases ─────────────────────────────────

    {
        "name": "near_miss_names",
        "description": (
            "'Okta Logs' instead of catalog name 'Okta System Log' — "
            "tests whether the judge resolves common abbreviations"
        ),
        "plan": """\
### 1. Internal Log Sources
Okta Logs — Flag a session presented from a new IP/device than the one that authenticated it; \
externalSessionId reuse is the primary detection signal for AiTM compromise.
Microsoft Entra ID Sign-In Logs — Flag impossible travel and conditional access failures.
GitHub Audit Log — Monitor repository access from anomalous sessions.
CrowdStrike Falcon — Post-compromise endpoint detection on partner machines.

### 2. External / OSINT Sources
Proofpoint Email Security — Phishing delivery detection for partner employees.
SpyCloud — Session cookie and credential exposure monitoring.
urlscan.io — Phishing infrastructure identification.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Evilginx2 AiTM session hijacking.

**Priority Signal**: Active session (externalSessionId / session token) exercised from a new IP, ASN, device, or user-agent mid-session — the same authenticated session appearing from a new origin (session-cookie replay).
""",
        "expected_verdict": None,
        "expected_unverified": None,
        "scorable": False,
    },

    {
        "name": "relevance_tangential",
        "description": (
            "Jamf Pro and Kandji MDM included in an AiTM plan — "
            "valid catalog entries but tangential to the threat"
        ),
        "plan": """\
### 1. Internal Log Sources
Okta System Log — Flag a session presented from a new IP/device than the one that authenticated it (externalSessionId reuse).
Microsoft Entra ID Sign-In Logs — Flag impossible travel and anomalous-token / unfamiliar-sign-in-properties detections.
GitHub Audit Log — Repository access from anomalous sessions.
CrowdStrike Falcon — Post-compromise endpoint detection on partner machines.
Jamf Pro — MDM enrollment and device compliance status for partner macOS endpoints; \
flag devices that fall out of compliance following suspected compromise.
Kandji MDM — Device health and managed application status on partner Apple devices \
post-compromise.

### 2. External / OSINT Sources
Proofpoint Email Security — Phishing delivery detection.
SpyCloud — Session cookie exposure monitoring.

### 3. Threat Actor Tactics
MITRE ATT&CK T1557: Evilginx2 AiTM session hijacking.

**Priority Signal**: Active session (externalSessionId / session token) exercised from a new IP, ASN, device, or user-agent mid-session — the same authenticated session appearing from a new origin (session-cookie replay).
""",
        "expected_verdict": None,
        "expected_unverified": None,
        "scorable": False,
    },
]


# ---------------------------------------------------------------------------
# Judge runner
# A fresh Agent instance is created per call — ADK sets a parent reference on
# each sub-agent, so reusing instances across Runner constructions raises
# "Agent already has a parent".
# ---------------------------------------------------------------------------

async def run_judge_on_plan(
    plan_text: str,
    previous_verdict: str = "",
) -> dict:
    """Run the judge agent against a single plan text and return the parsed verdict.

    Args:
        plan_text:        The collection plan to validate.
        previous_verdict: Optional JSON string of the previous iteration's verdict.
                          If non-empty the judge treats this as a second pass and only
                          carries forward missing_critical entries that are still absent,
                          enabling PASS tests that mirror real refinement-loop behaviour.
    """
    judge = Agent(
        name="Source_Validation_Judge",
        model="gemini-3.1-pro-preview",
        instruction=JUDGE_INSTRUCTION,
        generate_content_config=types.GenerateContentConfig(
            temperature=0.0,
            response_mime_type="application/json",
        ),
        output_key="validation_verdict",
    )

    session_service = InMemorySessionService()
    session_id = f"eval_{uuid.uuid4().hex}"
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state={
            "collection_plan":    plan_text,
            "validation_verdict": previous_verdict,
        },
    )

    runner = Runner(agent=judge, app_name=APP_NAME, session_service=session_service)
    async for _ in runner.run_async(
        user_id=USER_ID,
        session_id=session_id,
        new_message=types.Content(
            role="user", parts=[types.Part(text="Validate the collection plan.")]
        ),
    ):
        pass

    session = await session_service.get_session(
        app_name=APP_NAME, user_id=USER_ID, session_id=session_id,
    )
    raw = session.state.get("validation_verdict", "{}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "verdict": "ERROR",
            "unverified": [],
            "confirmed_valid": [],
            "missing_critical": [],
            "summary": "JSON parse failed — raw response was not valid JSON.",
        }


# ---------------------------------------------------------------------------
# Evaluation runner — called by notebook and __main__
# ---------------------------------------------------------------------------

async def run_all(verbose: bool = True) -> list[dict]:
    """Run all test cases and return a list of result dicts."""
    results = []
    for tc in TEST_CASES:
        if verbose:
            print(f"  {tc['name']} ...", flush=True)
        verdict = await run_judge_on_plan(
            tc["plan"],
            previous_verdict=tc.get("previous_verdict", ""),
        )

        actual_verdict    = verdict.get("verdict", "ERROR")
        actual_unverified = len(verdict.get("unverified", []))

        if tc["scorable"]:
            verdict_match = actual_verdict == tc["expected_verdict"]
            count_match   = (
                tc["expected_unverified"] is None
                or actual_unverified == tc["expected_unverified"]
            )
            passed = verdict_match and count_match
        else:
            verdict_match = None
            count_match   = None
            passed        = None

        results.append({
            "name":               tc["name"],
            "description":        tc["description"],
            "expected_verdict":   tc["expected_verdict"],
            "actual_verdict":     actual_verdict,
            "expected_unverified": tc["expected_unverified"],
            "actual_unverified":  actual_unverified,
            "verdict_match":      verdict_match,
            "passed":             passed,
            "scorable":           tc["scorable"],
            "summary":            verdict.get("summary", ""),
        })
    return results


# ---------------------------------------------------------------------------
# CLI output
# ---------------------------------------------------------------------------

def print_results(results: list[dict]) -> None:
    scorable  = [r for r in results if r["scorable"]]
    unscored  = [r for r in results if not r["scorable"]]
    n_pass    = sum(1 for r in scorable if r["passed"])
    accuracy  = n_pass / len(scorable) * 100 if scorable else 0.0
    status    = "PASS" if accuracy >= ACCURACY_THRESHOLD else "FAIL"

    W = 34
    print("\n" + "=" * 74)
    print("JUDGE CALIBRATION RESULTS")
    print("=" * 74)
    print(f"\n  {'Test Case':<{W}} {'Expected':<10} {'Actual':<10} {'Unverified':>12}  Result")
    print("  " + "-" * 70)
    for r in results:
        tag     = "✓ PASS" if r["passed"] is True else "✗ FAIL" if r["passed"] is False else "─ N/A"
        exp_v   = r["expected_verdict"] or "–"
        act_v   = r["actual_verdict"]
        exp_u   = str(r["expected_unverified"]) if r["expected_unverified"] is not None else "–"
        unv_str = f"{r['actual_unverified']} (exp {exp_u})"
        print(f"  {r['name']:<{W}} {exp_v:<10} {act_v:<10} {unv_str:>12}  {tag}")

    print("\n  " + "-" * 70)
    print(f"\n  Scorable cases : {len(scorable)}")
    print(f"  Passed         : {n_pass}")
    print(f"  Accuracy       : {accuracy:.0f}%")
    print(f"  Threshold      : {ACCURACY_THRESHOLD:.0f}%")
    print(f"  Status         : {status}")

    if unscored:
        print(f"\n  Unscored (ambiguous) cases:")
        for r in unscored:
            print(f"    {r['name']}: verdict={r['actual_verdict']}, "
                  f"unverified={r['actual_unverified']}")
            print(f"      {r['summary']}")
    print("=" * 74)


async def main() -> None:
    print("Running judge calibration — 10 test cases ...")
    results = await run_all(verbose=True)
    print_results(results)


if __name__ == "__main__":
    asyncio.run(main())
