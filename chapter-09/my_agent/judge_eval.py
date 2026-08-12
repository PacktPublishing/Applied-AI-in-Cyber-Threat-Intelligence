"""
Stage 4 Analysis — Judge Evaluation

14 test cases with known-correct verdicts for independent judge calibration.
Tests whether the SAT Judge correctly:
  - Catches hallucinated (non-catalog) techniques
  - Identifies missing critical SATs for each scenario
  - Validates technique-scenario matching
  - Calibrates relevance ratings
  - Handles edge cases (near-miss names, subtle misapplications)
  - Enforces taxonomy cross-category rule (max 2 per category)
  - Validates new expanded-catalog techniques

Usage:
    python -m "Stage 4 Analysis.judge_eval"
    python -m "Stage 4 Analysis.judge_eval" --verbose
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

from google.adk import Agent, Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Ensure parent is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from .agent import make_judge_agent, parse_verdict, JudgeVerdict, APP_NAME, USER_ID
    from .domain_data import SAT_TAXONOMY
except ImportError:
    from agent import make_judge_agent, parse_verdict, JudgeVerdict, APP_NAME, USER_ID
    from domain_data import SAT_TAXONOMY


def _has_taxonomy_violation(confirmed_names: set) -> bool:
    """Return True if any taxonomy category has more than 2 confirmed techniques."""
    counts: dict = {}
    for name in confirmed_names:
        for category, members in SAT_TAXONOMY.items():
            if name in members:
                counts[category] = counts.get(category, 0) + 1
    return any(c > 2 for c in counts.values())

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("stage4_judge_eval")

# ---------------------------------------------------------------------------
# Test cases — 14 scenarios with known-correct judge verdicts
# ---------------------------------------------------------------------------

JUDGE_TEST_CASES = [
    {
        "id": "eval_01_all_valid_complete",
        "description": "Valid plan with correct SATs and good coverage — should PASS",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Partner account compromised. Three hypotheses: targeted attack, "
            "opportunistic breach, insider. Evidence: impossible travel, credential dump, repo cloning."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: ACH, What-If Analysis\n\n"
            "TECHNIQUE: ACH\n"
            "JUSTIFICATION: Three competing hypotheses exist for the partner compromise.\n"
            "APPLICATION: Hypothesis matrix evaluating targeted vs. opportunistic vs. insider "
            "against 4 evidence items. Targeted attack rated CONSISTENT with all evidence.\n"
            "AUDIENCE: Security Operations / Threat Intelligence\n\n"
            "TECHNIQUE: What-If Analysis\n"
            "JUSTIFICATION: Need to assess downstream impact if stolen code is published.\n"
            "APPLICATION: Impact chain: code theft -> competitor access to algorithms -> "
            "20% revenue product compromised -> 6-month launch delay.\n"
            "AUDIENCE: Business Leadership / Product Management\n\n"
            "KEY_ASSUMPTIONS: (1) Session hijacking was access method [HIGH vulnerability], "
            "(2) Single actor [MEDIUM vulnerability]\n"
            "OVERALL_CONFIDENCE: High"
        ),
        "expected_verdict": "PASS",
        "expected_confirmed": ["ACH", "What-If Analysis"],
        "expected_unverified": [],
        "expected_missing": [],
    },
    {
        "id": "eval_02_one_hallucination",
        "description": "Includes a non-catalog technique (SWOT Analysis) — should FAIL",
        "corroborated_brief": (
            "MEDIUM CONFIDENCE: Anomalous login pattern detected. Attribution provisional."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: Indicators of Change, SWOT Analysis\n\n"
            "TECHNIQUE: Indicators of Change\n"
            "JUSTIFICATION: Assessment is provisional, need monitoring signals.\n"
            "APPLICATION: List of 5 indicators that would confirm or refute attribution.\n"
            "AUDIENCE: SOC Manager\n\n"
            "TECHNIQUE: SWOT Analysis\n"
            "JUSTIFICATION: Need to evaluate organizational strengths and weaknesses.\n"
            "APPLICATION: Strengths-Weaknesses-Opportunities-Threats matrix.\n"
            "AUDIENCE: Business Leadership"
        ),
        "expected_verdict": "FAIL",
        "expected_confirmed": ["Indicators of Change"],
        "expected_unverified": ["SWOT Analysis"],
        "expected_missing": [],
    },
    {
        "id": "eval_03_two_hallucinations",
        "description": "Two non-catalog techniques (Delphi Method + Bayesian Network) — should FAIL",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Ransomware across 3 subnets. Initial access unclear."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: ACH, Delphi Method, Bayesian Network Analysis\n\n"
            "TECHNIQUE: ACH\n"
            "JUSTIFICATION: Multiple competing initial access hypotheses.\n"
            "APPLICATION: Matrix comparing phishing vs VPN exploit vs partner pivot.\n\n"
            "TECHNIQUE: Delphi Method\n"
            "JUSTIFICATION: Need expert consensus on likely attack vector.\n"
            "APPLICATION: Three rounds of expert polling.\n\n"
            "TECHNIQUE: Bayesian Network Analysis\n"
            "JUSTIFICATION: Probabilistic modeling of attack paths.\n"
            "APPLICATION: Bayesian network with conditional probabilities."
        ),
        "expected_verdict": "FAIL",
        "expected_confirmed": ["ACH"],
        "expected_unverified": ["Delphi Method", "Bayesian Network Analysis"],
        "expected_missing": [],
    },
    {
        "id": "eval_04_valid_but_missing_critical",
        "description": "All valid SATs but missing ACH when hypotheses exist — should be PARTIAL",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Two competing explanations for data exfiltration — insider threat "
            "vs. compromised credentials. Both have supporting evidence."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: What-If Analysis, Key Assumptions Check\n\n"
            "TECHNIQUE: What-If Analysis\n"
            "JUSTIFICATION: Need to assess impact of potential data leak.\n"
            "APPLICATION: Impact chain from exfiltration to regulatory exposure.\n\n"
            "TECHNIQUE: Key Assumptions Check\n"
            "JUSTIFICATION: Assessment assumes credentials were not shared intentionally.\n"
            "APPLICATION: Assumption matrix with vulnerability ratings."
        ),
        "expected_verdict": "PARTIAL",
        "expected_confirmed": ["What-If Analysis", "Key Assumptions Check"],
        "expected_unverified": [],
        "expected_missing": ["ACH"],
    },
    {
        "id": "eval_05_wrong_scenario_match",
        "description": "Structured Brainstorming used when evidence is sufficient for ACH — should FAIL",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Three well-defined hypotheses with extensive corroborating evidence "
            "from 5 independent sources. Each hypothesis has clear supporting and refuting signals."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: Structured Brainstorming, What-If Analysis\n\n"
            "TECHNIQUE: Structured Brainstorming\n"
            "JUSTIFICATION: Need to generate additional hypotheses.\n"
            "APPLICATION: Brainstorming session produced 6 new hypotheses.\n\n"
            "TECHNIQUE: What-If Analysis\n"
            "JUSTIFICATION: Need to assess downstream business impact.\n"
            "APPLICATION: Impact chain mapping."
        ),
        "expected_verdict": "FAIL",
        "expected_confirmed": ["What-If Analysis"],
        "expected_unverified": ["Structured Brainstorming"],
        "expected_missing": ["ACH"],
    },
    {
        "id": "eval_06_near_miss_names",
        "description": "Near-miss technique names (Competing Hypotheses Analysis vs ACH) — tests name matching",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Multiple plausible explanations for the breach."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: Competing Hypotheses Analysis, What-If Analysis\n\n"
            "TECHNIQUE: Competing Hypotheses Analysis\n"
            "JUSTIFICATION: Multiple explanations require systematic evaluation.\n"
            "APPLICATION: Matrix comparing 3 hypotheses against evidence.\n\n"
            "TECHNIQUE: What-If Analysis\n"
            "JUSTIFICATION: Downstream impact assessment needed.\n"
            "APPLICATION: Impact chain analysis."
        ),
        "expected_verdict": "PARTIAL",
        "expected_confirmed": ["Analysis of Competing Hypotheses", "What-If Analysis"],
        "expected_unverified": [],
        "expected_missing": [],
    },
    {
        "id": "eval_07_missing_ioc_for_provisional",
        "description": "Provisional attribution but no Indicators of Change recommended — PARTIAL",
        "corroborated_brief": (
            "MEDIUM CONFIDENCE: Activity attributed to UNC-XXXX but attribution is provisional. "
            "Based on IP overlap only. Could change with forensic analysis."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: ACH, Red Team Analysis\n\n"
            "TECHNIQUE: ACH\n"
            "JUSTIFICATION: Multiple threat actors could match the observed TTPs.\n"
            "APPLICATION: Hypothesis matrix comparing UNC-XXXX vs commodity actor vs insider.\n\n"
            "TECHNIQUE: Red Team Analysis\n"
            "JUSTIFICATION: Need adversary perspective on defensive gaps.\n"
            "APPLICATION: Attack path analysis from adversary viewpoint."
        ),
        "expected_verdict": "PARTIAL",
        "expected_confirmed": ["ACH", "Red Team Analysis"],
        "expected_unverified": [],
        "expected_missing": ["Indicators of Change"],
    },
    {
        "id": "eval_08_perfect_plan",
        "description": "Comprehensive 4-technique plan perfectly matched to scenario — PASS",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Partner account compromise confirmed. Three hypotheses exist. "
            "Business impact assessment required. Assessment relies on assumption that attacker "
            "used session hijacking (not verified). Team has reached consensus on state-sponsored "
            "attribution without formal challenge."
        ),
        "analysis_output": (
            "ANALYTIC_SPECTRUM_POSITION: Evaluative\n"
            "BIAS_AWARENESS: Confirmation bias (team consensus), Anchoring (first hypothesis)\n\n"
            "RECOMMENDED_TECHNIQUES: ACH, What-If Analysis, Key Assumptions Check, Devil's Advocacy\n\n"
            "TECHNIQUE: ACH\n"
            "TAXONOMY_CATEGORY: Diagnostic\n"
            "JUSTIFICATION: Three competing hypotheses for the compromise vector.\n"
            "APPLICATION: Full hypothesis matrix with 5 evidence items rated CONSISTENT/"
            "INCONSISTENT/NOT APPLICABLE per hypothesis. Targeted attack rated most consistent.\n"
            "AUDIENCE: Security Operations / Threat Intelligence\n\n"
            "TECHNIQUE: What-If Analysis\n"
            "TAXONOMY_CATEGORY: Imaginative Thinking\n"
            "JUSTIFICATION: Stolen code impacts flagship product revenue.\n"
            "APPLICATION: Impact chain: code theft -> algorithm exposure -> competitive advantage "
            "lost -> $2.3M quarterly revenue at risk -> 6-month product delay.\n"
            "AUDIENCE: Business Leadership / Product Management\n\n"
            "TECHNIQUE: Key Assumptions Check\n"
            "TAXONOMY_CATEGORY: Diagnostic\n"
            "JUSTIFICATION: Assessment depends on unverified assumption of session hijacking.\n"
            "APPLICATION: Assumption matrix: (1) session hijacking [HIGH vulnerability — if wrong, "
            "entire remediation strategy changes], (2) single actor [MEDIUM — if wrong, broader "
            "campaign], (3) no insider involvement [LOW — evidence strongly refutes].\n"
            "AUDIENCE: Threat Intelligence / Risk Management\n\n"
            "TECHNIQUE: Devil's Advocacy\n"
            "TAXONOMY_CATEGORY: Challenge\n"
            "JUSTIFICATION: Team consensus on state-sponsored attribution has not been "
            "rigorously challenged.\n"
            "APPLICATION: Strongest case AGAINST state-sponsored attribution: IP overlap may "
            "be shared infrastructure, TTP similarity reflects publicly documented techniques. "
            "Evidence gaps: no confirmed C2 match, no malware linkage. If wrong, remediation "
            "is over-scoped.\n"
            "AUDIENCE: Threat Intelligence / CISO\n\n"
            "KEY_ASSUMPTIONS: (1) Session hijacking was access method [HIGH], "
            "(2) Single actor [MEDIUM], (3) No insider involvement [LOW]\n"
            "OVERALL_CONFIDENCE: High"
        ),
        "expected_verdict": "PASS",
        "expected_confirmed": ["ACH", "What-If Analysis", "Key Assumptions Check", "Devil's Advocacy"],
        "expected_unverified": [],
        "expected_missing": [],
    },
    {
        "id": "eval_09_relevance_test",
        "description": "Valid techniques but mostly tangential to the scenario — tests relevance calibration",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Confirmed credential stuffing attack using breach-sourced passwords. "
            "Single clear attack vector. No competing hypotheses."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: Structured Brainstorming, Red Team Analysis\n\n"
            "TECHNIQUE: Structured Brainstorming\n"
            "JUSTIFICATION: Generate additional hypotheses about attacker intent.\n"
            "APPLICATION: Brainstorming session: 4 hypotheses about post-access intent.\n\n"
            "TECHNIQUE: Red Team Analysis\n"
            "JUSTIFICATION: Evaluate if our defenses can detect the known vector.\n"
            "APPLICATION: Attack path from stolen credentials through Okta to data."
        ),
        "expected_verdict": "FAIL",
        "expected_confirmed": ["Red Team Analysis"],
        "expected_unverified": ["Structured Brainstorming"],
        "expected_missing": ["What-If Analysis"],
    },
    {
        "id": "eval_10_empty_analysis",
        "description": "No SATs recommended at all — should FAIL",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Confirmed breach with multiple hypotheses and business impact."
        ),
        "analysis_output": (
            "Based on the corroborated brief, the situation seems serious. "
            "I recommend the security team investigate further and consider "
            "engaging external forensics support."
        ),
        "expected_verdict": "FAIL",
        "expected_confirmed": [],
        "expected_unverified": [],
        "expected_missing": ["ACH", "What-If Analysis"],
    },
    # --- New test cases for expanded catalog ---
    {
        "id": "eval_11_new_technique_valid",
        "description": "Devil's Advocacy correctly applied to challenge prevailing single-view assessment — PASS",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Team has reached consensus that the breach was conducted by "
            "state-sponsored actor UNC-XXXX based on IP overlap and TTP similarity. No "
            "dissenting views have been considered. All remediation planning assumes "
            "state-sponsored intent and resources."
        ),
        "analysis_output": (
            "ANALYTIC_SPECTRUM_POSITION: Explanatory\n"
            "BIAS_AWARENESS: Groupthink (team consensus without dissent), "
            "Confirmation bias (only supporting evidence cited)\n\n"
            "RECOMMENDED_TECHNIQUES: ACH, Devil's Advocacy\n\n"
            "TECHNIQUE: ACH\n"
            "TAXONOMY_CATEGORY: Diagnostic\n"
            "JUSTIFICATION: Multiple actor attributions possible despite team consensus.\n"
            "APPLICATION: Hypothesis matrix comparing state-sponsored vs financially "
            "motivated vs opportunistic. Evidence evaluation shows state-sponsored is "
            "most consistent but not conclusive.\n"
            "AUDIENCE: Threat Intelligence / CISO\n\n"
            "TECHNIQUE: Devil's Advocacy\n"
            "TAXONOMY_CATEGORY: Challenge\n"
            "JUSTIFICATION: Team has reached consensus without rigorous challenge. "
            "Single prevailing view dominates.\n"
            "APPLICATION: Strongest case AGAINST state-sponsored attribution: IP overlap "
            "may be shared infrastructure, TTP similarity may reflect publicly documented "
            "techniques adopted by multiple groups. Evidence gaps: no confirmed C2 "
            "infrastructure match, no malware sample linkage. If the team is wrong, "
            "remediation is over-scoped and diverts resources from simpler threats.\n"
            "AUDIENCE: Threat Intelligence / CISO\n\n"
            "KEY_ASSUMPTIONS: (1) IP overlap indicates same actor [HIGH vulnerability], "
            "(2) TTP match is distinctive [MEDIUM vulnerability]\n"
            "OVERALL_CONFIDENCE: Medium"
        ),
        "expected_verdict": "PASS",
        "expected_confirmed": ["ACH", "Devil's Advocacy"],
        "expected_unverified": [],
        "expected_missing": [],
    },
    {
        "id": "eval_12_taxonomy_overload",
        "description": "3 Imaginative Thinking techniques in same plan — violates cross-category rule — FAIL",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Confirmed breach with clear business impact and multiple "
            "competing hypotheses for initial access vector."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: What-If Analysis, Premortem Analysis, Scenario Analysis\n\n"
            "TECHNIQUE: What-If Analysis\n"
            "TAXONOMY_CATEGORY: Imaginative Thinking\n"
            "JUSTIFICATION: Need to assess downstream impact.\n"
            "APPLICATION: Impact chain analysis.\n\n"
            "TECHNIQUE: Premortem Analysis\n"
            "TAXONOMY_CATEGORY: Imaginative Thinking\n"
            "JUSTIFICATION: Need to identify failure modes.\n"
            "APPLICATION: Failure scenario narrative with 4 causal factors.\n\n"
            "TECHNIQUE: Scenario Analysis\n"
            "TAXONOMY_CATEGORY: Imaginative Thinking\n"
            "JUSTIFICATION: Need to plan for multiple futures.\n"
            "APPLICATION: 2x2 scenario matrix with 4 named futures."
        ),
        "expected_verdict": "FAIL",
        "expected_confirmed": ["What-If Analysis"],
        "expected_unverified": ["Premortem Analysis", "Scenario Analysis"],
        "expected_missing": ["ACH"],
    },
    {
        "id": "eval_13_new_hallucination",
        "description": "SWOT and Delphi Method still not in expanded catalog — FAIL",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Supply chain compromise confirmed. Multiple injection "
            "points identified."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: ACH, SWOT Analysis, Delphi Method\n\n"
            "TECHNIQUE: ACH\n"
            "JUSTIFICATION: Multiple injection vectors to evaluate.\n"
            "APPLICATION: Hypothesis matrix for 3 injection points.\n\n"
            "TECHNIQUE: SWOT Analysis\n"
            "JUSTIFICATION: Evaluate organizational posture.\n"
            "APPLICATION: Strengths-Weaknesses-Opportunities-Threats matrix.\n\n"
            "TECHNIQUE: Delphi Method\n"
            "JUSTIFICATION: Need expert consensus.\n"
            "APPLICATION: Multi-round expert polling."
        ),
        "expected_verdict": "FAIL",
        "expected_confirmed": ["ACH"],
        "expected_unverified": ["SWOT Analysis", "Delphi Method"],
        "expected_missing": [],
    },
    {
        "id": "eval_14_deception_detection_required",
        "description": "State actor suspected but Deception Detection omitted — PARTIAL",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Evidence points to state-sponsored actor APT-29 (Cozy Bear). "
            "However, APT-29 is known for sophisticated false flag operations. Key evidence "
            "includes conveniently placed breadcrumb artifacts pointing directly to known APT-29 "
            "tooling. The attribution feels unusually clean for a group known for operational "
            "security. Alternative: a different actor is planting APT-29 indicators."
        ),
        "analysis_output": (
            "RECOMMENDED_TECHNIQUES: ACH, Key Assumptions Check\n\n"
            "TECHNIQUE: ACH\n"
            "JUSTIFICATION: Competing attributions — APT-29 vs. false flag by another actor.\n"
            "APPLICATION: Hypothesis matrix comparing APT-29 genuine operation vs. "
            "false flag by Group B vs. unrelated commodity actor.\n"
            "AUDIENCE: Threat Intelligence\n\n"
            "TECHNIQUE: Key Assumptions Check\n"
            "JUSTIFICATION: Attribution assumes tooling artifacts are genuine, not planted.\n"
            "APPLICATION: Assumption matrix with vulnerability ratings for each "
            "attribution-critical assumption.\n"
            "AUDIENCE: Threat Intelligence / Risk Management"
        ),
        "expected_verdict": "PARTIAL",
        "expected_confirmed": ["ACH", "Key Assumptions Check"],
        "expected_unverified": [],
        "expected_missing": ["Deception Detection"],
    },
]


# ---------------------------------------------------------------------------
# Evaluation runner
# ---------------------------------------------------------------------------

async def evaluate_judge(verbose: bool = False) -> dict:
    """Run all 14 test cases through the judge and compare to expected verdicts."""
    session_service = InMemorySessionService()
    judge = make_judge_agent()

    runner = Runner(
        agent=judge,
        app_name=APP_NAME,
        session_service=session_service,
    )

    results = []

    for case in JUDGE_TEST_CASES:
        sid = f"judge_eval_{case['id']}"

        await session_service.create_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=sid,
            state={
                "corroborated_brief": case["corroborated_brief"],
                "analysis_output": case["analysis_output"],
            },
        )

        judge_output = ""
        async for event in runner.run_async(
            user_id=USER_ID,
            session_id=sid,
            new_message=types.Content(
                role="user",
                parts=[types.Part(text="Evaluate the analysis output against the SAT catalog.")],
            ),
        ):
            if event.is_final_response() and event.content and event.content.parts:
                judge_output = event.content.parts[0].text

        verdict = parse_verdict(judge_output)
        is_jv = isinstance(verdict, JudgeVerdict)

        actual_verdict = verdict.verdict if is_jv else "PARSE_ERROR"

        # Apply the pipeline's deterministic FAIL -> PARTIAL upgrade (this
        # calibration harness does not reproduce the PASS -> FAIL downgrade).
        if is_jv and actual_verdict == "FAIL":
            confirmed_names = {i.source for i in verdict.confirmed_valid}
            # Dedup: any technique listed in both confirmed_valid and unverified
            # is treated as confirmed (confirmed_valid takes precedence).
            effective_unverified = [
                i for i in verdict.unverified if i.source not in confirmed_names
            ]
            # Upgrade FAIL → PARTIAL when:
            #   - no effective unverified entries remain
            #   - at least one required SAT is missing
            #   - no taxonomy category is over-represented (> 2 techniques)
            if (not effective_unverified
                    and verdict.missing_critical
                    and not _has_taxonomy_violation(confirmed_names)):
                actual_verdict = "PARTIAL"

        verdict_match = actual_verdict == case["expected_verdict"]

        actual_confirmed = sorted([i.source for i in verdict.confirmed_valid]) if is_jv else []
        actual_unverified = sorted([i.source for i in verdict.unverified]) if is_jv else []
        actual_missing = sorted([i.source for i in verdict.missing_critical]) if is_jv else []

        result = {
            "id": case["id"],
            "description": case["description"],
            "expected_verdict": case["expected_verdict"],
            "actual_verdict": actual_verdict,
            "verdict_match": verdict_match,
            "expected_confirmed": sorted(case["expected_confirmed"]),
            "actual_confirmed": actual_confirmed,
            "expected_unverified": sorted(case["expected_unverified"]),
            "actual_unverified": actual_unverified,
            "expected_missing": sorted(case["expected_missing"]),
            "actual_missing": actual_missing,
        }
        results.append(result)

        status = "PASS" if verdict_match else "FAIL"
        logger.info(
            "[%s] %s — expected=%s actual=%s",
            status, case["id"], case["expected_verdict"], actual_verdict,
        )

        if verbose and not verdict_match:
            logger.info("  Confirmed:  expected=%s actual=%s", case["expected_confirmed"], actual_confirmed)
            logger.info("  Unverified: expected=%s actual=%s", case["expected_unverified"], actual_unverified)
            logger.info("  Missing:    expected=%s actual=%s", case["expected_missing"], actual_missing)

    # Summary
    total = len(results)
    correct = sum(1 for r in results if r["verdict_match"])
    accuracy = correct / total if total > 0 else 0

    summary = {
        "total_cases": total,
        "correct_verdicts": correct,
        "accuracy": round(accuracy, 3),
        "results": results,
    }

    logger.info("\n=== JUDGE EVALUATION SUMMARY ===")
    logger.info("Accuracy: %d/%d (%.0f%%)", correct, total, accuracy * 100)

    # Write results
    output_path = Path(__file__).parent / "judge_eval_results.json"
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info("Results written to %s", output_path)

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Stage 4 Analysis — Judge Evaluation")
    parser.add_argument("--verbose", action="store_true", help="Show detailed diff on failures")
    args = parser.parse_args()

    asyncio.run(evaluate_judge(verbose=args.verbose))


if __name__ == "__main__":
    main()
