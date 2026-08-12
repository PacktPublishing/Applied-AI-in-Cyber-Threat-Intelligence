# Chapter 8 — The Processing Stage

A three-agent self-refining pipeline built with the **Google Agent Development Kit (ADK)** that turns a validated collection plan into a corroborated intelligence brief with rule-enforced confidence levels and TLP markings.

## What It Does

Given a verified collection plan (the Stage 2 output from Chapter 7), the pipeline produces a structured corroboration brief covering five sections:

1. **Signal Inventory** — each signal observed from the collection plan's sources, classified by type and isolated confidence level
2. **Corroboration Links** — cross-source correlations with the corroboration rule satisfied and the resulting confidence level (LOW / MEDIUM / HIGH)
3. **Confidence Assessment Summary** — table of findings, confidence levels, supporting signals, and source categories
4. **Attribution Assessment** — threat actor attribution if evidence meets the CR-005 standard; otherwise states what additional signals would be required
5. **Intelligence Gaps** — signals that remain uncorroborated and what additional collection would elevate them

Closed with a **Key Finding** callout — the single highest-confidence finding with the strongest cross-source corroboration — and a **TLP marking** assigned from the most restrictive source category referenced.

> **Note on telemetry**: This pipeline operates on the collection plan, not on live log data. The Correlation Agent reasons about what signals *would* be observed given the plan's sources. Treat the output as a threat model and corroboration framework — "if these signals appear from these sources, here is how they corroborate" — not a detection result.

## Agent Architecture

```
Collection Plan (Stage 2 output)
   ↓
LoopAgent  (max 3 iterations; exits early when a sub-agent escalates)
   └── SequentialAgent
         ├── Correlation_Agent            →  corroboration_brief
         ├── Processing_Validation_Judge  →  processing_verdict (JSON)
         └── Verification_Agent           →  verified_brief
               └─ after_agent_callback _escalate_on_pass: sets actions.escalate on PASS
   ↓
Final corroboration brief (TLP-marked, rule-validated)
```

Three agents, all in `my_agent/agent.py`:

| Agent | Model | Role |
|---|---|---|
| `Correlation_Agent` | defaults from best_config.json (as shipped: gemini-2.5-flash @ temp=0.2) | Synthesizes and correlates signals; assigns confidence levels per corroboration rules |
| `Processing_Validation_Judge` | gemini-2.5-flash @ temp=0.0 | Validates every confidence level and correlation link against the signal catalog; emits structured JSON |
| `Verification_Agent` | gemini-2.5-flash @ temp=0.0 | Mechanically applies the judge's corrections and produces the final brief; its `after_agent_callback` (`_escalate_on_pass`) exits the loop on a PASS verdict, deterministically and with no model call |

Loop exit is handled by that callback rather than a separate agent: ADK's `LoopAgent` stops as soon as any sub-agent sets `actions.escalate = True`, so the last agent in the sequence (Verification) signals the exit directly.

State flows between agents through `output_key` writes and `{placeholder}` reads in each instruction.

## The Closed-World Signal Catalog

`my_agent/indicator_schemas.py` defines the closed universe of signal types, confidence rules, and corroboration relationships:

- **10 signal types** — authentication_anomaly, credential_exposure, repository_access_anomaly, infrastructure_match, domain_permutation, dark_web_mention, phishing_indicator, data_movement, endpoint_compromise, privilege_escalation
- **24 source categories** — identity_provider, mfa, edr_xdr, breach_intelligence, dark_web, version_control, email_security, network_security, cloud_audit, casb, and more
- **3 confidence levels** — LOW (1 signal, 1 category), MEDIUM (2 signals, 2 categories), HIGH (3+ signals, 3+ categories)
- **5 corroboration rules** (CR-001 through CR-005) — cross-category requirement, temporal proximity (tiered), geographic consistency, corroborates-with constraint, attribution evidence standard
- **TLP markings** — RED / AMBER / GREEN / CLEAR assigned from the most restrictive source category referenced

The full catalog is injected statically into the Correlation Agent's and the Judge's system prompts at import time via `format_schemas_for_prompt()`. Any confidence level that violates these rules is detectable with certainty — compliance is binary per correlation link.

## Deterministic Rule Checker

`check_verdict_rules()` in `agent.py` programmatically validates the judge's structured verdict after Pydantic parsing. It catches logical errors the LLM judge may miss — PASS with non-empty unverified lists, CR-004 violations in the corroboration graph — and downgrades the verdict to FAIL so the loop continues rather than exiting on a contradictory result.

## Output Validation

`ProcessingVerdict` (Pydantic) defines the verdict schema with three nested models:

- `ConfirmedCorrelation` — source, rationale, relevance ∈ {ESSENTIAL, USEFUL, TANGENTIAL}
- `UnverifiedCorrelation` — source, reason, suggested_alternative
- `MissingCorrelation` — source, importance

The judge is forced to return JSON via `response_mime_type="application/json"`, parsed and validated before the Verification Agent reads it.

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate     # macOS/Linux
.venv\Scripts\activate        # Windows
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

To also run the simulation notebook (`Chap 8 Simulations.ipynb`):

```bash
pip install -r requirements-simulation.txt
```

Launch the notebook with:

```bash
jupyter lab "Chap 8 Simulations.ipynb"
```

### 3. Configure your API key

Create a `.env` file at the `chapter-08/` root (or the project root one level up) and add:

```
GOOGLE_API_KEY='your-actual-api-key-here'
GOOGLE_GENAI_USE_VERTEXAI=0
```

Create a key (free tier available) at <https://ai.google.dev/gemini-api/docs/api-key>.

**Cost expectations:** a single pipeline run is ≤ 9 model calls (3 agents × up to 3 iterations). The notebook's grid search is 450 runs at roughly six calls each — **≈ 2,700 calls**; the ground-truth eval is 3 scenarios (≤ 27 calls) and judge calibration is 10 calls.

### 4. Run the agent

```bash
cd my_agent
python agent.py
```

Or run interactively from the `chapter-08/` root:

```bash
adk web
```

## Project Structure

```
chapter-08/
├── README.md
├── requirements.txt
├── requirements-simulation.txt
├── ground_truth.csv                 # 3 expert-curated scenarios for the notebook
├── Chap 8 Simulations.ipynb         # grid search + ground-truth eval + visualization
├── config_search_results.csv        # written by the notebook grid search; empty until you run it
├── ground_truth_results.json        # per-scenario results (ships pre-filled with the recorded run; a fresh eval overwrites it)
├── gt_checkpoint.json               # checkpoint written by the notebook's ground-truth eval (ships with the completed recorded run; delete it, or individual scenario entries, to force a fresh run)
├── Images/                          # screenshots
└── my_agent/
    ├── __init__.py
    ├── agent.py                     # all three agents + escalate-on-PASS callback + deterministic rule checker
    ├── indicator_schemas.py         # 10 signal types, 5 corroboration rules, TLP levels
    ├── judge_eval.py                # 10 judge calibration test cases
    └── best_config.json             # loaded by agent.py at import; as shipped hand-set, overwritten when you run the grid search
```

## Related Files

### `Chap 8 Simulations.ipynb`

Combined experiment notebook covering three evaluations:

1. **Grid search** — three models (`gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-3.1-pro-preview`) × three temperatures (0.0, 0.5, 1.0) × ten signal scenarios × five Monte Carlo simulations = 450 total runs, capped at 20 concurrent pipelines via `asyncio.Semaphore(20)`. Ranks configurations by F1 (judge-compliance metric); tiebroken on iteration count, then average latency. Writes the winning config to `best_config.json`, which `agent.py` loads at import time.
2. **Ground-truth eval** — runs the pipeline against the three expert-curated scenarios in `ground_truth.csv` and measures **Confidence Accuracy** (fraction of findings where the pipeline's relevance rating is consistent with the expected confidence level). Threshold: Confidence Accuracy ≥ 70%.
3. **Judge calibration** — runs ten synthetic corroboration briefs with known-correct verdicts through the Processing Validation Judge and reports check accuracy. Threshold: 80%.

The grid search measures how well the Correlation Agent satisfies the judge; the ground-truth eval measures whether the corroboration brief matches what a human analyst would produce. A lenient judge produces F1=100% on a brief with wrong confidence levels — only the ground-truth comparison catches that failure mode.

### `ground_truth.csv`

Three expert-curated scenarios — AiTM Session Hijacking (Full Chain), Ransomware via Stolen VPN Credentials, and BEC with OAuth Consent Abuse — each with a collection plan, threat context, expected findings keyed by signal type combinations, expected key finding, and expected attribution assessment. Drives the notebook's ground-truth comparison against the Confidence Accuracy threshold (≥ 70%).

### `my_agent/indicator_schemas.py`

The signal type catalog plus `format_schemas_for_prompt()`, which renders all schemas, confidence rules, corroboration rules, and TLP markings as a flat string for static prompt injection. Treated as trusted infrastructure — ships in source code rather than via RAG so it cannot drift.

### `my_agent/judge_eval.py`

Ten synthetic corroboration briefs with known-correct verdicts covering: valid HIGH confidence, confidence inflation, CR-001 same-category corroboration, CR-004 invalid corroboration pairs, CR-002 temporal violations, CR-003 geographic inconsistency, CR-005 unsupported attribution, missed obvious correlations, and comprehensive multi-signal briefs. All ten cases are scorable. Accuracy threshold: 80%.

## A Note on the Recorded Results

The shipped evaluation artifacts record honest results, including failures: the recorded ground-truth run averages **50% Confidence Accuracy against the 70% threshold**, and the recorded judge calibration scores **75% against the 80% bar** (visible in the shipped JSON, checkpoint, and reference screenshots). That is the point, not a broken setup — this book's evaluation methodology only works if evaluations are allowed to fail, and the recorded run demonstrates what a failing calibration looks like in practice. If your own runs also land below threshold, you are reproducing the recorded behavior; treat closing the gap (tighter prompts, stronger rules) as the exercise.

Also note the two accuracy views in the notebook: the summary print counts **individual checks passed**, while the styled table counts **test cases fully correct** — the same run can score differently under each (recorded: 75% of checks, 5/10 cases). Neither is wrong; they answer different questions about the same run.

One recorded scenario makes the failure mode concrete: *BEC with OAuth Consent Abuse* **passes with zero confirmed findings** (0 findings, 0 overlap, verdict PASS in a single iteration). Neither the judge nor `check_verdict_rules()` tests for an empty `confirmed_valid` on a PASS — that gap is the judge-leniency lesson on display, and closing it is the natural reader exercise.

The shipped result artifacts (`ground_truth_results.json`, `gt_checkpoint.json`, `ground_truth.csv`) all hold the recorded run and are overwritten by fresh evals — any of them is recoverable with `git checkout -- <file>`.
