# Chapter 11 — The Dissemination Stage

A fan-out pipeline built with the **Google Agent Development Kit (ADK)** — three fixed agents plus one dynamically generated brief agent per routed stakeholder — that routes a verified intelligence product to the correct set of corporate stakeholders, generates tailored briefs for each recipient, and validates every routing and classification decision against a closed-world catalog of rules.

## What It Does

Given a verified intelligence product (the Stage 5 output from Chapter 10), the pipeline:

1. **Routes** the product to the correct subset of ten stakeholder roles based on eight hard routing rules — mandatory inclusion, contractual triggers, classification ceilings, confidence gates, and over-routing restrictions
2. **Generates** a tailored brief for each routed stakeholder sequentially (fan-out), with per-brief retries, and with format and content scoped to that role's decision authority and clearance level
3. **Validates** every classification assignment deterministically against the stakeholder clearance hierarchy before the judge sees the plan
4. **Judges** the assembled dissemination plan against routing correctness and completeness criteria, returning a structured Pydantic verdict
5. **Verifies** corrections identified by the judge and produces the final dissemination plan
6. **Loops** until the verdict is PASS or the iteration cap is reached

The two topologies — batch path (`run_pipeline()`) and web path (`adk web`) — share the same agents but differ in brief generation: the batch path runs the full fan-out, the web path delivers raw structured output for interactive use.

## Agent Architecture

```
Verified Product (Stage 5 output)
   ↓
Routing_Agent (temp=0.0)              →  routing_manifest (JSON)
   ↓
Brief_Generator × N (fan-out)         →  per-stakeholder brief per routed role
   ↓
check_classification_compliance()     →  deterministic RR-004 / RR-005 check
   ↓
Routing_Judge (temp=0.0)              →  dissemination_verdict (JSON)
   ↓
check_verdict_rules()                 →  deterministic structural check
   ↓
check_over_routing()                  →  deterministic RR-003 / RR-008 over-routing check
   ↓
Verification_Agent (temp=0.0)         →  verified dissemination plan
   ↓
_escalate_on_pass callback            →  exit LoopAgent on PASS (max 3 iterations)
```

All agents are defined in `my_agent/agent.py`:

| Agent | Model | Role |
|---|---|---|
| `Routing_Agent` | gemini-2.5-flash @ temp=0.0 | Applies all eight routing rules to produce a routing manifest — which stakeholders receive the product, at what classification tier, and why |
| `Brief_Generator` (×N) | gemini-2.5-flash (configurable) | Generates one tailored brief per routed stakeholder, sequentially, with per-brief retries; all generators share one dedicated `InMemorySessionService`, each in its own session |
| `Routing_Judge` | gemini-2.5-flash @ temp=0.0 | Validates routing correctness (six checks) and completeness (six checks) against the stakeholder catalog; emits structured JSON |
| `Verification_Agent` | gemini-2.5-flash @ temp=0.0 | Applies the judge's corrections; produces the final plan. `_escalate_on_pass` after-agent callback exits the LoopAgent when verdict is PASS |

## The Closed-World Stakeholder Catalog

`my_agent/stakeholder_directory.py` defines the closed universe of routing decisions:

- **10 stakeholder roles** — `soc_manager`, `ciso`, `threat_hunt_lead`, `vp_cloud_engineering`, `general_counsel`, `head_of_product`, `corporate_comms`, `third_party_risk`, `privacy_dpo`, `hr_operations`
- **4 classification tiers** — RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC — with a numeric hierarchy enforcing clearance ceilings
- **8 routing rules** (RR-001 through RR-008):
  - Mandatory inclusion (RR-001 SOC Manager, RR-002 General Counsel on contractual triggers, RR-006 Privacy DPO on regulatory triggers, RR-007 HR on insider threats)
  - Over-routing restriction (RR-003 Corporate Comms only on public disclosure risk)
  - Classification ceiling (RR-004 brief classification ≤ stakeholder clearance)
  - IOC policy (RR-005 no IOCs in non-technical briefs)
  - Confidence gate (RR-008 LOW-confidence indicators route to SOC Manager and Threat Hunt Lead only)
- **3 confidence-gated routing tiers** — HIGH, MEDIUM, LOW — controlling which stakeholder classes are eligible

The full catalog is injected into the Routing Agent's and Judge's system prompts at import time via `format_directory_for_prompt()`. Compliance with classification, IOC, and over-routing rules is binary and detectable with certainty.

## Deterministic Rule Checkers

Three deterministic checkers run independently of the LLM judge and cannot be overridden by it:

**`check_classification_compliance()`** (`stakeholder_directory.py`) — checks every routed stakeholder's brief classification against the clearance hierarchy (RR-004) and IOC policy (RR-005). Runs at Phase 2.5, between brief generation and the judge; violations are logged there. When the judge later returns PASS despite logged classification violations, the verdict is forced to FAIL; a PARTIAL verdict already routes through the correction path.

**`check_verdict_rules()`** (`agent.py`) — validates the structural consistency of the judge's verdict. Catches PASS with non-empty `unverified`, PASS with non-empty `missing_critical`, and FAIL with empty `unverified`. Downgrades PASS to FAIL if contradictions are found.

**`check_over_routing()`** (`stakeholder_directory.py`) — catches the two over-routing patterns the judge under-penalizes: RR-008 (any stakeholder beyond `soc_manager` / `threat_hunt_lead` at LOW confidence) and RR-003 (`corporate_comms` routed with no public disclosure trigger keyword in the rationale). Promotes verdict to FAIL when violations are detected — closing the judge's known gap of returning PARTIAL where FAIL is required for over-routing violations.

## Output Validation

`DisseminationVerdict` (Pydantic) defines the verdict schema:

- `ConfirmedRouting` — stakeholder correctly routed with valid classification
- `UnverifiedRouting` — stakeholder with routing or classification violations; includes reason and rule reference
- `MissingRouting` — mandatory stakeholder absent from the routing manifest
- `DisseminationVerdict` — top-level object containing `confirmed_valid`, `unverified`, `missing_critical`, `verdict` ∈ {PASS, PARTIAL, FAIL}, `summary`

Three validation layers enforce this schema: API-level constrained decoding (`output_schema`), Pydantic validation in the batch path, and pre-verification validation in the web path.

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

To run the simulation notebook (`Chap 11 Simulations.ipynb`), also install:

```bash
pip install -r requirements-simulation.txt
```

Launch the notebook with:

```bash
jupyter lab "Chap 11 Simulations.ipynb"
```

### 3. Configure your API key

Create a `.env` file in `chapter-11/`:

```
GOOGLE_API_KEY='your-actual-api-key-here'
GOOGLE_GENAI_USE_VERTEXAI=0
```

Create a key (free tier available) at <https://ai.google.dev/gemini-api/docs/api-key>.

**Cost expectations:** a single pipeline run makes several model calls per iteration (routing + per-audience briefs + judge + verification, up to 3 iterations). The notebook's grid search is **200 pipeline executions**; the ground-truth eval is 8 scenarios and judge calibration is 15 calls.

### 4. Run the agent

```bash
adk web
```

Or run a single batch pipeline call directly:

```python
import asyncio
from my_agent.agent import run_pipeline

session_id, iterations = asyncio.run(run_pipeline(verified_product="...", max_iterations=3))
```

## Project Structure

```
chapter-11/
├── README.md
├── requirements.txt                   # runtime dependencies
├── requirements-simulation.txt        # notebook/simulation dependencies
├── ground_truth.csv                   # 8 expert-curated scenarios for evaluation
├── config_search_results.csv          # grid search results (header-only until you run the sweep)
├── Chap 11 Simulations.ipynb          # judge calibration + ground truth + grid search
├── Images/                                                          # (Figs 11.1–11.9 infographics appear in the book only)
│   ├── Agentic Threat Intel - Stage 6.png                           # Fig 11.10 pipeline architecture
│   ├── Judge Calibration Results.png                                # Fig 11.11
│   ├── Ground Truth Eval.png / Ground Truth Eval_highres.png        # Fig 11.12
│   ├── ADK Web UI Routing Agent.png                                 # Fig 11.13
│   └── ADK Web UI Routing Output.png                                # Fig 11.14 (full screenshot)
└── my_agent/
    ├── agent.py                       # all agents, fan-out logic, deterministic checkers
    ├── stakeholder_directory.py       # 10 stakeholders, 8 routing rules, classification hierarchy
    ├── judge_eval.py                  # 15 judge calibration test cases
    └── __init__.py
```

## Related Files

### `Chap 11 Simulations.ipynb`

Evaluation notebook structured to match the Ch8/Ch10 pattern:

1. **Setup** — consolidated imports, environment loading
2. **Pipeline Helper** — `run_scenario()` wrapper with verbose per-iteration output
3. **Single-Scenario Demo** — AiTM canonical scenario, full verbose run
4. **Grid Search** — 2 models × 2 temperatures × 10 scenarios × 5 Monte Carlo runs = 200 total executions. Ranks configurations by avg F1. Styled pandas tables for ranked results and F1 pivot.
5. **Ground Truth Evaluation** — runs the full pipeline against 8 expert-curated scenarios in `ground_truth.csv`. Styled pandas table with color-coded pass/fail rows. Thresholds: Routing overlap ≥ 60%, Classification Accuracy ≥ 70%.
6. **Judge Calibration** — runs 15 test cases inline with styled pandas output. Threshold: 80% (24/30 checks).
7. **Discussion** — layered validation hierarchy interpretation

### `ground_truth.csv`

Eight expert-curated scenarios spanning the routing conditions the pipeline must handle: LOW-confidence gate (RR-008), mandatory regulatory inclusion (RR-006 Privacy DPO), mandatory insider routing (RR-007 HR), TLP:RED classification ceiling (RR-004), contractual third-party trigger (RR-002 General Counsel), and mixed HIGH/MEDIUM confidence profiles. Each row stores both the scenario definition (as JSON strings) and the evaluation result columns.

> **Recorded results & recovery:** the result columns ship pre-filled with the authors' recorded run (the numbers behind Fig 11.12). The notebook's write-back cell overwrites them with your own results — and a partially completed eval followed by the write-back silently mixes your rows with the recorded ones. The shipped canonical copy is always recoverable with `git checkout -- ground_truth.csv`.

### `my_agent/stakeholder_directory.py`

The stakeholder catalog plus `format_directory_for_prompt()`, which renders all roles, routing rules, classification tiers, confidence routing tiers, and notification order as a flat string for static prompt injection. Also contains two deterministic checkers: `check_classification_compliance()` (RR-004/RR-005, runs at Phase 2.5 before the judge) and `check_over_routing()` (RR-003/RR-008, runs at Phase 3.5 after the judge, promotes verdict to FAIL for over-routing violations the judge under-penalizes).

### `my_agent/judge_eval.py`

Fifteen synthetic dissemination plans with known-correct verdicts covering: clean routing across all confidence levels (PASS cases 1–3), mandatory-inclusion violations (RR-001, RR-002, RR-006, RR-007), classification ceiling violations (RR-004), IOC policy violations (RR-005), over-routing violations (RR-003, RR-008), and confidence-gate violations. All 15 cases are scorable across 30 binary checks. Accuracy threshold: 80%.

## Known Judge Calibration Gap

The Routing_Judge accurately identifies routing violations but consistently under-penalizes over-routing severity at RR-003 (Corporate Comms without public disclosure risk) and RR-008 (all stakeholders on LOW-confidence indicators) — returning PARTIAL when FAIL is required. `check_verdict_rules()` provides a partial backstop for PASS-with-unverified cases but cannot promote PARTIAL to FAIL, because PARTIAL with non-empty `unverified` is structurally valid. `check_over_routing()` closes this gap specifically for RR-003 and RR-008: it evaluates the routing manifest directly and forces the verdict to FAIL when either violation is detected, independently of the judge's severity assessment. This is documented in the judge calibration section of the notebook.

Note the two accuracy computations in the notebook: the summary print scores per **individual check** (recorded run: 24/30 = 80%, exactly at threshold), while the styled table and Fig 11.11 count **cases fully correct** (11/15 = 73%). Both describe the same run — the per-check number is the stated pass/fail gate, and the per-case view is the stricter lens that exposes the four missed cases discussed above.

## A Note on the Recorded Results

The ground-truth banner "ALL THRESHOLDS MET — PASS" is computed on **averages** (avg routing overlap 72% ≥ 60%, avg classification 94% ≥ 70%), while the per-row table shows **3 of 8 scenarios red** — including one that routed 9 stakeholders where 3 were expected, in the need-to-know chapter. Every red row still carries a green judge Verdict: that gap between the judge's leniency and the ground-truth check is the chapter's own thesis visible in the shipped data, not a defect in your setup. The aggregate PASS remains the stated gate; the per-row view is where the improvement work lives. (For the parallel two-metric situation in the judge calibration, see the Known Judge Calibration Gap section above.)
