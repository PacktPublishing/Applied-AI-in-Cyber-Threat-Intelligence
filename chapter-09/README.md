# Chapter 9 — The Analysis Stage

A three-agent self-refining pipeline built with the **Google Agent Development Kit (ADK)** that selects and applies Structured Analytic Techniques (SATs) to a corroborated intelligence brief, producing a structured analysis output validated against a closed-world technique catalog.

## What It Does

Given a corroborated brief (the Stage 3 output from Chapter 8), the pipeline:

1. **Selects** the most appropriate SATs from a 14-technique catalog based on scenario characteristics, evidence patterns, and audience requirements
2. **Applies** each selected technique to the brief — generating hypothesis matrices (ACH), impact chains (What-If), assumption vulnerability assessments (Key Assumptions Check), and other technique-specific outputs
3. **Validates** the analysis against catalog membership, technique-scenario matching, taxonomy balance, and tradecraft standards via a structured Pydantic verdict
4. **Corrects** errors identified by the judge and iterates until PASS or the iteration cap is reached

## Agent Architecture

```
Corroborated Brief (Stage 3 output)
   ↓
SAT_Recommendation_Agent (configurable model/temp)  →  analysis_output (SAT selections + applications)
   ↓
SAT_Judge (temp=0.0)                                →  analysis_verdict (JSON, constrained)
   ↓
Analysis_Verification_Agent (temp=0.0)              →  verified_analysis
   ↓
check_analysis_verdict_rules() + _check_loop_exit_callback
     web path:   run at the START of the next iteration, on the prior verdict
                 (bundled into the Generator's before_agent_callback)
     batch path: run AFTER each iteration completes, then written back to state
     →  the rule check downgrades a contradictory PASS to FAIL; the loop exits
        on a genuine PASS, otherwise repeats (max 3 iterations)
```

All agents are defined in `my_agent/agent.py`:

| Agent | Model | Role |
|---|---|---|
| `SAT_Recommendation_Agent` | gemini-3.1-pro-preview (configurable) | Selects SATs from the catalog and applies each to the brief |
| `SAT_Judge` | gemini-2.5-flash @ temp=0.0 | Validates technique selection, application quality, and catalog compliance |
| `Analysis_Verification_Agent` | gemini-2.5-flash @ temp=0.0 | Applies judge corrections; produces verified analysis |

## The Closed-World SAT Catalog

`my_agent/domain_data.py` defines the closed universe of analytic techniques:

- **14 SATs** — ACH, What-If Analysis, Key Assumptions Check, Red Team Analysis, Devil's Advocacy, Indicators of Change, Quality of Information Check, Structured Brainstorming, and six more
- **SAT taxonomy** with category-based selection rules (max 2 per category)
- **Audience map** — which stakeholder types each SAT serves
- **Cognitive biases** — which biases each technique is designed to counter
- **Tradecraft standards** — analytic-rigor and confidence-calibration requirements the agent must follow

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
pip install -r requirements-simulation.txt   # for the evaluation notebook
```

Launch the notebook with:

```bash
jupyter lab "Chap 9 Simulations.ipynb"
```

### 3. Configure your API key

Create a `.env` file in `chapter-09/`:

```
GOOGLE_API_KEY='your-actual-api-key-here'
GOOGLE_GENAI_USE_VERTEXAI=0
```

Create a key (free tier available) at <https://ai.google.dev/gemini-api/docs/api-key>.

**Cost expectations:** a single pipeline run is ≤ 9 model calls (3 agents × up to 3 iterations). The notebook's grid search is **450 runs**; the ground-truth eval is 5 scenarios (≤ 45 calls) and judge calibration is 14 calls.

### 4. Run the agent

From the `chapter-09/` folder (the parent of `my_agent/`):

```bash
adk web
```

## Project Structure

```
chapter-09/
├── README.md
├── requirements.txt
├── requirements-simulation.txt
├── ground_truth.csv                   # 5 expert-curated scenarios
├── config_search_results.csv          # written by the notebook grid search; ships empty until you run it
├── Chap 9 Simulations.ipynb           # all eval logic inline
├── Images/                                            # chapter figures (Figs 9.1–9.5 infographics appear in the book only)
│   ├── Stage 4 Analysis.png                               # Fig. 9.6 (pipeline topology)
│   ├── ADK Web UI Analysis Agent.png                      # Fig. 9.7 (ADK web UI)
│   ├── ADK Web UI Analysis Output - Overview.png                        # Fig. 9.8a
│   ├── ADK Web UI Analysis Output - ACH Hypothesis Matrix.png           # Fig. 9.8b
│   ├── ADK Web UI Analysis Output - What-If Impact Chain.png            # Fig. 9.8c
│   ├── ADK Web UI Analysis Output - Indicators of Change.png            # Fig. 9.8d
│   ├── ADK Web UI Analysis Output - Key Assumptions and Confidence.png  # Fig. 9.8e
│   ├── ADK Web UI Analysis Output.png                     # full output (split into 9.8a–e for print)
│   ├── Judge Calibration Results.png                      # Fig. 9.9
│   └── Ground Truth Eval.png                              # Fig. 9.10
└── my_agent/
    ├── __init__.py                    # exposes the agent package for `adk web`
    ├── agent.py                       # all agents, loop control, deterministic checkers
    ├── domain_data.py                 # 14-SAT catalog, taxonomy, selection rules, audience map
    ├── judge_eval.py                  # 14 judge calibration test cases
    ├── judge_eval_results.json        # saved judge calibration results
    └── best_config.json               # generator model/temp for the recorded runs (grid search left as an exercise)
```

## Related Files

### `Chap 9 Simulations.ipynb`

Evaluation notebook, structured to match the simulation-notebook pattern used across the Intel Cycle chapters:

1. **Setup** — consolidated imports
2. **Pipeline Helper** — `run_scenario()` wrapper with verbose output
3. **Single-Scenario Demo** — AiTM canonical scenario
4. **Grid Search** — 3 models × 3 temps × 10 scenarios × 5 runs = 450 executions. Styled ranked table and F1 pivot.
5. **Ground Truth Evaluation** — 5 scenarios, F1 score. Styled table with color-coded pass/fail. Threshold: 70% (applied to the average). Authors' run: average F1 0.78 clears the threshold; 3 of 5 scenarios pass individually.
6. **Judge Calibration** — 14 test cases, inline execution with styled table. Threshold: 80%. Authors' run: 12/14 = 86% (2 over-strict cases, eval_01 and eval_11, encoded as expected-PASS in `judge_eval.py`).
7. **Discussion** — layered validation hierarchy interpretation

### `ground_truth.csv`

Five expert-curated scenarios with expected SAT selections. Each row stores both the scenario definition (corroborated brief, expected SATs) and evaluation result columns (F1, verdict).

> **Recorded results & recovery:** the result columns ship pre-filled with the authors' recorded run. Because the eval cell resumes from any row whose F1 is non-empty, running it as shipped replays the recorded results without making any API calls — to force a real fresh run, clear the result columns first. The notebook's write-back also overwrites this file with your own results; the shipped canonical copy is always recoverable with `git checkout -- ground_truth.csv`.

### `my_agent/domain_data.py`

The SAT catalog plus audience map, cognitive biases, analytic spectrum, tradecraft standards, and SAT selection rules. All assembled into prompt text by format functions called at module initialization.

### `my_agent/judge_eval.py`

Fourteen synthetic analysis outputs with known-correct verdicts covering: valid complete analysis (PASS), hallucinated techniques (FAIL), missing critical SATs (FAIL/PARTIAL), taxonomy violations (FAIL), near-miss technique names (FAIL), and edge cases. Threshold: 80%. Authors' run: 12/14 = 86%. Two documented gaps (eval_01, eval_11) represent over-strict behavior — phantom unverified entries for valid analyses. In production this costs extra correction iterations rather than correctness; `check_analysis_verdict_rules()` guards the opposite risk — a too-lenient PASS slipping through.
