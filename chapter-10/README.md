# Chapter 10 — The Production Stage

A three-agent self-refining pipeline built with the **Google Agent Development Kit (ADK)** that transforms a validated intelligence analysis (Stage 4 output) into a structured, logic-validated intelligence product with formal argument maps, TLP markings, and rule-enforced reasoning standards.

## What It Does

Given a verified analysis from Chapter 9, the pipeline produces a structured intelligence product covering eight required sections:

1. **Executive Summary** — high-confidence assessment with TLP marking
2. **Key Findings** — ranked by confidence level with supporting evidence
3. **Evidence Summary** — all evidence nodes with source, timestamp range, and isolated confidence
4. **Analytical Reasoning** — formal inference chains citing evidence by node ID
5. **Assumptions and Limitations** — explicit assumption nodes (A-NNN) with impact-if-wrong assessments
6. **Alternative Hypotheses** — at least one alternative per conclusion with rejection rationale
7. **Recommendations** — prioritized actions scoped to each stakeholder's decision authority
8. **Appendix: Source List with TLP Markings** — all sources with their TLP tier

The pipeline enforces five logic rules across every argument map. Any violation detected by the judge triggers a correction loop — the Verification Agent applies fixes and the judge re-evaluates until the verdict is PASS or the iteration cap is reached.

## Agent Architecture

```
Verified Analysis (Stage 4 output)
   ↓
LoopAgent  (max 3 iterations)
   └── SequentialAgent
         ├── Argument_Mapping_Agent  →  argument_map
         ├── Logic_Judge             →  production_verdict (JSON)
         └── Verification_Agent      →  verified_product
   ↓
Final intelligence product (TLP-marked, logic-validated)
```

Three agents, all in `my_agent/agent.py`:

| Agent | Model | Temp | Role |
|---|---|---|---|
| `Argument_Mapping_Agent` | gemini-2.5-flash (configurable) | 0.2 (configurable) | Structures analysis into a formal argument map: evidence nodes → inference nodes → conclusion nodes, with explicit assumption and alternative hypothesis nodes |
| `Logic_Judge` | gemini-2.5-flash | 0.0 | Validates every node in the argument map against LR-001 through LR-005; emits structured JSON via constrained decoding |
| `Verification_Agent` | gemini-2.5-flash | 0.0 | Applies the judge's corrections — preserves confirmed nodes, fixes unverified nodes, adds missing nodes — to produce the final product |

Loop exit is handled by `_check_loop_exit_callback`, a deterministic after-callback on the Verification Agent that reads the verdict from state and escalates the LoopAgent on a genuine PASS (no LLM call). The batch path (`run_pipeline`) drives the same three agents with a Python `for` loop and breaks on PASS.

## The Argument Template Catalog

`my_agent/argument_templates.py` defines the closed universe of valid argument structures:

**4 node types:**
- `evidence_node` — source, timestamp_range, description, confidence ∈ {HIGH, MEDIUM, LOW}
- `inference_node` — claim, supporting_evidence (list of E-NNN IDs), reasoning, strength ∈ {STRONG, MODERATE, WEAK}
- `conclusion_node` — assessment, confidence, supporting_inferences, key_assumptions, alternatives_considered
- `assumption_node` — assumption, if_wrong_impact, testable (bool)

**3 inference strength levels:**
- `WEAK` — 1+ evidence node from 1+ source category
- `MODERATE` — 2+ evidence nodes from 2+ source categories
- `STRONG` — 3+ evidence nodes from 3+ source categories

**5 logic rules** (LR-001 through LR-005):
- **LR-001 Evidence Chain Completeness** — conclusions require ≥2 independent evidence nodes
- **LR-002 Source Citation Requirement** — inferences must cite evidence by node ID (E-NNN), not by description
- **LR-003 Strength Calibration** — STRONG/MODERATE/WEAK labels must match the supporting evidence count and source category count
- **LR-004 Assumption Explicitness** — assumptions must be explicit A-NNN nodes, not embedded in inference reasoning
- **LR-005 Alternative Hypothesis Consideration** — each conclusion requires ≥1 alternative with a rejection rationale

The full catalog is injected into the Argument Mapping Agent's and Logic Judge's system prompts at import time via `format_templates_for_prompt()`. Violations of LR-001 through LR-005 are detectable with certainty — compliance is binary per argument node.

## Deterministic Rule Checkers

Two deterministic functions run programmatically after the judge verdict is parsed:

**`check_verdict_rules(verdict, argument_map)`** (`agent.py`) — validates structural consistency of the judge's verdict against the logic rules. Catches contradictory states (PASS with non-empty `unverified`, FAIL with empty `unverified`) and downgrades the verdict to FAIL so the loop continues rather than exiting on a contradictory result.

**`validate_product_tlp(verified_product)`** (`agent.py`) — validates TLP marking consistency. The product's TLP must be at least as restrictive as the most restrictive source TLP referenced in the appendix. Violations are reported as `tlp_issues` in the iteration output.

## Output Validation

`ProductionVerdict` (Pydantic) defines the verdict schema:

- `ConfirmedNode` — source, rationale, relevance ∈ {ESSENTIAL, USEFUL, TANGENTIAL}
- `UnverifiedNode` — source, reason, suggested_alternative
- `MissingNode` — source, importance
- `ProductionVerdict` — `confirmed_valid`, `unverified`, `missing_critical`, `verdict` ∈ {PASS, PARTIAL, FAIL}, `summary`

The judge is forced to return JSON via `output_schema=ProductionVerdict` (API-level constrained decoding). The verdict is Pydantic-validated before the Verification Agent reads it.

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
pip install -r requirements-simulation.txt   # for the simulation notebook
```

Launch the notebook with:

```bash
jupyter lab "Chap 10 Simulations.ipynb"
```

### 3. Configure your API key

Create a `.env` file in `chapter-10/`:

```
GOOGLE_API_KEY='your-actual-api-key-here'
GOOGLE_GENAI_USE_VERTEXAI=0
```

Create a key (free tier available) at <https://ai.google.dev/gemini-api/docs/api-key>.

**Cost expectations:** a single pipeline run is ≤ 9 model calls (3 agents × up to 3 iterations). The notebook's ground-truth eval is 3 scenarios (≤ 27 calls) and judge calibration is 10 calls.

### 4. Run the agent

```bash
adk web
```

Or run a single batch pipeline call directly:

```python
import asyncio
from my_agent.agent import run_pipeline

session_id, iterations = asyncio.run(run_pipeline(verified_analysis="...", max_iterations=3))
```

## Project Structure

```
chapter-10/
├── README.md
├── requirements.txt                   # runtime dependencies
├── requirements-simulation.txt        # notebook/simulation dependencies
├── ground_truth.csv                   # 3 expert-curated scenarios for evaluation
├── config_search_results.csv          # grid search results (header-only until the grid search cell is run)
├── Chap 10 Simulations.ipynb          # judge calibration + ground truth + grid search + argument-map visualization
├── Images/
│   ├── Stage 5 Production.png
│   ├── Judge Calibration Results.png
│   ├── Ground Truth Eval.png
│   ├── AiTM Argument Map.png            # static NetworkX render
│   ├── AiTM Argument Map (interactive).png  # static snapshot of the Plotly view
│   ├── AiTM Argument Map.html           # interactive Plotly view (hover + click-to-pin)
│   ├── ApexCode Argument Map (illustrative).png    # Figure 10.8 narrative map art
│   ├── Output Types Comparison Table.png    # Table 10.1 art
│   ├── ADK Web UI Argument Mapping Agent.png       # Stage 4 analysis submitted as input
│   ├── ADK Web UI Argument Mapping Output 1.png     # verified product, sections 1–3
│   ├── ADK Web UI Argument Mapping Output 2.png     # verified product, sections 4–5
│   └── ADK Web UI Argument Mapping Output 3.png     # verified product, sections 6–8
└── my_agent/
    ├── agent.py                       # all three agents, deterministic checkers, run_pipeline
    ├── argument_templates.py          # 4 node types, 3 strength levels, 5 logic rules, 8 product sections
    ├── judge_eval.py                  # 10 judge calibration test cases
    └── __init__.py
```

## Related Files

### `Chap 10 Simulations.ipynb`

Combined evaluation notebook covering three evaluations plus a visualization tool:

1. **Judge Calibration** — re-runs the `judge_eval.py` test cases with a case-level scorecard (imports `run_judge_on_argument_map` and `_score_case`); a row is fully correct only when both the verdict and the unverified count match. Threshold: 80% of rows.
2. **Ground Truth Evaluation** — runs the full pipeline against 3 expert-curated scenarios in `ground_truth.csv` and measures three metrics: **Recall** (fraction of expected argument nodes found in pipeline output), **Level Accuracy** (fraction of matched nodes with correct strength/confidence level), and **F1** (harmonic mean of precision and recall on the node set). Thresholds: Recall ≥ 60%, Level Accuracy ≥ 70%.
3. **Configuration Grid Search** — sweeps model × temperature across ten scenarios with Monte Carlo simulations (**450 pipeline runs**; progress checkpoints to `config_search_checkpoint.jsonl`, so an interrupted sweep resumes on re-run). Writes the winning config to `best_config.json`, loaded by `agent.py` at startup; until you run the sweep the file doesn't exist and `agent.py` falls back to its defaults (gemini-2.5-flash @ temp 0.2). *Printed copies of the notebook show the two sweep cells as placeholders; the runnable cells ship in this repository.*
4. **Argument Map Visualization** (§9) — `parse_argument_map(text)` builds a NetworkX `DiGraph` from any argument-map markdown using the same regex patterns the Logic_Judge applies. Two renderers are provided: `visualize_argument_map(...)` writes a static matplotlib PNG (book-ready), and `visualize_argument_map_interactive(...)` returns a Plotly figure with per-node hover tooltips. Both use Graphviz `dot` for layout. The interactive view also exports a self-contained HTML file with **click-to-pin** annotations — open `Images/AiTM Argument Map.html` in any browser, click a node to pin its description, click the pin to remove it.

### `ground_truth.csv`

Three expert-curated scenarios — AiTM Session Hijacking, Ransomware via Stolen VPN Credentials, and BEC with OAuth Consent Abuse — each with a verified analysis, expected argument nodes by type and ID, and expected key finding. Drives the notebook's ground-truth comparison across Recall, Level Accuracy, and F1.

> **Recorded results & recovery:** the result columns ship pre-filled with the authors' recorded run, and running the ground-truth eval writes your own results over them. Section 9's demo cells likewise rewrite the shipped `Images/AiTM Argument Map` files. Any overwritten file is recoverable with `git checkout -- <path>`.

### `my_agent/argument_templates.py`

The argument node catalog plus `format_templates_for_prompt()`, which renders all node types, strength levels, logic rules, and required product sections as a flat string for static prompt injection. Also provides `compute_verdict_metrics(verdict)` for computing precision, coverage, F1, and relevance from a `ProductionVerdict` dict. Treated as trusted infrastructure — ships in source code rather than via RAG so it cannot drift.

### `my_agent/judge_eval.py`

Ten synthetic argument maps with known-correct verdicts covering: valid complete argument (PASS), LR-001 violation (conclusion with one evidence node), LR-002 violation (inference without E-NNN citation), LR-003 violation (STRONG label with two evidence nodes), LR-004 violation (implicit assumption), LR-005 violation (no alternative hypotheses), circular reasoning (inference citing inference), missing product sections, correctly calibrated WEAK chain (PASS), and a comprehensive multi-conclusion argument (PASS). Accuracy threshold: 80%.

## A Note on the Recorded Results

The shipped artifacts record honest results, including a failure: the recorded ground-truth run passes Recall (**66.7%** vs the 60% threshold) but misses Level Accuracy (**67%** vs 70%) — the notebook's dated provenance note documents that run. If your own runs land below threshold, you are reproducing the recorded behavior, not breaking anything.

The judge calibration also illustrates the two accuracy views used across these chapters: counting **individual checks passed**, the recorded run scores 16/20 = 80% (exactly at the wire); counting **test cases fully correct** — the computation shown in the styled table and the chapter figure — it scores 7/10. Neither number is wrong; they answer different questions, and the gap between them is itself evidence of the judge-leniency failure mode this book teaches.
