# Chapter 12 — The Feedback Stage

A three-agent self-refining pipeline built with the **Google Agent Development Kit (ADK)** that transforms raw stakeholder feedback (received after Stage 6 Dissemination) into structured, validated follow-on Quality Intelligence Requirements (QIRs) that re-enter the intelligence cycle at Stage 1.

## What It Does

Given stakeholder feedback and the original QIR context, the pipeline:

1. **Decomposes** raw questions and concerns into atomic follow-on QIRs — each distinct question becomes a separate QIR conforming to the nine-field `QIR_TEMPLATE`
2. **Validates** every generated QIR against template completeness, scope classification, priority justification, temporal window explicitness, and compound-question splitting rules
3. **Corrects** violations identified by the judge — fills missing fields, fixes scope misclassification, splits compound QIRs, adds priority justification — producing the verified follow-on QIR set
4. **Loops** until the verdict is PASS or the iteration cap is reached

The output is a structured set of follow-on QIRs (FP-NNN format) that feed directly into Stage 1 Requirement for the next intelligence cycle.

## Agent Architecture

```
Stakeholder Feedback + Original QIR context
   ↓
LoopAgent  (max 3 iterations)
   └── SequentialAgent
         ├── Transformation_Agent  →  feedback_qirs       (JSON array)
         ├── Compliance_Judge      →  feedback_verdict    (JSON, constrained)
         └── Verification_Agent    →  verified_feedback
   ↓
Verified follow-on QIRs (FP-NNN, template-validated, scope-classified)
```

Loop exit is controlled by `_check_loop_exit_callback` (a `before_agent_callback` on `Transformation_Agent`), which reads the verdict from state and sets `escalate=True` on PASS. No LLM-based loop controller is needed.

Three agents, all in `my_agent/agent.py`:

| Agent | Model | Temp | Role |
|---|---|---|---|
| `Transformation_Agent` | gemini-2.5-flash (configurable) | 0.2 (configurable) | Decomposes raw feedback into atomic follow-on QIRs; on refinement passes, preserves confirmed QIRs, fixes unverified QIRs, and adds missing QIRs per the judge verdict |
| `Compliance_Judge` | gemini-2.5-flash | 0.0 | Validates every QIR against TR-001 through TR-006 and template completeness; emits structured JSON via constrained decoding |
| `Verification_Agent` | gemini-2.5-flash | 0.0 | Applies the judge's corrections to produce the final verified QIR set |

State handoff:
- `Transformation_Agent` → `output_key="feedback_qirs"` → session state
- `Compliance_Judge` → `output_key="feedback_verdict"` → session state (JSON)
- `Verification_Agent` → `output_key="verified_feedback"` → session state

## The QIR Template Catalog

`my_agent/requirement_templates.py` defines the closed universe of valid follow-on QIR structures:

**9 required fields** (`QIR_TEMPLATE`):
- `qir_id` — unique identifier; format `FP-NNN` (zero-padded sequence)
- `originator` — role title or named individual who raised the question
- `raw_feedback` — verbatim stakeholder question or concern (audit trail)
- `refined_requirement` — formal intelligence requirement stating what is needed, what scope it covers, and what decision it enables
- `scope` — one of the four scope classifications (see below)
- `temporal_window` — explicit time scope: retroactive hunt duration or continuous monitoring cycle
- `priority` — urgency tier (`IMMEDIATE`, `ROUTINE`, or `DEFERRED`)
- `priority_justification` — operational impact justification citing criteria from the corresponding priority level
- `linked_qir` — original QIR this follow-on traces to; format `QIR-YYYY-NNNN`

**4 scope classifications** (`SCOPE_TYPES`):
- `EXPANSION` — broader scope; extends investigation to additional entities or populations
- `DEEPENING` — more detail; drills into an existing finding for additional granularity
- `PIVOT` — new direction; changes investigation focus to a different domain or stakeholder concern
- `VALIDATION` — confirm or deny; tests a specific claim, hypothesis, or proposed countermeasure

**3 priority levels** (`PRIORITY_LEVELS`):
- `IMMEDIATE` — active threat, ongoing exposure, or regulatory deadline
- `ROUTINE` — important but not time-critical; threat contained or question is strategic
- `DEFERRED` — low urgency; informational, speculative, or dependent on other QIRs

**6 transformation rules** (TR-001 through TR-006):
- **TR-001 Atomic Decomposition** — each distinct question or concern becomes a separate QIR; compound questions must be split
- **TR-002 Linked QIR Requirement** — every follow-on QIR must reference the original QIR via `linked_qir`; orphaned QIRs break the audit chain
- **TR-003 Scope Classification Required** — every QIR must be classified as exactly one scope type; misclassification distorts downstream prioritization
- **TR-004 Priority Justification** — every priority assignment must include explicit justification citing operational impact criteria
- **TR-005 Temporal Window Explicitness** — time scope must be specific (e.g., "90-day retroactive hunt"); vague references like "recent" or "ongoing" are insufficient
- **TR-006 Non-Actionable Feedback Filter** — praise, acknowledgments, and status updates produce zero QIRs; the agent must not fabricate requirements from non-actionable input

The full catalog is injected into the Transformation Agent's and Compliance Judge's system prompts at import time via `format_templates_for_prompt()`.

## Deterministic Rule Checker

**`check_verdict_rules(verdict)`** (`agent.py`) — validates structural consistency of the judge's verdict programmatically. Catches:
- PASS with non-empty `unverified` (should be FAIL)
- PASS with non-empty `missing_critical` (should be PARTIAL)
- FAIL with empty `unverified` (FAIL requires at least one unverified QIR)

Discrepancies are logged per iteration; if PASS is issued with a non-empty `unverified` list, the verdict is downgraded so the loop continues rather than exiting on a contradictory result.

A second deterministic layer runs in `run_pipeline()`: `validate_qir_fields()` from `requirement_templates.py` checks every QIR in the verified output for required field presence, `qir_id` format (`FP-NNN`), `linked_qir` format (`QIR-YYYY-NNNN`), and valid `scope`/`priority` values. Violations are reported as `qir_validation_issues` in the iteration output.

A third defensive helper, **`_strip_code_fence(text)`**, is applied to both `feedback_qirs` (Transformation_Agent output) and `verified_feedback` (Verification_Agent output) before they are stored in the iteration record. LLMs occasionally wrap structured-output JSON in markdown fences (` ```json ... ``` `) despite prompt instructions; the helper strips the fence so every downstream consumer — the deterministic validator, the notebook's ground-truth evaluator, the calling script — can `json.loads()` the value directly.

## Output Validation

`FeedbackVerdict` (Pydantic) defines the verdict schema:

- `ConfirmedQIR` — `source`, `rationale`, `relevance` ∈ {ESSENTIAL, USEFUL, TANGENTIAL}
- `UnverifiedQIR` — `source`, `reason`, `suggested_alternative`
- `MissingQIR` — `source`, `importance`
- `FeedbackVerdict` — `confirmed_valid`, `unverified`, `missing_critical`, `verdict` ∈ {PASS, PARTIAL, FAIL}, `summary`

The judge is forced to return JSON via `output_schema=FeedbackVerdict` (API-level constrained decoding). The verdict is Pydantic-validated before the Verification Agent reads it.

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate     # macOS/Linux
.venv\Scripts\activate        # Windows
```

### 2. Install dependencies

```bash
pip install -r requirements.txt                   # runtime
pip install -r requirements-simulation.txt        # notebook (pandas, jinja2, jupyter)
```

Launch the notebook with:

```bash
jupyter lab "Chap 12 Simulations.ipynb"
```

### 3. Configure your API key

Create a `.env` file in `chapter-12/`:

```
GOOGLE_API_KEY='your-actual-api-key-here'
GOOGLE_GENAI_USE_VERTEXAI=0
```

Create a key (free tier available) at <https://ai.google.dev/gemini-api/docs/api-key>.

**Cost expectations:** a single pipeline run is ≤ 9 model calls (3 agents × up to 3 iterations). The notebook's grid search is **66 pipeline runs**; the ground-truth eval is 5 scenarios (≤ 45 calls) and judge calibration is 10 calls.

### 4. Run the agent

**Web UI (interactive chat):**

```bash
cd chapter-12
adk web
```

Open the URL ADK prints (typically `http://localhost:8000`), select **`my_agent`** from the agent dropdown, and paste a paired-context prompt:

```
ORIGINAL QIR:
QIR-2025-0042: Determine attribution, scope, and business impact of the AiTM session hijacking incident
targeting ApexCode Solutions via partner developer DevPartner, Inc, including assessment of data exfiltration
from 12 private GitHub repositories.

STAKEHOLDER FEEDBACK:
CISO compound feedback after the Stage 6 briefing:

1. Could 50 other vendors be compromised the same way? We use the same Okta SSO integration with all
   partner development shops.

2. Can we prevent session hijacking entirely with FIDO2? I want to know if it's worth the investment.

3. Can we detect if the attacker planted backdoors in our repos? We need to know if the 12 repositories
   are clean.
```

**CLI single-shot:**

```bash
adk run my_agent
```

**Programmatic batch call:**

```python
import asyncio
from my_agent.agent import run_pipeline, SAMPLE_ORIGINAL_QIR

session_id, iterations = asyncio.run(run_pipeline(
    stakeholder_feedback="CISO: Could 50 other vendors be compromised the same way?",
    original_qir=SAMPLE_ORIGINAL_QIR,
    max_iterations=3,
))
final_verdict = iterations[-1]["verdict"]["verdict"]   # "PASS" / "PARTIAL" / "FAIL"
final_qirs    = iterations[-1]["verified_feedback"]    # JSON-parseable string
```

## Project Structure

```
chapter-12/
├── README.md                                   # this file
├── requirements.txt                            # runtime dependencies
├── requirements-simulation.txt                 # notebook dependencies (pandas, ipython)
├── ground_truth.csv                            # 5 expert-curated scenarios for evaluation
├── config_search_results.csv                   # grid search aggregated summary (header-only until gs-run executes)
├── config_search_runs.csv                      # per-run rows; created by gs-run when the grid runs (not shipped)
├── Chap 12 Simulations.ipynb                   # 7-section eval notebook (see below)
├── Images/
│   ├── Stage 7 Feedback.png                    # Fig. 9 — pipeline architecture
│   ├── ADK Web UI Transformation Agent.png     # Fig. 10 — ADK web UI input panel
│   ├── ADK Web UI Transformation Output.png    # Fig. 11 — ADK web UI structured QIR output
│   ├── Judge Calibration Results.png           # Fig. 12 — judge calibration styled table
│   └── Ground Truth Eval (5 scenarios).png     # Fig. 13 — ground-truth eval styled table
└── my_agent/
    ├── agent.py                                # all three agents, deterministic checker, run_pipeline,
    │                                           #   _strip_code_fence helper
    ├── requirement_templates.py                # 9 QIR fields, 4 scope types, 3 priority levels, 6 rules,
    │                                           #   validate_qir_fields, compute_verdict_metrics
    ├── judge_eval.py                           # 10 judge calibration test cases + run_judge_on_feedback_qirs
    ├── session_service.py                      # InMemorySessionService factory
    ├── best_config.json                        # created by gs-best-config when you lock in a configuration (not
    │                                           #   shipped; agent.py falls back to gemini-2.5-flash @ temp 0.2)
    └── __init__.py
```

## Related Files

### `Chap 12 Simulations.ipynb`

Combined evaluation notebook covering seven sections (~940 LOC, 23 cells). Cells are named by `id` for direct reference from the chapter prose:

1. **Setup** (`setup-imports`) — `load_dotenv`, `sys.path` wiring, agent/judge_eval/templates imports, threshold constants.
2. **Pipeline Helper** (`pipeline-helper`) — `async def run_scenario(...)` wrapping `run_pipeline()`.
3. **Single-Scenario Demo** (`demo-run`) — canonical CISO compound feedback as a smoke test.
4. **Configuration Grid Search** (`gs-imports`, `gs-run`, `gs-load`, `gs-pivot`, `gs-best-config`) — sweeps 1 model × 3 temperatures × 6 scenarios with **Monte Carlo suppression at temp=0.0** (`runs_for_temp = MONTE_CARLO_RUNS if temp > 0 else 1`); 66 total runs at default settings. Per-run rows persisted to `config_search_runs.csv` for true checkpoint resume; aggregated `(model, temp)` summary persisted to `config_search_results.csv`. Best config written to `my_agent/best_config.json`.
5. **Ground-Truth Evaluation** (`gt-imports`, `gt-helpers`, `gt-run`, `gt-summary`, `gt-table`) — runs the full pipeline against the 5 scenarios in `ground_truth.csv` and measures **Recall** (matched / expected), **Scope Accuracy** (per-class breakdown via `per_scope_accuracy`), **Priority Accuracy**, **Field Completeness**, and **F1**. Thresholds: Recall ≥ 60%, Scope Accuracy ≥ 70%. Bipartite matcher uses scope hard-gate + 0.4×scope + 0.2×priority + 0.4×phrase-fraction scoring with threshold 0.3. `gt-table` re-renders the styled results table directly from `ground_truth.csv`, so it works on a fresh kernel without an API run; `gt-summary` aggregates the in-memory `gt_results` and needs `gt-run` first (it prints a notice otherwise).
6. **Judge Calibration** (`judge-run`, `judge-table`) — runs the Compliance_Judge against 10 known-verdict cases from `judge_eval.py`. Threshold: 80% of individual checks. The harness scores one verdict check and one violation-count check per case, plus a scope check on `already_answered_question` — 21 checks total (as-run: 20 of 21, 95%). `judge-table` renders from the in-memory rows produced by `judge-run` and prints a notice on a fresh kernel.
7. **Discussion** (`section-7-discussion`) — synthesis of the three-layer validation: judge calibration catches schema/verdict gaps; ground-truth eval catches semantic drift; grid search picks production config.

The notebook uses pandas Styler exclusively for result tables (no hand-rolled SVG or inline visualization library).

### `ground_truth.csv`

Five expert-curated scenarios spanning the feedback types the pipeline must handle, all anchored on the running scenario from earlier chapters (the AiTM compromise of ApexCode via its partner DevPartner, Inc): vendor compromise expansion (CISO question about 50 other vendors via shared Okta SSO), FIDO2 countermeasure validation, compound dwell-time + GDPR notification split, code publication impact assessment, and a three-question CISO compound. Each row stores both the scenario definition (`stakeholder_feedback`, `expected_qirs` JSON, `expected_qir_count`) and evaluation result columns (`Recall`, `Scope_Accuracy`, `F1`, `Iters`, etc.) populated by `gt-summary`.

> **Recorded results & recovery:** the result columns ship pre-filled with the authors' recorded run. `gt-summary` overwrites them with your own results by scenario-name lookup — a partial `gt-run` followed by `gt-summary` silently mixes your rows with the recorded ones. The shipped canonical copy is always recoverable with `git checkout -- ground_truth.csv`.

### `my_agent/requirement_templates.py`

The QIR template catalog plus `format_templates_for_prompt()`, which renders all field definitions, scope types, priority levels, and transformation rules as a flat string for static prompt injection. Also provides `validate_qir_fields()` for deterministic field-level validation and `compute_verdict_metrics()` for computing precision, coverage, F1, and relevance from a `FeedbackVerdict` dict (the grid search's `gs-run` cell uses it for its per-run F1). Treated as trusted infrastructure — ships in source code rather than via RAG so it cannot drift.

### `my_agent/judge_eval.py`

Ten synthetic QIR arrays with known-correct verdicts, each constructed to isolate exactly one transformation rule:

| Case | Tests | Expected verdict |
|---|---|---|
| `single_clear_question` | All-pass baseline | PASS |
| `compound_not_split` | TR-001 (Atomic Decomposition) | FAIL |
| `missing_temporal_window` | TR-005 (Temporal Window Explicitness) | FAIL |
| `missing_linked_qir` | TR-002 (Linked QIR Requirement) | FAIL |
| `two_questions_properly_split` | TR-001 no-false-positive control | PASS |
| `unjustified_priority` | TR-004 (Priority Justification) | FAIL |
| `wrong_scope_classification` | TR-003 (Scope Classification) | PARTIAL or FAIL |
| `praise_no_question` | TR-006 (Non-Actionable Filter) | FAIL |
| `five_questions_decomposed` | TR-001 large-N control | PASS |
| `already_answered_question` | TR-006 boundary / coverage | PASS (plus a scope check) |

Accuracy threshold: 80%, measured over the 21 individual checks (as-run: 20 of 21, 95%). At the case level the same run scores 9 of 10 fully correct; the sole miss is `compound_not_split` (judge returned PARTIAL where the harness expects FAIL).

## Figures in the Manuscript

| Fig | Image | Section in chapter |
|---|---|---|
| 1 | (cycle closure diagram) | §1 Feedback Loops & Narrative Closure |
| 2 | (product vs system closure) | Removed in author revision — the manuscript now runs Fig. 12.1 → 12.3; final renumbering is handled in production |
| 3 | (types of feedback) | §1 Feedback as a Formal Intelligence Input |
| 4 | (CISO email reproduction) | §1 The ApexCode Closure |
| 5 | (requirement types: strategic vs operational) | §2 Parsing Strategic & Operational Needs |
| 6 | (session hijacking outcomes by audience) | §2 |
| 7 | (CISO concern → strategic requirement) | §2 The ApexCode Application |
| 8 | (CISO concern → operational requirement) | §2 |
| **9** | **`Stage 7 Feedback.png`** | §3 Agent Roles and the Recursive Pipeline Architecture |
| **10** | **`ADK Web UI Transformation Agent.png`** | §3 (after Verification_Agent description) |
| **11** | **`ADK Web UI Transformation Output.png`** | §3 (paired with Fig. 10) |
| **12** | **`Judge Calibration Results.png`** | §4 Judge Calibration |
| **13** | **`Ground Truth Eval (5 scenarios).png`** | §4 Ground Truth QIR Accuracy |

The architecture diagram (Fig. 9) was authored before the chapter's PIR → QIR rename; the diagram retains the legacy "PIR" label, but the chapter prose clarifies that in this build the same identifier is QIR.

## Known Limitations

- **Grid search measures judge self-consistency on the swept configurations**; ground-truth correctness is measured separately in §5 against the expert-curated `ground_truth.csv`. The two harnesses are intentionally separate — passing one does not imply passing the other.
- **`MissingQIR` three-entry cap** (the judge will not propose more than three missing QIRs per refinement pass) is enforced at the prompt level, not the Pydantic schema level. Production deployments that need a hard guarantee should add `Field(max_length=3)` to `FeedbackVerdict.missing_critical`.
- **The `GS_CHECKPOINT` constant (`gt_checkpoint.json`) is currently unused.** The grid search uses `config_search_runs.csv` for checkpoint resume; the constant is retained for forward compatibility with longer-running evaluations.
- **Cell `gs-best-config` writes to `my_agent/best_config.json`** (cwd-relative). Run the notebook from the `chapter-12/` directory.

## A Note on the Recorded Results

The recorded ground-truth run passes both gates (avg Recall 80% ≥ 60%, avg Scope Accuracy 80% ≥ 70%) — but only because averaging absorbs one scenario, *Code Publication Impact*, which scores **0.0 on every metric while the pipeline's own verdict on it was PASS**. That zero-recall row is the lenient-judge failure mode the notebook's Discussion warns about, sitting in the shipped data — treat it as the chapter's lesson made concrete (and as the natural improvement target), not as an error in your setup. The judge calibration's one recorded miss (`compound_not_split`: PARTIAL where FAIL is required) is documented in the notebook's judge section.
