# Chapter 7 — The Collection Stage

A three-agent self-refining pipeline built with the **Google Agent Development Kit (ADK)** that turns a Quality Intelligence Requirement (QIR) into a validated, catalog-constrained collection plan.

## What It Does

Given a refined QIR (e.g., *"Detect indicators of third-party partner account compromise via session-cookie theft on GitHub, Jira, and Okta"*), the pipeline produces a structured collection plan covering three sections:

1. **Internal Log Sources** — exact event types, fields, and anomaly patterns
2. **External / OSINT Sources** — APIs, tools, and what a hit means operationally
3. **Threat Actor Tactics** — the TTPs the plan is designed to surface, with MITRE ATT&CK IDs

Closed with a **Priority Signal** — the highest-fidelity indicator of an active compromise.

## Agent Architecture

```
User QIR
   ↓
LoopAgent  (max 3 iterations; exits early when a sub-agent escalates)
   └── SequentialAgent
         ├── Collection_Recommendation_Agent  →  collection_plan
         ├── Source_Validation_Judge          →  validation_verdict (JSON)
         └── Verification_Agent               →  verified_plan
               └─ after_agent_callback _escalate_on_pass: sets actions.escalate on PASS
   ↓
Final verified plan
```

Three agents, all in `my_agent/agent.py`:

| Agent | Model | Role |
|---|---|---|
| `Collection_Recommendation_Agent` | gemini-2.5-flash | Generates (or refines) the collection plan |
| `Source_Validation_Judge` | gemini-3.1-pro-preview | Validates every source against the catalog; emits structured JSON |
| `Verification_Agent` | gemini-2.5-flash | Mechanically applies the judge's corrections; its `after_agent_callback` (`_escalate_on_pass`) exits the loop on a PASS verdict, deterministically and with no model call |

Loop exit is handled by that callback rather than a separate agent: ADK's `LoopAgent` stops as soon as any sub-agent sets `actions.escalate = True`, so the last agent in the sequence (Verification) signals the exit directly.

State flows between agents through `output_key` writes and `{placeholder}` reads in each instruction.

## The Closed-World Catalog

`my_agent/sources.py` defines `KNOWN_SOURCES` — 56 approved sources (36 internal, 20 external) across **26 categories total**: 16 internal (version control, project management, identity providers, MDM/UEM, RMM, EDR/XDR, SIEM, NGFW, DNS/secure web gateway, CASB, cloud audit, PAM/secrets management, collaboration and productivity, email security, ITSM, SaaS/CRM) and 10 external (breach and credential intelligence, domain and infrastructure reconnaissance, code and secret exposure, URL and phishing intelligence, IP reputation, IOC sharing, malware and file intelligence, commercial threat intelligence, network threat intelligence, vulnerability intelligence). Anything outside this list is, by definition, a hallucination.

The catalog is injected statically into the Collection and Judge instructions at import time via `format_catalog_for_prompt()`. This is intentional:

- **Auditability** — the exact text the model received is in source code.
- **Constraint enforcement** — the agent cannot choose to ignore a source category.
- **Reliability** — no embedding drift, no retrieval failures.

## Output Validation

`JudgeVerdict` (Pydantic) defines the verdict schema with three nested models:

- `ConfirmedSource` — source name, rationale, relevance ∈ {ESSENTIAL, USEFUL, TANGENTIAL}
- `UnverifiedSource` — source name, reason, suggested_alternative
- `MissingCriticalSource` — source name, importance

The judge is forced to return JSON via `response_mime_type="application/json"`, and the verdict is parsed before the verification agent reads it.

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

### 3. Configure your API key

Create `my_agent/.env` with the following two lines:

```
GOOGLE_API_KEY='your-actual-api-key-here'
GOOGLE_GENAI_USE_VERTEXAI=0
```

Create a key (free tier available) at <https://ai.google.dev/gemini-api/docs/api-key>.

**Cost expectations:** a single pipeline run is ≤ 9 model calls (3 agents × up to 3 iterations). The notebook's grid search is **450 runs (~1–2 hours)**; the ground-truth eval is 3 scenarios (≤ 27 calls) and judge calibration is 10 calls.

### 4. Run the agent

```bash
cd my_agent
python agent.py
```

Or run interactively from the `chapter-07/` root:

```bash
adk web
```

## Project Structure

```
chapter-07/
├── README.md
├── requirements.txt
├── requirements-simulation.txt
├── ground_truth.csv                 # 3 expert-rated QIRs for the notebook
├── Chap 7 Simulations.ipynb         # grid search + ground-truth eval + judge calibration
├── Additional QIRs.xlsx             # 10 QIRs for the notebook grid search
├── config_search_results.csv        # ships pre-filled with a copy of the canonical results (reproduction target; a grid re-run overwrites it)
├── config_search_results_original.csv  # canonical 450-run results the chapter cites
├── gt_checkpoint.json               # ground-truth eval checkpoint (notebook-managed; only present mid-run)
├── Images/                          # screenshots
└── my_agent/
    ├── agent.py                     # all three agents + escalate-on-PASS callback in one file
    ├── sources.py                   # 56-source catalog
    ├── judge_eval.py                # judge calibration test suite (10 synthetic cases)
    ├── .env                         # API key (you create this in Setup step 3)
    └── __init__.py
```

## Related Files

### `Chap 7 Simulations.ipynb`

Combined experiment notebook covering three evaluations (install its dependencies first with `pip install -r requirements-simulation.txt`, then launch with `jupyter lab "Chap 7 Simulations.ipynb"`):

1. **Grid search** — three models (`gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-3.1-pro-preview`) × three temperatures (0.0, 0.5, 1.0) × ten QIRs from `Additional QIRs.xlsx` × five Monte Carlo simulations = **450 runs**, executed as concurrent direct model calls. Ranks the nine configurations by F1 (judge-compliance metric); tiebroken on iteration count and latency.
2. **Ground-truth eval** — runs the pipeline against the three curated QIRs in `ground_truth.csv` and measures **Essential Coverage** (the fraction of analyst-designated essential sources present in the verified plan) by substring-matching catalog names against the plan text.
3. **Judge calibration** — imports the ten synthetic test cases from `my_agent/judge_eval.py` and scores the eight scorable cases against the 80% accuracy threshold (at least 7 of 8 must match; the recorded run scored 8/8).

This decoupling matters: the grid search measures how well the agent satisfies the judge; the ground-truth eval measures whether the plan matches what a human analyst would write. A lenient judge produces F1=100% on mediocre output — only the ground-truth comparison catches that failure mode. The judge calibration closes the loop by testing the judge itself against synthetic plans of known correctness. (See the *Failure Mode* subsection in the chapter for the worked diagnosis of an AiTM run that PASSed the judge while missing two of four essential sources.)

### `ground_truth.csv`

Three expert-curated scenarios — AiTM Session Hijacking, Ransomware via Stolen VPN Credentials, and BEC with OAuth Consent Abuse — each with QIR, threat context, ESSENTIAL and USEFUL source picks, and a written priority signal. Each scenario has exactly 4 essential sources, held constant so Coverage is comparable across scenarios without normalization. Drives the notebook's ground-truth comparison.

### `my_agent/sources.py`

The 56-source catalog plus `format_catalog_for_prompt()`, which renders it as a flat string for prompt injection. Treated as trusted infrastructure — it ships in source code rather than via RAG so it cannot drift.

### `my_agent/judge_eval.py`

Ten synthetic collection plans that calibrate the Source Validation Judge across four failure modes: hallucination detection, near-miss name handling, product disambiguation, and relevance calibration. Eight cases are scorable against an 80% accuracy threshold (at least 7 of 8 must match; the recorded run scored 8/8); the two ambiguous cases are observed but unscored. Run standalone with `python my_agent/judge_eval.py` from the `chapter-07/` root, or via Section 6 of the notebook.
