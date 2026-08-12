# Chapter 6 — Cybersecurity Intelligence Requirement Evaluator

A two-agent system built with the **Google Agent Development Kit (ADK)** that scores cybersecurity intelligence requirements across three quality dimensions and recommends improvements.

## What It Does

Given a cybersecurity intelligence requirement (e.g., *"What cyber threats should we worry about this year?"*), the agent evaluates it across three dimensions:

| Dimension | Description |
|---|---|
| **Specificity** | Is the requirement narrowly scoped with explicit actors, assets, and timeframes? |
| **Decision-Centricity** | Does it directly support one specific decision with a clear decision point? |
| **Feasibility** | Can it realistically be answered using typical cybersecurity telemetry and intelligence sources? |

Each dimension is rated on a **1–4 scale** (1 = Poor, 2 = Good, 3 = Better, 4 = Best), with explanations and recommended improvement actions for any score below 4.

## Agent Architecture

The system uses a two-agent chain:

```
User Input (intelligence requirement)
    ↓
root_agent  (orchestrator)
    ↓ tool call
evaluator_agent  (scorer)
    ↓ structured JSON (OutputJSON schema)
root_agent
    ↓
Markdown table output
```

- **`evaluator_agent`** — Scores the requirement and returns structured JSON matching the `OutputJSON` Pydantic schema (`chap6.json`). Runs at `temperature=0.0` for deterministic output.
- **`root_agent`** — Receives the user's input, calls `evaluator_agent` as a tool, and renders the results as a formatted markdown table.

Both agents use `gemini-3.1-pro-preview` — the same model configured in the grid-search notebook, so the deployed agent matches the benchmarked setup.

## Output Format

The agent returns a markdown table with four columns:

| Variable | Rating (1–4) | Explanation | Recommended Actions |
|---|---|---|---|
| Specificity | ... | ... | ... |
| Decision-Centricity | ... | ... | ... |
| Feasibility | ... | ... | ... |

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt

# To also run the research notebook (Chap 6 Simulations.ipynb):
pip install -r requirements-simulation.txt
```

Launch the notebook with:

```bash
jupyter lab "Chap 6 Simulations.ipynb"
```

### 3. Configure your API key

Create a `.env` file in `my_agent/` (it is not shipped) and add your Google API key:

```
GOOGLE_API_KEY='your-api-key-here'
GOOGLE_GENAI_USE_VERTEXAI=0
```

Create a key (free tier available) at <https://ai.google.dev/gemini-api/docs/api-key>.

**Cost expectations:** chatting with the agent costs 2 model calls per message. The notebook's full grid search makes ~1,140 calls and takes **~75–85 minutes** — the runtime is dominated by built-in rate-limit cooldowns, not compute — and its 19-way concurrency assumes paid-tier rate limits.

### 4. Run the agent

```bash
# From the chapter-06 folder (the parent of my_agent)
adk web
```

The ADK web server discovers the agent package from there; open the localhost URL it prints to chat with the agent.

## Project Structure

```
chapter-06/
├── README.md
├── requirements.txt                  # ADK agent dependencies
├── requirements-simulation.txt       # Notebook dependencies
├── Chap 6 Simulations.ipynb          # Grid-search research notebook
├── cyber_intel_requirements_with_explanations.csv   # Golden dataset (20 rows)
├── df_raw_runs.csv                   # Raw MAE output from the 30 recorded runs
├── Photos/                           # Screenshots used in the chapter (incl. simulation_results.png)
└── my_agent/
    ├── agent.py        # Two-agent implementation (evaluator + root)
    ├── chap6.json      # Output schema reference
    ├── .env            # Google API key configuration
    └── __init__.py
```

## Related Files

### `Chap 6 Simulations.ipynb`
The research notebook that preceded and informed this agent's design. It runs a full grid-search experiment comparing two prompt strategies against an expert-rated golden dataset.

**Experiment design:**
- **Golden dataset** (`cyber_intel_requirements_with_explanations.csv`) — 20 cybersecurity intelligence requirements hand-rated by experts across three dimensions (the first row is the worked example embedded in the prompts and is dropped at load, leaving 19 for evaluation), ranging from clearly poor (*"How risky is our cloud environment?"*) to clearly best (*"Is our WAF blocking exploitation attempts associated with Exploit Kit E in the last 24 hours?"*)
- **Two prompt strategies tested:**
  - `PROMPT_STRATEGY_A_COMBINED` — one unified prompt that evaluates all three dimensions in a single API call
  - `Chained_Prompts` — three separate focused prompts run sequentially, one per dimension
- **Grid search:** 2 strategies × 3 temperatures (0.0, 0.5, 1.0) × 5 runs each = 30 runs across 6 configurations
- **Parallelism:** All 19 requirements evaluated concurrently per run using `ThreadPoolExecutor` (19 workers)
- **Scoring Evaluation:** Mean Absolute Error (MAE) against expert ratings — lower is better

**Key finding:** `PROMPT_STRATEGY_A_COMBINED` beat the chained strategy at every temperature. `temperature=1.0` posted the lowest average MAE (0.358), but with high run-to-run variance (std 0.055, individual runs from 0.296 to 0.439); `temperature=0.0` came in at MAE 0.386 with zero variance across all five runs. Because the deployed agent needs deterministic, reproducible scoring, `temperature=0.0` was selected — which is why both agents in `agent.py` run at `temperature=0.0`. These numbers were recorded on `gemini-3-pro-preview`; the notebook and agents have since moved to `gemini-3.1-pro-preview`, so re-run the grid search to reproduce them under the current model.

### `cyber_intel_requirements_with_explanations.csv`
The golden dataset used to benchmark model performance. Contains 20 requirements with expert ratings (1–4) and written explanations for each of the three dimensions, plus an overall Quality Intelligence Requirement (QIR) grade. The first row is the worked example embedded in the prompts; the notebook drops it at load and evaluates the remaining 19.

### `df_raw_runs.csv`
Raw MAE output from all 30 experiment runs in the notebook. Used to generate `simulation_results.png`.

### `Photos/simulation_results.png`
Box plot with scatter overlay showing MAE distribution across 5 runs per configuration. Lower MAE (better performance) appears lower on the y-axis, matching the figure printed in the chapter. Running the notebook's plotting cell regenerates it as `simulation_results.png` in the working directory.
