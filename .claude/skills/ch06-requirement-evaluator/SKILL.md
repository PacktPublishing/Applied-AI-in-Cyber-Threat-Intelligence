---
name: ch06-requirement-evaluator
description: "Guides the Chapter 6 lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the two-agent ADK Intelligence Requirement Evaluator (my_agent) and the grid-search notebook \"Chap 6 Simulations.ipynb\". Use when setting up adk web for chapter-06/, running or costing the prompt-strategy grid search (~80 minutes), hitting the google.colab import error, GEMINI_API_KEY vs GOOGLE_API_KEY confusion, or reproducing simulation_results.png without an API key."
---

# Chapter 6 — Intelligence Requirement Evaluator (ADK agent + notebook)

Two-agent ADK system (`my_agent/`) scoring intelligence requirements 1–4 on
three dimensions, plus a grid-search notebook (`Chap 6 Simulations.ipynb`)
comparing two prompt strategies × three temperatures against a 20-row golden
dataset.

## Lab checklist

```
- [ ] venv + pip install -r requirements.txt (+ requirements-simulation.txt for the notebook)
- [ ] Create my_agent/.env (GOOGLE_API_KEY + GOOGLE_GENAI_USE_VERTEXAI=0)
- [ ] adk web from chapter-06/ -> submit a requirement, get the 4-column table
- [ ] Notebook: EITHER the keyless replay path below OR the full paid grid
```

## Keyless path (recommended first)

The shipped `df_raw_runs.csv` contains the full recorded grid results and
reproduces the README's key-finding numbers to 4 decimals, and the notebook
now ships a loader cell (directly after the paid grid cell) that reads it —
no API key or improvisation needed. Sequence: cell 0 (it errors at the Colab
import, but pandas/matplotlib/seaborn load before that line — or delete the
line first), the visualization-function cell, the loader cell, then the
stats/plot cell — `simulation_results.png` regenerates exactly. The loader is
also safe after a real grid run: it just re-reads the CSV that run wrote.

## Cost reality (paid path)

The grid is ~1,140 model calls and **~75–85 minutes**, dominated by hard-coded
60 s cooldowns. The stored output showing "Total Time: 3.72 minutes" is from a
reduced test run — off by ~20×. The 19-way concurrency assumes paid-tier rate
limits.

## Known issues frozen in print (guide around, do not edit the repo)

1. **Cell 0 contains `from google.colab import userdata`** (a few lines into
   the imports) → `ModuleNotFoundError` on any local install. The import is
   vestigial (its only use is an unreachable fallback). Reader should delete
   that line in their running kernel, or run in Colab.
2. **Key-name mismatch**: the notebook's getpass prompt asks for
   `GEMINI_API_KEY` while `.env` and all docs use `GOOGLE_API_KEY`. Same key
   value — paste the same Google AI Studio key at both.
3. **Bad/missing key soft-fails silently**: `_call_gemini_api` catches all
   exceptions and returns `'{}'`, so a bad key still burns the full ~80-minute
   run and ends with "No data to plot". Cell 5 ends with a live 1-call test —
   confirm it returns real JSON (not an error print) before launching the grid.
4. **Cooldown off-by-one**: the loop sleeps 60 s after the final run of each
   configuration too (~6 wasted minutes across the grid). Harmless; expected —
   the adjacent code comment now says so explicitly.
5. README's recorded numbers were produced on `gemini-3-pro-preview`; the code
   now uses `gemini-3.1-pro-preview`. A re-run should show the same qualitative
   pattern (combined beats chained at every temperature), not identical MAEs.

## Other unfixed quirks (repo-fixable, not yet fixed)

- Skipping cell 4 makes cell 5 fail with a `NameError` at *definition* time —
  the getpass value is bound as a default argument. Run cell 4 before cell 5
  even when not planning a full paid run.
- The notebook has zero markdown cells, and its section-number comments skip
  "4." (1 CONFIGURATION, 2 WORKER, 3 EXPERIMENT RUNNER, 5 VISUALIZATION) —
  numbering artifact, not a missing cell.

## Doneness

Agent: 4-column markdown table (Variable | Rating | Explanation | Recommended
actions) matching the `Photos/` screenshots. Notebook: reproduce the finding
that the combined prompt wins and T=0.0 is chosen for determinism (MAE 0.386,
zero variance) despite T=1.0's lower mean (0.358, high variance).

## Directions for improvement (from the chapter)

The README states the recorded numbers predate a model move and invites the
reader to **re-run the grid search under the current model**
(`gemini-3.1-pro-preview`) to reproduce the finding. How to move on it:
- Re-run the grid (paid, ~80 min) and check the *qualitative* pattern —
  combined beats chained at every temperature — rather than exact MAEs.
  Cell 12 overwrites the shipped `df_raw_runs.csv`; copy it aside first or
  recover with `git checkout -- df_raw_runs.csv`.
- Add a third prompt strategy as a new arm in the grid (the strategy prompts
  are plain strings in the notebook) and score it with the same MAE harness.
- Extend the golden dataset with the reader's own requirements plus expert
  ratings — keep row 1 as the worked example (the loader drops it) and the
  three-dimension 1–4 scheme so the MAE comparison stays valid.

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo.
API keys are free-tier at https://ai.google.dev/gemini-api/docs/api-key; check
the chapter README's "Cost expectations" note before any paid cell.
