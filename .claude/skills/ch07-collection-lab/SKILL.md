---
name: ch07-collection-lab
description: "Guides the Chapter 7 (Collection stage) lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the three-agent ADK collection-plan pipeline and \"Chap 7 Simulations.ipynb\" (grid search, ground-truth eval, judge calibration). Use when running chapter-07/ code, deciding whether to pay for the 450-run grid vs using the canonical CSVs keylessly, or interpreting FINAL VERDICT and Essential Coverage results."
---

# Chapter 7 — Collection Stage (3-agent pipeline + 3-part eval notebook)

Self-refining LoopAgent pipeline (Collection → Judge → Verification) with a
56-source closed-world catalog, plus `Chap 7 Simulations.ipynb`: grid search,
ground-truth eval, judge calibration.

## Lab checklist

```
- [ ] venv + pip install -r requirements.txt (agent) and -r requirements-simulation.txt (notebook)
- [ ] Create my_agent/.env; run: cd my_agent && python agent.py  (expect FINAL VERDICT: PASS)
- [ ] Or adk web from chapter-07/
- [ ] Notebook: keyless review path or paid evals (labeled cells)
```

## Keyless path

The grid search is **optional** — the canonical 450-run results ship in
`config_search_results_original.csv`, and the shipped `config_search_results.csv`
is a pre-filled copy of them (its README calls it the "reproduction target";
having it pre-filled is expected, the reader hasn't accidentally run anything).
Skipping the paid grid cell makes two later cells fail on an undefined
`df_grid`: load the canonical CSV into `df_grid` instead
(`df_grid = pd.read_csv("config_search_results_original.csv")`). One caveat:
the F1-distribution boxplot needs per-run data the shipped aggregated CSV
doesn't contain — that one figure genuinely requires the paid grid.

## Paid evals (cells are labeled)

Grid: 450 runs, ~1–2 h. Ground truth: 3 scenarios, ≤ 27 calls, Essential
Coverage ≥ 80% threshold. Judge calibration: 10 calls, 8 scorable cases, ≥ 7/8
to pass (recorded run: 8/8).

## Known issues frozen in print (guide around, do not edit the repo)

1. **Cell 2 silently swallows a missing key** (Colab-fallback try/except), so a
   keyless reader discovers the problem only as a deep stack trace at the first
   paid cell. Confirm `.env` exists before running any labeled cell.
2. **`gt_checkpoint.json` is notebook-managed**: present only mid-run. If a
   ground-truth run dies partway, the checkpoint makes the next run resume
   (completed scenarios are skipped). Delete it to force a full fresh eval.

## Doneness

Pipeline: printed `FINAL VERDICT: PASS` with a three-section collection plan +
Priority Signal. Notebook: grid winner `gemini-2.5-flash @ temp 0.0`; Essential
Coverage ≥ 80%; judge 8/8. Success thresholds are stated in both README and
notebook — this chapter's doneness signals are reliable.

## Directions for improvement (from the chapter)

The chapter's Failure Mode subsection diagnoses the core weakness itself: a
run can PASS the judge while missing 2 of 4 essential sources — the judge is
lenient, and only the ground-truth eval catches it. Forward moves:
- **Tighten the Source_Validation_Judge** (instructions in `my_agent/agent.py`)
  and re-measure Essential Coverage on the three GT scenarios — the ≥ 80%
  threshold is the scoreboard; improvement = higher coverage at PASS.
- **Extend `ground_truth.csv`** with the reader's own scenarios — keep exactly
  4 essential sources per scenario (the README's stated comparability
  constraint) so Coverage stays comparable without normalization.
- **Extend the closed-world catalog** in `my_agent/sources.py` with
  org-specific sources — it is statically injected, so additions stay
  auditable; the judge then validates against the extended universe.
- Re-run the 450-run grid on current models to see whether the winning config
  shifts (optional, paid; canonical results remain in the `_original` CSV).

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo.
API keys are free-tier at https://ai.google.dev/gemini-api/docs/api-key; check
the chapter README's "Cost expectations" note before any paid cell.
