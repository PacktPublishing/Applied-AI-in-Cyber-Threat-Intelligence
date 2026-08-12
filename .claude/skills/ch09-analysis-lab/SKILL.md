---
name: ch09-analysis-lab
description: "Guides the Chapter 9 (Analysis stage) lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the SAT-scaffolding pipeline and \"Chap 9 Simulations.ipynb\". Use when running chapter-09/ code or evals — ALWAYS read before the ground-truth eval: the shipped ground_truth.csv resume trap silently replays recorded results with zero API calls, and the write-back can corrupt the CSV. Also covers grid search, 14-case judge calibration, and adk web setup."
---

# Chapter 9 — Analysis Stage (SAT pipeline + eval notebook)

Three-agent LoopAgent pipeline scaffolding Structured Analytic Techniques
(14-SAT catalog), plus `Chap 9 Simulations.ipynb` with grid search (optional),
5-scenario ground-truth eval, and 14-case judge calibration.

## The most important thing to know — the resume trap

`ground_truth.csv` ships with its result columns **pre-filled** with the
authors' recorded run, and the GT eval cell treats any row with a non-empty F1
as "already complete". Consequence: running the eval as shipped **replays the
recorded results with zero API calls** ("Resuming — 5 scenario(s) already
complete") — a reader can believe they reproduced numbers they never ran.

- To run a **real** eval: first blank the result columns (F1, Verdict, etc.) in
  a copy-protected way — e.g. `cp ground_truth.csv ground_truth.canon.csv`
  first, then clear the result cells and run.
- To just **study** the recorded results keylessly: run the loader/table cells
  as-is; that's a legitimate path.

## Write-back corruption — fixed in the repo (history note)

The repo's cell 17 now writes back the resumed entries' true counts
(`r.get("n_pipeline", ...)` / `r.get("n_matched", ...)`), so the replayed path
writes back exactly what it read — the historical bug that zeroed
`Pipeline_Findings`/`Overlap` on all rows is fixed here. Two cautions remain:
- If a reader's copy of the notebook predates this fix, the old cell 17
  corrupts on the resumed path — symptom: those two columns all 0 with
  F1/Verdict intact. Recover with `git checkout -- ground_truth.csv` and
  update the notebook to the current repo version.
- The general canon rule still applies: the write-back overwrites
  `ground_truth.csv` with whatever `gt_results` holds — copy the CSV aside
  before real (fresh) eval runs.

## Other canon files that get overwritten

`my_agent/judge_eval_results.json` ships pre-filled with the recorded 12/14
run; executing the judge calibration (cell 20 or `judge_eval.py`) overwrites
it. Same recovery: `git checkout -- my_agent/judge_eval_results.json`.

## Lab checklist

```
- [ ] venv + both requirements files (ch9's include jupyter + jinja2); .env in chapter-09/
- [ ] adk web from chapter-09/ (agent constructs keylessly; key needed at first chat)
- [ ] Notebook: keyless study path or real evals per above
```

## Cost + doneness

Grid: 450 runs (optional — "left as an exercise"; `best_config.json` ships
hand-authored). GT: 5 scenarios, avg F1 ≥ 70% (recorded: 77.9%, 3/5 pass
individually — disclosed). Judge: 14 calls, ≥ 80% (recorded: 12/14 = 85.7%,
the two misses are named in the README with rationale). This chapter's
recorded results PASS their thresholds and its canonicity labeling is the most
honest in the repo — the GT screenshot showing per-row "PASS" verdicts beside
sub-threshold F1s is the pipeline judge's verdict, not the F1 check (the
Discussion cell explains).

## Directions for improvement (from the chapter)

- **The grid search is explicitly "left as an exercise"** (README, on
  `best_config.json`): running it (450 paid runs) fills the header-only
  `config_search_results.csv` and writes a machine-generated `best_config.json`
  — the intended reader-completed artifact.
- **Recalibrate the judge**: the README names the two recorded misses
  (`eval_01`, `eval_11` — judge over-strict) with rationale. Exercise: adjust
  the judge instructions in `my_agent/judge_eval.py`'s prompt so those pass
  without regressing the other twelve; target > 12/14. The shipped
  `judge_eval_results.json` is the before-picture (git-recoverable).
- **Close the two sub-threshold GT scenarios** (F1 0.667 / 0.571 in the
  recorded run): improve SAT-selection instructions, blank the result columns
  properly (see the resume-trap section above), and re-run the 5-scenario eval
  against the ≥ 70% avg F1 bar.

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo.
API keys are free-tier at https://ai.google.dev/gemini-api/docs/api-key; check
the chapter README's "Cost expectations" note before any paid cell.
