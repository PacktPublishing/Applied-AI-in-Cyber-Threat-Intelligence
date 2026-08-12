---
name: ch10-production-lab
description: "Guides the Chapter 10 (Production stage) lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the argument-map pipeline and \"Chap 10 Simulations.ipynb\" with its keyless NetworkX/Plotly visualization section. Use when running chapter-10/ code, looking for the intentionally stripped grid-search cells, interpreting the recorded Level-Accuracy FAIL, protecting the shipped Figure 10.10 images from overwrite, or fixing kaleido PNG export failures."
---

# Chapter 10 — Production Stage (argument-map pipeline + eval notebook)

Three-agent LoopAgent pipeline producing logic-validated intelligence products
with formal argument maps (5 logic rules), plus `Chap 10 Simulations.ipynb` and
a keyless NetworkX/Plotly visualization section.

## The most important things to know

1. **The grid search is runnable again (restored post-print)** — printed
   copies show cells 11/12 as `# skipped` placeholders, but the repo ships the
   invocation (`grid_configs = await run_grid(...)`, 450 paid runs,
   checkpointed to `config_search_checkpoint.jsonl` so interruptions resume)
   and the results cell (ranked table + `best_config.json` + HTML report).
   Like chapters 9/11/12 it ships un-run: `best_config.json` doesn't exist
   until the reader runs the sweep (agent falls back to gemini-2.5-flash
   @ 0.2, handled gracefully), and the Discussion's recorded grid numbers
   (F1=100% ceiling) remain the authors' run. Cell 8's single-scenario demo is
   also restored: it loads the canonical AiTM verified analysis from
   `ground_truth.csv` (JSON-encoded column) and runs the pipeline once
   (labeled; ~9 model calls).
2. **The recorded results fail one threshold, on purpose**: GT passes Recall
   (66.7% vs 60%) but misses Level Accuracy (67% vs 70%) — the notebook's dated
   provenance note and the README's "A Note on the Recorded Results" both
   disclose it. Judge calibration: per-check 16/20 = 80% (at the wire) vs
   per-case 7/10 — the two-views explanation is in the README.

## Lab checklist

```
- [ ] venv + both requirements files; .env in chapter-10/
- [ ] adk web (agent tree loads keylessly — verifiable before spending)
- [ ] Keyless: section 9 visualization runs end-to-end (argument-map figures)
- [ ] Paid: GT eval (3 scenarios, <=27 calls), judge (10 calls); optional grid (450 runs — that cell is labeled)
```

## Known issues frozen in print (guide around, do not edit the repo)

1. **Cells 28/29 overwrite shipped book figures** in `Images/` (the AiTM
   argument-map PNG/HTML — Figure 10.10). Running only cell 28 silently
   regresses the shipped figure to an older render. Either run both 28 and 29,
   or restore afterward: `git checkout -- "chapter-10/Images"`.
2. **`kaleido`** is now in `requirements-simulation.txt` (added post-print). If
   the interactive-map PNG export still fails with a kaleido message, the
   reader is on a stale clone — `pip install kaleido` fixes it. HTML and
   static PNG never needed it.
3. **Paid-run timing hazard**: the GT eval's styled table renders *after* the
   paid run but *before* results are written to CSV. If a display error occurs
   there, the results still exist in kernel memory — re-run only the
   write-back/display, do not re-pay for the eval. (The historical cause —
   missing jinja2 — is fixed in the repo requirements.)
4. **`ground_truth.csv` mixes units in one row** — Recall/F1 stored as
   fractions, Level_Accuracy as a percent. The code normalizes it; a reader
   eyeballing the CSV may think a value is 100× off.
5. The stored cell-2 output includes the author's local path and an ADK
   experimental-feature warning — stale output noise, not the reader's
   environment leaking.

## Directions for improvement (from the chapter)

The recorded run defines two open gaps, and the notebook's ceiling note gives
the stop condition (all-pass → "integration testing", not more tuning):
- **Close the Level Accuracy gap** (recorded 67% vs ≥ 70%): the miss is in
  strength/level calibration — tighten the Argument_Mapping_Agent's
  LR-003-related instructions (strength labels must match evidence counts) and
  re-run the 3-scenario GT eval to score it.
- **Lift judge calibration from 7/10 to ≥ 8/10 cases**: the per-case scorecard
  in the notebook names which cases miss; adjust the Logic_Judge instructions
  and re-run the 10 calibration calls.
- The restored grid (450 paid runs, checkpointed) can now generate a
  `best_config.json` tuned to the reader's environment; the GT and judge
  evals remain the primary scoreboards — protect `ground_truth.csv` and
  `Images/` before re-runs (both git-recoverable).

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo.
API keys are free-tier at https://ai.google.dev/gemini-api/docs/api-key; check
the chapter README's "Cost expectations" note before any paid cell.
