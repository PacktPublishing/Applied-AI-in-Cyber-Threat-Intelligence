---
name: ch12-feedback-lab
description: "Guides the Chapter 12 (Feedback stage) lab of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): the follow-on QIR generation pipeline and \"Chap 12 Simulations.ipynb\" (cell ids gs-run, gt-run, judge-run). Use when running chapter-12/ code or evals, protecting the shipped ground_truth.csv canon from overwrite, or interpreting the zero-recall Code Publication Impact scenario hiding inside the passing averages."
---

# Chapter 12 — Feedback Stage (QIR-generation pipeline + eval notebook)

Three-agent loop turning stakeholder feedback into template-validated follow-on
QIRs, plus `Chap 12 Simulations.ipynb`. This is the healthiest chapter in the
repo: the README's per-cell map matches real notebook cell ids (`gs-run`,
`gt-run`, `judge-run`...), generated artifacts are labeled "not shipped", and
both judge-metric views are reconciled in prose.

## Lab checklist

```
- [ ] venv + both requirements files; .env in chapter-12/
- [ ] adk web with the README's paired QIR+feedback prompt (Figs 10-11 = target)
- [ ] Paid (no cell labels here — see README cost note): demo-run, judge-run (10 calls), gt-run (5 scenarios), gs-run (66 runs, optional)
```

Missing key fails fast (~28 s) with the key URL. A spurious
`Task exception was never retrieved ... _async_httpx_client` traceback may
print on top of the real error — ignore it, read the RuntimeError beneath.

## Canon protection

`ground_truth.csv` ships pre-filled with the recorded run. `gt-summary`
overwrites it by scenario-name lookup, and a **partial** `gt-run` followed by
`gt-summary` silently mixes reader and recorded rows. Copy aside first or
restore with `git checkout -- ground_truth.csv`. There is no resume logic —
`gt-run` always runs fresh.

## Reading the recorded results

Recorded GT passes both gates (avg Recall 80% ≥ 60%, avg Scope 80% ≥ 70%) —
but only because averaging absorbs one scenario ("Code Publication Impact")
that scores **0.0 on every metric while the pipeline's own verdict on it was
PASS**. That zero-row is the judge-leniency failure mode the Discussion warns
about, sitting in the shipped data; point readers at it rather than letting
them treat it as their own error. Judge calibration: 20/21 checks (95%) and
9/10 cases (90%) — both pass; the one miss (`compound_not_split`) is named in
the README.

## Minor notes

- `session_service.py`'s `persistent: bool = True` parameter is decorative —
  it always returns an in-memory service; the chapter creates no session state
  files needing cleanup.
- A vestigial `GS_CHECKPOINT` constant in `gs-imports` is unused (disclosed in
  Known Limitations as forward-compat).

## Directions for improvement (from the chapter)

The shipped data itself names the two targets:
- **The zero-recall scenario** ("Code Publication Impact": 0.0 on every metric
  while the pipeline's own verdict was PASS) is the Discussion's lenient-judge
  warning made concrete. Exercise: improve the Transformation agent's
  prompts/templates (`my_agent/requirement_templates.py`) until that scenario
  produces scoring QIRs, and consider a rule check that refuses a PASS verdict
  on an empty QIR set — then re-run `gt-run`/`gt-summary` (canon copied aside)
  and check the per-row Recall, not just the passing averages.
- **The judge's one named miss** (`compound_not_split`: PARTIAL where FAIL —
  compound stakeholder questions must be split into separate QIRs): tighten
  the judge instructions until that case scores FAIL, holding the other nine;
  targets are the chapter's own gates (≥ 80% both views; recorded 95%/90%).
- Running `gs-run` (66 paid runs) legitimately generates the "not shipped"
  `best_config.json` — the reader-completed artifact this chapter labels
  honestly.

## Repo vs printed book

The repo contains post-print fixes; where a printed listing differs slightly
from repo code, the repo version is the corrected one. The "frozen in print"
issues above are the deliberate exceptions kept to match the book — guide the
reader around them at runtime; never edit them in the repo.
API keys are free-tier at https://ai.google.dev/gemini-api/docs/api-key; check
the chapter README's "Cost expectations" note before any paid cell.
