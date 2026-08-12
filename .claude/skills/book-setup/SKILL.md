---
name: book-setup
description: "Orients readers in the companion repository of the book \"Applied AI in Cyber Threat Intelligence\" (Packt): chapter folder layout, the per-chapter venv and requirements pattern, GOOGLE_API_KEY .env setup and costs, which chapters need no key, recovering shipped canonical results with git checkout, and how repo code relates to the printed book. Use when getting started with the repo, choosing a chapter to work on, or for setup questions not specific to a single chapter lab."
---

# Book Companion — Repo Orientation

Each `chapter-NN/` folder is a self-contained lab with its own README,
requirements file(s), and code. Every chapter with a lab has a dedicated
skill — **read that chapter's skill before doing chapter-specific work**; this
skill covers only what applies repo-wide.

| Chapter | Lab shape | API key? | Dedicated skill |
|---|---|---|---|
| 4 | Python-foundations notebook | No | `ch04-python-foundations` |
| 5 | Concept figures only — nothing to run | — | — |
| 6 | ADK agent + grid-search notebook | Yes | `ch06-requirement-evaluator` |
| 7 | Collection pipeline + eval notebook | Yes | `ch07-collection-lab` |
| 8 | Processing pipeline + eval notebook | Yes | `ch08-processing-lab` |
| 9 | Analysis (SAT) pipeline + eval notebook | Yes | `ch09-analysis-lab` |
| 10 | Production pipeline + eval notebook | Yes | `ch10-production-lab` |
| 11 | Dissemination pipeline + eval notebook | Yes | `ch11-dissemination-lab` |
| 12 | Feedback pipeline + eval notebook | Yes | `ch12-feedback-lab` |
| 13 | Classical-ML notebook + pinned datasets | No | `ch13-cti-ml-lab` |
| 14–16 | Standalone tools shipped as zips — unzip, follow inner README | varies | — |

## Universal facts

- **Environment**: fresh venv per chapter inside its folder;
  `pip install -r requirements.txt` (+ `requirements-simulation.txt` where
  present). Notebooks launch with `jupyter lab "<notebook name>"`.
- **API key** (ch 6–12): `.env` per the chapter README with
  `GOOGLE_API_KEY='...'` and `GOOGLE_GENAI_USE_VERTEXAI=0`; free tier at
  https://ai.google.dev/gemini-api/docs/api-key. In chapters 6–8 (plus
  chapter 10's restored grid and demo cells) the paid notebook cells carry a
  `# NOTE: REQUIRES API KEY` comment with call counts; other cells in
  chapters 9, 11, and 12 are not individually labeled — use each README's
  "Cost expectations" note (every keyed chapter has one) before running evals.
- **Canonical results are git-protected**: chapters ship recorded results
  (pre-filled CSVs, checkpoints, figures) that some eval cells overwrite.
  Recover anything with `git checkout -- <path>`; copy files aside before
  running evals when the reader wants to keep the canon.
- **Recorded results are allowed to fail**: chapters 8 and 10 ship runs that
  miss their own thresholds by design (see their READMEs' "A Note on the
  Recorded Results") — a reproduced FAIL is not a setup error.
- **The repo is newer than the printed book**: post-print fixes live here;
  where a printed listing differs slightly from repo code, the repo is the
  corrected version. Bugs deliberately kept to match print are listed in each
  chapter skill under "Known issues frozen in print".
- **Going beyond the labs**: every chapter skill has a "Directions for
  improvement" section grounding the chapter's own stated next steps (re-run
  grids under current models, close recorded eval gaps, recalibrate judges,
  extend catalogs/ground truth, adapt to enterprise data) with the eval
  harness to measure against and the canon-protection steps to take first.
