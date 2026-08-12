# Chapter 13 — Classical ML for the Threat Intelligence Lifecycle

Companion materials for Chapter 13 of the Packt book on AI/ML for cyber threat intelligence. This chapter applies classical ML techniques to the ApexCode AiTM scenario from Chapters 6-12, evaluates them honestly against baselines on public data, and defines the integration pattern for wiring ML models into the agentic pipeline.

## Skills

1. Critically review CTI-ML research using a 10-criterion evaluation checklist
2. Build, evaluate, and interpret results honestly when models fail to beat baselines
3. Diagnose why a model underperforms and specify what data would fix it
4. Wire classical ML models as tools into agentic pipelines with promotion criteria

## Folder Contents

```
chapter-13/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── B32645_13.docx                     # Chapter manuscript (gitignored — not in the public repo)
├── CTI_ML.ipynb                       # Companion notebook — all code and figures
├── data/                              # Data files (created by extracting the zip, or auto-downloaded — not tracked in git)
│   ├── kev.json                       # CISA Known Exploited Vulnerabilities catalog
│   ├── attck_enterprise.json          # MITRE ATT&CK Enterprise STIX bundle
│   ├── nvd_2020.json                  # NVD CVE data 2020
│   ├── nvd_2021.json                  # NVD CVE data 2021
│   ├── nvd_2022.json                  # NVD CVE data 2022
│   ├── nvd_2023.json                  # NVD CVE data 2023
│   ├── nvd_2024.json                  # NVD CVE data 2024
│   └── nvd_2025.json                  # NVD CVE data 2025
└── Images/                            # Generated figures (all produced by the notebook)
    ├── insider_threat_features.png    # Chapter Figure 13.1 — Paper 8 NW/ABW feature engineering
    ├── figure_13_1_ndcg_at_k.png      # Chapter Figure 13.2 — Q1 NDCG@k ranker comparison
    ├── figure_13_2_temporal_metrics.png# Chapter Figure 13.3 — Q2 temporal metrics (2×3 subplot)
    ├── figure_13_3_pr_curve.png       # Chapter Figure 13.4 — Q2 precision-recall curves
    ├── figure_13_4_reliability_diagram.png # Chapter Figure 13.5 — Q2 reliability diagram (uncalibrated RF)
    ├── figure_13_5_shap_waterfall.png  # Chapter Figure 13.6 — Q2 SHAP waterfall (top CVE)
    ├── figure_13_6_dendrogram.png      # Repo-only — Q3 TTP clustering dendrogram (not embedded in the chapter; too dense for print)
    ├── figure_13_7_disclosure_forecast.png # Chapter Figure 13.7 — Disclosure forecast + Monte Carlo
    ├── figure_13_8_ach_argument_map.png# Chapter Figure 13.8 — ACH consistency-weight heatmap
    └── figure_13_9_ach_sankey.png      # Chapter Figure 13.9 — ACH Sankey flow view
```

Filename numbering predates the chapter's final figure renumbering (the insider-threat
figure became chapter Figure 13.1 and the dendrogram moved to repo-only), so
`figure_13_N` filenames map to chapter Figure 13.(N+1) for N = 1–5; N = 7–9 match.
The notebook writes figures to a lowercase `images/` directory; on a case-sensitive
filesystem this creates a second folder alongside the shipped `Images/`.

Reproducibility note: the shipped `figure_13_9_ach_sankey.png` reflects a post-run
styling revision (blue/orange palette, top legend chips, 2400x1500 canvas at 3x).
Re-running cell 17 as shipped regenerates the earlier green/red styling at
2200x1400 and will overwrite the shipped file. The ACH weights, net scores, and
diagnosticity values are identical in both renders.

## Chapter Structure

| Section | Content |
|---------|---------|
| **13.1** The CTI-ML Research Landscape | 8 papers (2018-2026) mapped against the intelligence cycle. Systematic methodology failures (temporal split, cross-source, and baseline gaps across roughly 90% of the corpus). 10-criterion evaluation checklist. |
| **13.2** Applying Classical ML to the ApexCode Scenario | Q1: CVE triage ranking (RF vs LambdaMART vs XGBRanker, NDCG@200). Q2: Exploitation detection (RF + HistGBT + XGBoost, AUPRC ~0.010, calibration + SHAP). Q3: Actor TTP clustering (Jaccard, complete linkage). Disclosure forecasting (GBR + Monte Carlo). |
| **13.3** Evaluation of ML Systems | Where each model fell short and what closes the gap (4-row failure-modes-and-fixes table pairing each per-Q failure with the data move that closes it and the falsification test on enterprise data). 10-item evaluation harness as the deliverable (7 standard ML hygiene + 3 CTI-specific: catalog freshness, label-source provenance, TLP propagation). Marking and audit discipline (TLP 2.0 spec + dissemination audit InfoBoxes). Adversarial drift. |
| **13.4** ML Models as Agent Tools | 3-gate promotion criteria (beats baseline at operating point / calibration holds / drift monitor green). Tool-wrapper pattern with baseline failover on drift (tool returns `drift_flag=True` and `source='baseline'` as a breadcrumb on a completed failover). ADK `ToolContext` function-tool registration on the agent's `tools` list. ACH synthesis product (matrix + Sankey, Figures 13.8/13.9). 6-step promotion lifecycle from harness build through production monitoring. |

## Notebook Cells

| Cell | Stage | Content |
|------|-------|---------|
| 0 | — | Markdown intro |
| 1 | — | Imports and setup |
| 2 | — | pip install (optional dependencies) |
| 3 | — | Data loading utilities (NVD, KEV, ATT&CK STIX) |
| 4 | — | Markdown: data setup |
| 5 | Collection | Download and merge NVD + KEV into master CVE dataset |
| 6 | — | Markdown: Stage 2 intro |
| 7 | Collection | Q1: CVE relevance ranking — three ranker families vs CVSS-sort |
| 8 | — | Markdown: Stage 4 intro |
| 9 | Analysis | Q2: Exploitation detection — three classifiers, temporal metrics (chapter Figure 13.3), PR curves (chapter Figure 13.4) |
| 10 | — | Markdown: Actor TTP clustering intro |
| 11 | Analysis | Q3: ATT&CK TTP clustering — Jaccard distance, dendrogram (repo-only figure) |
| 12 | — | Markdown: Stage 5 intro |
| 13 | Production | Reliability diagram + SHAP attribution (chapter Figures 13.5, 13.6) |
| 14 | — | Markdown: Stage 7 intro |
| 15 | Feedback | Disclosure volume forecasting + Monte Carlo capacity simulation (chapter Figure 13.7) |
| 16 | — | Markdown: ACH intro |
| 17 | Synthesis | ACH argument map — matrix heatmap (chapter Figure 13.8) + Sankey flow (chapter Figure 13.9) |
| 18 | — | Markdown: Insider threat intro |
| 19 | Analysis | Paper 8 feature engineering — NW/ABW temporal windowing (chapter Figure 13.1) |
| 20 | — | Markdown: Synthesis |

## Data

### Getting the data (do this first)

The shipped **`CTI_ML_and_DATA.zip`** (~100 MB) contains the pinned data
snapshot that reproduces this chapter's recorded numbers digit-for-digit.
Extract it so `data/` lands directly inside `chapter-13/`:

```bash
cd chapter-13 && unzip -o CTI_ML_and_DATA.zip 'data/*' -d .
```

> **macOS note:** double-clicking the zip extracts into a `CTI_ML_and_DATA/`
> subfolder the notebook never checks — use the command above instead, and
> verify `chapter-13/data/kev.json` exists before launching the notebook.

If `data/` is absent, the notebook falls back to downloading everything
automatically via `fetch_kev()`, `fetch_nvd_year(year)`, and
`fetch_attck_stix()` — this works but takes **1–3 hours**, transfers ~800 MB,
and fetches a *newer snapshot* (KEV grows weekly, NVD revises CVSS), so your
numbers will drift slightly from the Key Results below. Drift on a fresh
download is expected, not an error. All files are cached locally after first
download either way.

**Footprint:** ~1 GB disk (zip + extracted data); peak RAM ~4–6 GB during the
six-year NVD load — 16 GB machines are comfortable, 8 GB is tight.

| Source | Size | Records |
|--------|------|---------|
| NVD (2020-2025) | ~800 MB total | 176,940 CVEs |
| CISA KEV | ~1 MB | 1,587 exploited CVEs |
| MITRE ATT&CK STIX | ~39 MB | Enterprise technique/group catalog |

## Key Results on Public Data

- **Q1 (ranking):** None of three ranker families beat CVSS-sort at NDCG@200.
- **Q2 (classification):** AUPRC ~0.010 vs CVSS-threshold 0.0072 — only ~1.4× lift over the operational baseline (and ~4.5× over the 0.0022 prevalence floor, but prevalence is the wrong comparator when CVSS-sort is the deployed alternative). Operationally insufficient — the KEV-within-30-days label is the ceiling.
- **Q3 (clustering):** Top Jaccard similarity ~0.07. Produces candidate hypothesis set, not attribution.
- **Forecast:** GBR loses to simpler baselines on the public NVD aggregate (Rolling Mean MAE 191.3 vs GBR 283.5); the Monte Carlo capacity-breach overlay reads 100% by construction since weekly disclosures already exceed the 350-CVE capacity in every week of the held-out test window (the final 40 weeks of the 2020-2025 series, Apr-Dec 2025, from the notebook's chronological 70/15/15 split). The technique is sound; the public input is not.

The chapter's pedagogical contribution is the evaluation harness used to measure honestly against simple baselines. On enterprise data with SIEM/EDR exploitation telemetry replacing the KEV proxy, the same pipelines apply.

## Setup

```bash
pip install -r requirements.txt
```

macOS users need `libomp` for XGBoost and LightGBM:

```bash
brew install libomp
```

Launch the notebook with:

```bash
jupyter lab CTI_ML.ipynb
```

> **Recorded figures & recovery:** the notebook saves figures to `images/`, which on case-insensitive filesystems (the macOS and Windows default) is the same folder as the shipped `Images/` — re-running figure cells overwrites the canonical PNGs, including the book figures. Any overwritten file is recoverable with `git checkout -- Images/`.