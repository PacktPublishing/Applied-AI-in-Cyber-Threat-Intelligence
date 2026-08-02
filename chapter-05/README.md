# Chapter 5 — AI Foundations for Agentic Intelligence Systems

The foundational primer for the seven case-study chapters that follow. Chapter 5 establishes every architectural pattern, evaluation method, and design principle used in Chapters 6 through 12 — applied to a running threat intelligence analyst scenario throughout.

Unlike Chapters 6–12, this chapter contains no agent implementation. All code snippets are illustrative patterns showing ADK syntax and architecture in context; fully working, production-complete implementations begin in Chapter 6.

---

## What It Covers

| Section | Topic |
|---|---|
| 5.1 | The Taxonomy of AI — Symbolic AI → ML → Deep Learning → GenAI → Agentic AI → Multi-Agent → Data Science |
| 5.2 | Optimisation — Temperature, Top-k, Top-p, Frequency/Presence Penalties, Grid Search |
| 5.3 | Prompt Frameworks — COSTAR (Context, Objective, Style, Tone, Audience, Response) |
| 5.4 | Memory and Context Engineering — Context Rot, four-layer memory architecture, ADK `session.state` + `output_key` |
| 5.5 | Knowledge Retrieval: RAG — Embeddings, Cosine Similarity, Vector DB |
| 5.6 | Closed-World Catalog Injection — `format_catalog_for_prompt()` anti-hallucination pattern; appears in Ch7–12 |
| 5.7 | External Integration: MCP and the Tools Interface |
| 5.8 | Multi-Agent Architectures — Sequential topology, LoopAgent + Judge + Verifier, Fan-Out Parallelism |
| 5.9 | Three-Layer Output Validation — API-level constrained decoding, Pydantic schema validation, deterministic rule checkers |
| 5.10 | AI Guardrails: The Defensive Perimeter — Input shields, intention locking, output shields, OWASP LLM Top 10, NIST AI RMF, ISO/IEC 42001 |
| 5.11 | Observability, Telemetry, and Evaluation — Tracing/logging/monitoring, three-layer evaluation hierarchy (Grid Search → Ground Truth → Judge Calibration) |
| 5.12 | Conclusion — Five production-readiness principles |

---

## Running Example

All sections use a **threat intelligence analyst** scenario built around a Priority Intelligence Requirement (PIR):

> *"Determine whether a nation-state actor has compromised our research division's cloud environment over the past 90 days, and assess the scope of any data exfiltration."*

This PIR scenario is the seed for the full seven-stage intelligence cycle implemented in Chapters 6–12.

---

## Illustrative Patterns

The code snippets in this chapter demonstrate:

- ADK `Agent`, `LoopAgent`, `SequentialAgent` construction
- `output_key` → `{placeholder}` state handoff between agents
- `_escalate_on_pass` callback for loop exit on PASS verdict
- `asyncio.Semaphore` + `asyncio.gather` for concurrent grid search and fan-out brief generation
- `output_schema=PydanticModel` for API-level constrained JSON decoding
- `format_catalog_for_prompt()` closed-world catalog injection
- `check_verdict_rules()` deterministic rule checker pattern
- Three-layer evaluation scaffold (`run_grid_search` → `measure_ground_truth` → `calibrate_judge`)

These patterns are not intended to run standalone. Each is fully implemented in the corresponding chapter's `my_agent/agent.py`.

---

## Chapter Preview: Where Each Pattern First Appears

| Pattern | Introduced | First Full Implementation |
|---|---|---|
| COSTAR system prompt | §5.3 | Ch6 |
| `session.state` + `output_key` | §5.4 | Ch6 |
| Closed-world catalog injection | §5.6 | Ch7 |
| LoopAgent + Judge + Verifier | §5.8.2 | Ch7 |
| Fan-out parallelism | §5.8.3 | Ch11 |
| Three-layer output validation | §5.9 | Ch8 |
| Hyperparameter grid search | §5.2 / §5.11 | Ch6 |
| Ground truth evaluation | §5.11 | Ch7 |
| Judge calibration | §5.11 | Ch7 |

---

## Images

| File | Figure | Section |
|---|---|---|
| `Figure 5.1 AI Landscape.png` | Figure 5.1 | §5.1 — AI taxonomy Venn diagram |
| `Context Architecture.png` | Figure 5.2 | §5.4 — Four-layer agent memory architecture |
| `ADK Agent Flow Diagram.png` | Figure 5.3 | §5.8.2 — LoopAgent + Judge + Verifier topology |
| `Three Layer Validation.png` | Figure 5.4 | §5.9 — Three-layer output validation pipeline |
| `Evaluation Hierachy.png` | Figure 5.5 | §5.11 — Three-layer evaluation hierarchy |

---

## Project Structure

```
Chap_5/
├── README.md
├── requirements.txt          # dependencies for the ADK illustrative snippets
├── Chapter 5 Hybrid.docx     # published chapter document
└── Images/
    ├── Figure 5.1 AI Landscape.png
    ├── Context Architecture.png
    ├── ADK Agent Flow Diagram.png
    ├── Three Layer Validation.png
    └── Evaluation Hierachy.png
```

No `my_agent/`, simulation notebook, `ground_truth.csv`, or `config_search_results.csv` — this chapter is a primer, not a pipeline implementation.
