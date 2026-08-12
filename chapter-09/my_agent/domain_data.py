"""
Stage 4 Analysis — Domain Data

Ground truth catalog of Structured Analytic Techniques (SATs) that constrains
the SAT Recommendation Agent. The agent may ONLY recommend techniques from this
catalog. Any recommendation outside this catalog is a hallucination.

Also defines application rules and evidence requirements that the Judge uses
to validate whether a technique was correctly applied to a given scenario.

Extended catalog (14 techniques), taxonomy mapping, cognitive-bias reference,
analytic-spectrum levels, and tradecraft standards for the full Stage 4 pipeline.
"""

# Schema version — used by agent.py stale-config guard to detect when
# best_config.json was produced under a different catalog/rules version.
TEMPLATE_VERSION = "1.0"

# ---------------------------------------------------------------------------
# SAT Catalog — 14 Structured Analytic Techniques
# ---------------------------------------------------------------------------

SAT_CATALOG = {
    "ACH": {
        "full_name": "Analysis of Competing Hypotheses",
        "when_to_use": "Multiple plausible explanations exist for the observed activity",
        "required_inputs": [
            "corroborated signals from Processing stage",
            "at least 2 competing hypotheses",
        ],
        "output_format": "Hypothesis matrix with evidence ratings (CONSISTENT / INCONSISTENT / NOT APPLICABLE) per hypothesis-evidence pair",
        "example_scenarios": [
            "Partner account compromise could be targeted attack, opportunistic breach, or insider action",
            "Anomalous data transfer could be exfiltration, legitimate backup, or misconfigured automation",
        ],
        "evaluation_criteria": {
            "minimum_hypotheses": 2,
            "requires_evidence_matrix": True,
            "requires_confidence_label": True,
            "requires_rejected_hypothesis_reasoning": True,
        },
    },
    "What-If Analysis": {
        "full_name": "What-If Analysis",
        "when_to_use": "Need to assess downstream impact of a confirmed or probable event",
        "required_inputs": [
            "scenario statement describing the confirmed or probable event",
            "asset context (affected systems, data, business units)",
        ],
        "output_format": "Impact chain: scenario -> immediate consequences -> cascading effects -> business impact quantification",
        "example_scenarios": [
            "Stolen source code is published — map product, revenue, and competitive impact",
            "Compromised API keys are used — map data exposure, customer impact, regulatory obligations",
        ],
        "evaluation_criteria": {
            "requires_scenario_statement": True,
            "requires_immediate_impact": True,
            "requires_cascading_impact": True,
            "requires_business_quantification": True,
        },
    },
    "Indicators of Change": {
        "full_name": "Indicators of Change",
        "when_to_use": "Current assessment is provisional and may change; need a monitoring plan for signals that would confirm or refute the assessment",
        "required_inputs": [
            "current assessment or attribution",
            "key assumptions underlying the assessment",
        ],
        "output_format": "Indicator list: each with source, detection method, threshold, and whether it confirms or refutes the current assessment",
        "example_scenarios": [
            "Provisional attribution to threat group — define signals that would strengthen or weaken confidence",
            "Assessed as opportunistic — define signals that would indicate targeted intent",
        ],
        "evaluation_criteria": {
            "requires_confirms_indicators": True,
            "requires_refutes_indicators": True,
            "requires_detection_source": True,
            "requires_threshold": True,
        },
    },
    "Key Assumptions Check": {
        "full_name": "Key Assumptions Check",
        "when_to_use": "Assessment relies on unstated or unvalidated beliefs that could be wrong",
        "required_inputs": [
            "current assessment",
            "explicit list of assumptions the assessment depends on",
        ],
        "output_format": "Assumption x evidence matrix with vulnerability rating (HIGH / MEDIUM / LOW) per assumption",
        "example_scenarios": [
            "Assessment assumes MFA was not bypassed — check whether session hijacking is possible",
            "Assessment assumes insider acted alone — check for external coordination signals",
        ],
        "evaluation_criteria": {
            "requires_assumption_list": True,
            "requires_vulnerability_rating": True,
            "requires_if_wrong_impact": True,
        },
    },
    "Red Team Analysis": {
        "full_name": "Red Team Analysis",
        "when_to_use": "Need to evaluate defensive posture from the adversary's perspective",
        "required_inputs": [
            "current defensive posture (controls, detections, response procedures)",
            "actor profile (known TTPs, capability level, objectives)",
        ],
        "output_format": "Attack path analysis: entry points, lateral movement options, data targets, exploitation likelihood per path",
        "example_scenarios": [
            "Evaluate Okta/GitHub defensive gaps from the perspective of a state-sponsored actor",
            "Assess whether current EDR coverage would detect the observed TTP chain",
        ],
        "evaluation_criteria": {
            "requires_attack_paths": True,
            "requires_exploitation_likelihood": True,
            "requires_defensive_gap_identification": True,
        },
    },
    "Structured Brainstorming": {
        "full_name": "Structured Brainstorming",
        "when_to_use": "Early-stage investigation with limited signals; need to generate hypotheses before evidence is sufficient for ACH",
        "required_inputs": [
            "initial observations or signals",
            "domain context (industry, threat landscape, asset profile)",
        ],
        "output_format": "Prioritized hypothesis list with evidence mapping: each hypothesis rated by plausibility and testability",
        "example_scenarios": [
            "Single anomalous login detected — brainstorm possible explanations before collecting more data",
            "New vulnerability disclosed — brainstorm potential exploitation scenarios in our environment",
        ],
        "evaluation_criteria": {
            "minimum_hypotheses": 3,
            "requires_plausibility_rating": True,
            "requires_testability_assessment": True,
            "requires_evidence_needed": True,
        },
    },
    # ------------------------------------------------------------------
    # NEW techniques (7-14)
    # ------------------------------------------------------------------
    "Devil's Advocacy": {
        "full_name": "Devil's Advocacy",
        "when_to_use": "A single prevailing assessment dominates and has not been rigorously challenged",
        "required_inputs": [
            "the prevailing assessment or conclusion",
            "the key evidence supporting the prevailing view",
        ],
        "output_format": (
            "Opposing argument: strongest case AGAINST the prevailing view, "
            "evidence gaps that could invalidate it, conditions under which "
            "the prevailing view would be wrong"
        ),
        "example_scenarios": [
            "Attribution consensus points to a specific nation-state group — construct the strongest case that a different actor is responsible",
            "All evidence suggests external compromise — build the argument that an insider with legitimate access is the true source",
        ],
        "evaluation_criteria": {
            "requires_prevailing_view_stated": True,
            "requires_opposing_argument": True,
            "requires_evidence_gaps_identified": True,
            "requires_conditions_for_invalidation": True,
        },
    },
    "Premortem Analysis": {
        "full_name": "Premortem Analysis",
        "when_to_use": "Need to identify what could make the current assessment wrong BEFORE it is finalized and acted upon",
        "required_inputs": [
            "current assessment or planned course of action",
            "confidence level of the assessment",
        ],
        "output_format": (
            "Failure scenario narrative: imagine the assessment was proven wrong "
            "6 months from now, then work backward to identify what factors caused "
            "the failure -- each with likelihood and detectability"
        ),
        "example_scenarios": [
            "Before publishing attribution report, imagine it is later proven wrong — what went wrong and what signals were missed?",
            "Before recommending remediation plan, imagine the threat actor returns within 90 days — what assumptions failed?",
        ],
        "evaluation_criteria": {
            "requires_failure_narrative": True,
            "requires_causal_factors": True,
            "minimum_failure_factors": 3,
            "requires_likelihood_rating": True,
            "requires_detectability_rating": True,
        },
    },
    "High-Impact Low-Probability": {
        "full_name": "High-Impact Low-Probability Analysis",
        "when_to_use": "Need to assess unlikely but catastrophic scenarios that standard analysis might dismiss",
        "required_inputs": [
            "current threat landscape assessment",
            "list of organizational critical assets or functions",
        ],
        "output_format": (
            "HILP scenario table: each row is a low-probability event with "
            "impact severity (CATASTROPHIC/SEVERE/MODERATE), probability estimate, "
            "early warning indicators, and preparedness gap"
        ),
        "example_scenarios": [
            "Assess the scenario where a trusted certificate authority used by the organization is compromised — map cascading impact across all TLS-dependent services",
            "Evaluate the possibility that a zero-day in the organization's core cloud provider allows tenant escape — identify blast radius and response readiness",
        ],
        "evaluation_criteria": {
            "minimum_scenarios": 2,
            "requires_impact_severity": True,
            "requires_probability_estimate": True,
            "requires_early_warning_indicators": True,
            "requires_preparedness_gap": True,
        },
    },
    "Scenario Analysis": {
        "full_name": "Scenario Analysis",
        "when_to_use": "Multiple plausible future states exist and planning must account for divergent outcomes",
        "required_inputs": [
            "current situation assessment",
            "key drivers of change (variables that could shift the outcome)",
        ],
        "output_format": (
            "2x2 scenario matrix based on two key drivers, with 4 named future "
            "states -- each described with narrative, indicators, and recommended "
            "actions"
        ),
        "example_scenarios": [
            "Threat actor's next move depends on whether stolen code is monetized or weaponized, and whether the organization detects and rotates credentials in time",
            "Post-breach trajectory depends on regulatory response severity and whether the attacker retains persistent access",
        ],
        "evaluation_criteria": {
            "requires_key_drivers": True,
            "minimum_drivers": 2,
            "minimum_scenarios": 3,
            "requires_scenario_narratives": True,
            "requires_indicators_per_scenario": True,
            "requires_actions_per_scenario": True,
        },
    },
    "Deception Detection": {
        "full_name": "Deception Detection",
        "when_to_use": "Adversary may be deliberately misleading analysts through planted evidence, false flags, or misdirection",
        "required_inputs": [
            "evidence inventory with source reliability ratings",
            "adversary capability profile (if available)",
        ],
        "output_format": (
            "Deception assessment: for each key evidence item, evaluate whether "
            "it could be fabricated or planted -- with MOM criteria (Motive, "
            "Opportunity, Means) and a deception likelihood rating "
            "(HIGH/MEDIUM/LOW/NEGLIGIBLE)"
        ),
        "example_scenarios": [
            "Attribution evidence points cleanly to a known APT — assess whether a sophisticated actor planted false-flag indicators to frame the group",
            "Insider threat investigation surfaces a trail of breadcrumbs pointing to one employee — evaluate whether someone else planted the evidence",
        ],
        "evaluation_criteria": {
            "requires_evidence_by_evidence_assessment": True,
            "requires_mom_criteria": True,
            "requires_deception_likelihood_rating": True,
            "requires_overall_deception_assessment": True,
        },
    },
    "Quality of Information Check": {
        "full_name": "Quality of Information Check",
        "when_to_use": (
            "Assessment relies on evidence of uncertain reliability or validity "
            "-- need to evaluate the quality of the information itself before "
            "drawing conclusions"
        ),
        "required_inputs": [
            "key evidence items supporting the assessment",
            "source descriptions for each evidence item",
        ],
        "output_format": (
            "Information quality matrix: each evidence item rated on Reliability "
            "(A-F scale) and Validity (1-6 scale) per NATO Admiralty Code, with "
            "overall quality classification and impact on assessment confidence"
        ),
        "example_scenarios": [
            "Threat intelligence report from a new vendor cites specific IOCs — evaluate whether the source and the data meet the bar for inclusion in the assessment",
            "Open-source social media post claims insider knowledge of an upcoming attack — rate information quality before incorporating into threat picture",
        ],
        "evaluation_criteria": {
            "requires_reliability_rating": True,
            "requires_validity_rating": True,
            "requires_overall_quality_classification": True,
            "requires_confidence_impact_assessment": True,
        },
    },
    "Argument Mapping": {
        "full_name": "Argument Mapping",
        "when_to_use": "Complex conclusion depends on multiple inferential steps -- need to expose the logical structure and identify weak links",
        "required_inputs": [
            "primary conclusion or assessment",
            "evidence items supporting the conclusion",
        ],
        "output_format": (
            "Hierarchical argument structure: conclusion <- supporting inferences "
            "<- evidence nodes, with link strength (STRONG/MODERATE/WEAK) per "
            "connection and identification of the weakest link in the chain"
        ),
        "example_scenarios": [
            "Attribution conclusion rests on three inferential chains — map each chain to expose which link is most vulnerable to new evidence",
            "Risk assessment conclusion depends on multiple assumptions and evidence sources — visualize the argument tree to identify single points of failure",
        ],
        "evaluation_criteria": {
            "requires_conclusion_node": True,
            "requires_inference_nodes": True,
            "requires_evidence_nodes": True,
            "requires_link_strength": True,
            "requires_weakest_link_identification": True,
        },
    },
    "Cross-Impact Matrix": {
        "full_name": "Cross-Impact Matrix",
        "when_to_use": (
            "Multiple factors or variables may influence each other in ways that "
            "are not immediately obvious -- need to assess second-order effects"
        ),
        "required_inputs": [
            "list of key factors or variables in the scenario",
            "current assessment of each factor's state",
        ],
        "output_format": (
            "N x N matrix where each cell indicates how Factor A changing would "
            "affect Factor B -- rated as STRONG POSITIVE/WEAK POSITIVE/NEUTRAL/"
            "WEAK NEGATIVE/STRONG NEGATIVE, with narrative for non-neutral "
            "interactions"
        ),
        "example_scenarios": [
            "Assess how changes in attacker persistence, regulatory scrutiny, public disclosure, and patch deployment interact to shape the overall risk trajectory",
            "Map how credential rotation, threat actor adaptability, employee awareness, and vendor response times influence each other during an active incident",
        ],
        "evaluation_criteria": {
            "requires_factor_list": True,
            "minimum_factors": 3,
            "requires_impact_matrix": True,
            "requires_narrative_for_key_interactions": True,
        },
    },
}

# Canonical technique names — used by the Judge to validate recommendations
SAT_NAMES = set(SAT_CATALOG.keys())

# ---------------------------------------------------------------------------
# SAT Taxonomy — maps analytic categories to technique lists
# ---------------------------------------------------------------------------

SAT_TAXONOMY = {
    "Environment Scanning": ["Indicators of Change"],
    "Source Evaluation": ["Quality of Information Check"],
    "Decomposition and Visualization": ["Argument Mapping"],
    "Creative Thinking": ["Structured Brainstorming"],
    "Diagnostic": ["ACH", "Key Assumptions Check", "Deception Detection"],
    "Challenge": ["Red Team Analysis", "Devil's Advocacy"],
    "Imaginative Thinking": [
        "What-If Analysis",
        "Premortem Analysis",
        "High-Impact Low-Probability",
        "Scenario Analysis",
    ],
    "Decision Support": ["Cross-Impact Matrix"],
}

# ---------------------------------------------------------------------------
# SAT Selection Rules — constraints the Judge enforces
# ---------------------------------------------------------------------------

SAT_SELECTION_RULES = {
    "minimum_techniques": 2,
    "maximum_techniques": 4,
    "rules": [
        "Each recommended SAT must exist in SAT_CATALOG by exact name",
        "Each SAT must match the 'when_to_use' criteria for the given scenario",
        "Each SAT must be applied with all 'required_inputs' present",
        "Output must follow the SAT's defined 'output_format'",
        "ACH is required when 2+ competing explanations are plausible",
        "What-If is required when downstream business impact must be assessed",
        "Indicators of Change is required when the assessment is explicitly provisional",
        "Structured Brainstorming should NOT be used when evidence is already sufficient for ACH",
        "Devil's Advocacy is required when a single prevailing view dominates without challenge",
        "Quality of Information Check is required when evidence reliability is uncertain or contested",
        "Deception Detection is required when a state-level adversary is suspected of misdirection",
        "No more than 2 techniques from the same SAT_TAXONOMY category may be recommended in a single analysis",
    ],
}

# ---------------------------------------------------------------------------
# Audience Mapping — who consumes each SAT's output
# ---------------------------------------------------------------------------

AUDIENCE_MAP = {
    "ACH": {
        "primary": "Security Operations / Threat Intelligence",
        "secondary": "CISO",
        "classification": "SECRET",
        "rationale": "Technical hypothesis evaluation with evidence from restricted sources",
    },
    "What-If Analysis": {
        "primary": "Business Leadership / Product Management",
        "secondary": "General Counsel",
        "classification": "CONFIDENTIAL",
        "rationale": "Business impact quantification for strategic decision-making",
    },
    "Indicators of Change": {
        "primary": "SOC Manager / Detection Engineering",
        "secondary": "Threat Intelligence",
        "classification": "SECRET",
        "rationale": "Forward-looking detection signals requiring operational action",
    },
    "Key Assumptions Check": {
        "primary": "Threat Intelligence / Risk Management",
        "secondary": "CISO",
        "classification": "CONFIDENTIAL",
        "rationale": "Assessment integrity validation for risk-informed decisions",
    },
    "Red Team Analysis": {
        "primary": "Security Engineering / SOC",
        "secondary": "VP Cloud Engineering",
        "classification": "TOP SECRET",
        "rationale": "Defensive gap analysis with exploitation likelihood",
    },
    "Structured Brainstorming": {
        "primary": "Threat Intelligence (internal)",
        "secondary": "SOC Manager",
        "classification": "CONFIDENTIAL",
        "rationale": "Hypothesis generation for early-stage investigation direction",
    },
    "Devil's Advocacy": {
        "primary": "Threat Intelligence / CISO",
        "secondary": "Security Operations",
        "classification": "SECRET",
        "rationale": "Stress-testing prevailing assessments to surface blind spots",
    },
    "Premortem Analysis": {
        "primary": "Risk Management / CISO",
        "secondary": "Security Operations",
        "classification": "CONFIDENTIAL",
        "rationale": "Pre-decision failure-mode identification to strengthen assessments",
    },
    "High-Impact Low-Probability": {
        "primary": "CISO / Board Risk Committee",
        "secondary": "General Counsel",
        "classification": "TOP SECRET",
        "rationale": "Catastrophic-scenario preparedness for executive risk governance",
    },
    "Scenario Analysis": {
        "primary": "Business Leadership / CISO",
        "secondary": "Product Management",
        "classification": "CONFIDENTIAL",
        "rationale": "Divergent-future planning for strategic and operational resilience",
    },
    "Deception Detection": {
        "primary": "Threat Intelligence (internal)",
        "secondary": "SOC Manager",
        "classification": "TOP SECRET",
        "rationale": "Counter-deception evaluation of evidence provenance and integrity",
    },
    "Quality of Information Check": {
        "primary": "Threat Intelligence (internal)",
        "secondary": "Risk Management",
        "classification": "CONFIDENTIAL",
        "rationale": "Evidence quality assurance before incorporation into assessments",
    },
    "Argument Mapping": {
        "primary": "Threat Intelligence / Risk Management",
        "secondary": "CISO",
        "classification": "SECRET",
        "rationale": "Logical-structure audit to identify inferential weak points",
    },
    "Cross-Impact Matrix": {
        "primary": "Risk Management / Business Leadership",
        "secondary": "CISO",
        "classification": "CONFIDENTIAL",
        "rationale": "Second-order interaction analysis for multi-variable scenarios",
    },
}

# ---------------------------------------------------------------------------
# Cognitive Biases — reference for analytic tradecraft guards
# ---------------------------------------------------------------------------

COGNITIVE_BIASES = {
    "anchoring": {
        "name": "Anchoring Bias",
        "description": (
            "Over-reliance on the first piece of information encountered (the "
            "'anchor') when making judgments, causing subsequent evidence to be "
            "interpreted relative to that anchor rather than on its own merits."
        ),
        "mitigation": (
            "Deliberately generate assessments BEFORE reviewing legacy reports. "
            "Use ACH to force equal consideration of all hypotheses regardless "
            "of the order in which evidence was received."
        ),
        "detection_signal": (
            "Analyst's conclusion closely mirrors the first report received, "
            "even when later evidence diverges significantly."
        ),
    },
    "confirmation_bias": {
        "name": "Confirmation Bias",
        "description": (
            "Tendency to search for, interpret, and recall information in a way "
            "that confirms pre-existing beliefs or hypotheses, while giving "
            "disproportionately less attention to disconfirming evidence."
        ),
        "mitigation": (
            "Apply Devil's Advocacy to force construction of the strongest "
            "counter-argument. In ACH, explicitly weight INCONSISTENT evidence "
            "more heavily than CONSISTENT evidence when discriminating hypotheses."
        ),
        "detection_signal": (
            "Assessment cites abundant supporting evidence but fails to address "
            "or even mention evidence that contradicts the conclusion."
        ),
    },
    "groupthink": {
        "name": "Groupthink",
        "description": (
            "Desire for conformity within a group leads to irrational or "
            "dysfunctional decision-making outcomes. Dissenting views are "
            "suppressed or self-censored to maintain group harmony."
        ),
        "mitigation": (
            "Assign a formal Devil's Advocate role in every analytic session. "
            "Use Red Team Analysis to inject an adversarial perspective. Require "
            "anonymous alternative hypotheses before group discussion."
        ),
        "detection_signal": (
            "All team members converge on a single explanation without documented "
            "dissent, alternative hypotheses, or minority opinions."
        ),
    },
    "mirror_imaging": {
        "name": "Mirror Imaging",
        "description": (
            "Assuming that the adversary thinks and behaves the way the analyst "
            "or the analyst's organization would in the same situation, rather "
            "than reasoning from the adversary's actual context and incentives."
        ),
        "mitigation": (
            "Use Red Team Analysis explicitly adopting the adversary's known "
            "doctrine, cultural context, and resource constraints. Cross-check "
            "assumptions against documented adversary behavior from past campaigns."
        ),
        "detection_signal": (
            "Assessment predicts adversary actions that align with the analyst's "
            "own organization's playbook rather than the adversary's known TTPs "
            "or strategic objectives."
        ),
    },
    "availability_bias": {
        "name": "Availability Bias",
        "description": (
            "Overweighting information that is easily recalled — typically "
            "recent, vivid, or emotionally salient events — leading to skewed "
            "probability estimates."
        ),
        "mitigation": (
            "Use structured base-rate data from historical incident databases "
            "when estimating probabilities. Apply Scenario Analysis to force "
            "consideration of less memorable but statistically more likely "
            "outcomes."
        ),
        "detection_signal": (
            "Probability estimates closely track recent headline incidents "
            "rather than historical base rates for the threat category."
        ),
    },
    "premature_closure": {
        "name": "Premature Closure",
        "description": (
            "Reaching a conclusion before all available evidence has been "
            "considered, often driven by time pressure or an early satisfying "
            "explanation. Once the conclusion is 'locked in,' new evidence is "
            "ignored or rationalized away."
        ),
        "mitigation": (
            "Apply Key Assumptions Check before finalizing any assessment. Use "
            "Premortem Analysis to force the team to imagine the conclusion was "
            "wrong and work backward. Require Indicators of Change to define "
            "what would reopen the analysis."
        ),
        "detection_signal": (
            "Assessment was finalized early in the investigation timeline and "
            "subsequent evidence collection did not alter the conclusion — even "
            "when new data introduced ambiguity."
        ),
    },
}

# ---------------------------------------------------------------------------
# Analytic Spectrum — levels of analytic depth
# ---------------------------------------------------------------------------

ANALYTIC_SPECTRUM = {
    "descriptive": {
        "label": "Descriptive",
        "question": "What happened?",
        "sat_alignment": [
            "Quality of Information Check",
            "Structured Brainstorming",
        ],
        "confidence_requirement": (
            "Descriptive products require HIGH confidence in factual accuracy; "
            "uncertain details must be flagged explicitly."
        ),
    },
    "explanatory": {
        "label": "Explanatory",
        "question": "Why did it happen?",
        "sat_alignment": [
            "ACH",
            "Key Assumptions Check",
            "Argument Mapping",
            "Deception Detection",
        ],
        "confidence_requirement": (
            "Explanatory products must state the confidence level of the causal "
            "explanation and list alternative explanations that were considered "
            "and rejected."
        ),
    },
    "evaluative": {
        "label": "Evaluative",
        "question": "What is the impact?",
        "sat_alignment": [
            "What-If Analysis",
            "Red Team Analysis",
            "Cross-Impact Matrix",
            "Devil's Advocacy",
        ],
        "confidence_requirement": (
            "Evaluative products must quantify impact where possible and "
            "distinguish between confirmed impact and projected impact, with "
            "separate confidence labels for each."
        ),
    },
    "estimative": {
        "label": "Estimative",
        "question": "What will happen next?",
        "sat_alignment": [
            "Scenario Analysis",
            "Indicators of Change",
            "Premortem Analysis",
            "High-Impact Low-Probability",
        ],
        "confidence_requirement": (
            "Estimative products must use calibrated probability language "
            "(e.g., 'likely' = 55-80%), provide explicit assumptions, and "
            "define indicators that would change the estimate."
        ),
    },
}

# ---------------------------------------------------------------------------
# Tradecraft Standards — analytic rigor benchmarks
# ---------------------------------------------------------------------------

TRADECRAFT_STANDARDS = {
    "confidence_calibration": {
        "LOW": (
            "Assessment is based on fragmentary or uncorroborated information; "
            "the evidence is insufficient to resolve competing hypotheses. "
            "Probability range: roughly 20-40%."
        ),
        "MEDIUM": (
            "Assessment is based on credibly sourced and partially corroborated "
            "information; remaining gaps are identified but do not invalidate "
            "the conclusion. Probability range: roughly 40-70%."
        ),
        "HIGH": (
            "Assessment is based on multiple independent, corroborated sources "
            "with strong logical consistency; alternative explanations have been "
            "considered and are significantly less supported. Probability range: "
            "roughly 70-95%."
        ),
    },
    "assumption_surfacing": (
        "Every analytic product must explicitly list the key assumptions on "
        "which the assessment depends. Each assumption must be rated for "
        "vulnerability (HIGH/MEDIUM/LOW) and accompanied by a statement of "
        "what would change if the assumption proved false. Assumptions must "
        "be surfaced BEFORE the analysis begins, not retrofitted afterward."
    ),
    "alternative_hypothesis_standard": (
        "Analysts must identify and evaluate at least two alternative "
        "hypotheses for every primary conclusion. Rejection of an alternative "
        "must cite specific INCONSISTENT evidence, not merely the absence of "
        "supporting evidence. The absence of evidence is not evidence of "
        "absence — this asymmetry must be documented explicitly."
    ),
    "analytic_process_steps": [
        "1. Define the analytic question and scope",
        "2. Identify and surface key assumptions",
        "3. Collect and evaluate evidence quality (Quality of Information Check)",
        "4. Generate hypotheses (Structured Brainstorming or prior knowledge)",
        "5. Apply diagnostic techniques (ACH, Key Assumptions Check, Deception Detection)",
        "6. Apply challenge techniques (Devil's Advocacy, Red Team Analysis)",
        "7. Assess future states and impact (Scenario Analysis, What-If Analysis, Premortem Analysis)",
        "8. Synthesize findings, assign confidence, and document limitations",
    ],
}

# ---------------------------------------------------------------------------
# Config Search Inputs — 10 scenarios for grid search
# ---------------------------------------------------------------------------

CONFIG_SEARCH_INPUTS = [
    {
        "id": "analysis_input_01",
        "label": "ACH scenario — partner account compromise",
        "corroborated_brief": (
            "HIGH CONFIDENCE corroboration: Partner developer account at DevPartner Inc. "
            "cloned 3 sensitive repos from IP 185.220.101.x (known UNC-XXXX egress). "
            "Same developer's credentials appeared in dark web dump 48h prior. "
            "GitHub audit log shows impossible travel (US login, then RU-based clone within 20min). "
            "Three competing explanations: (1) targeted state-sponsored IP theft, "
            "(2) opportunistic credential stuffing by commodity actor, "
            "(3) disgruntled partner employee acting independently."
        ),
    },
    {
        "id": "analysis_input_02",
        "label": "What-If scenario — confirmed code theft",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Source code for Project Phoenix (flagship product, 20% of Q4 revenue) "
            "confirmed exfiltrated via compromised partner session. Repos accessed: phoenix-core, "
            "phoenix-api, phoenix-auth. Code contains hardcoded API keys for 3 production services. "
            "Actor had access for approximately 6 hours before detection."
        ),
    },
    {
        "id": "analysis_input_03",
        "label": "IoC scenario — provisional attribution",
        "corroborated_brief": (
            "MEDIUM CONFIDENCE: Activity pattern matches UNC-XXXX TTPs (session hijacking via "
            "Evilginx2, targeting developer accounts, focus on source code). Attribution is "
            "provisional — based on IP overlap and tooling similarity. No direct C2 communication "
            "observed. Assessment could change if forensic analysis reveals different tooling."
        ),
    },
    {
        "id": "analysis_input_04",
        "label": "KAC scenario — MFA bypass assumption",
        "corroborated_brief": (
            "HIGH CONFIDENCE corroboration: Partner account accessed repos without triggering MFA "
            "challenge. Current assessment assumes attacker used session cookie theft to bypass MFA. "
            "However, this assumption has not been validated — alternative explanations include: "
            "MFA fatigue attack succeeded, MFA was disabled on the partner's Okta tenant, or "
            "the partner shared credentials deliberately."
        ),
    },
    {
        "id": "analysis_input_05",
        "label": "Red Team scenario — Okta/GitHub defensive posture",
        "corroborated_brief": (
            "Following the confirmed breach, security leadership requests an adversary-perspective "
            "evaluation of ApexCode's Okta SSO and GitHub Enterprise defensive posture. Current "
            "controls: Okta with push MFA (not FIDO2), GitHub with SSO enforcement, CASB monitoring "
            "for bulk downloads, no session binding, no impossible-travel automated response. "
            "Actor profile: UNC-XXXX, state-sponsored, specializes in SaaS session hijacking."
        ),
    },
    {
        "id": "analysis_input_06",
        "label": "Brainstorming scenario — limited signals",
        "corroborated_brief": (
            "LOW CONFIDENCE: Single anomalous signal detected — partner developer accessed a repo "
            "they have never accessed before (infrastructure-secrets) at 02:00 local time. No "
            "credential leak detected. No impossible travel. No other corroborating signals. "
            "Could be legitimate late-night work, compromised account, or reconnaissance."
        ),
    },
    {
        "id": "analysis_input_07",
        "label": "ACH + What-If — ransomware initial access",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Ransomware payload detected on 3 endpoints in Engineering subnet. "
            "Initial access vector unclear — competing hypotheses: (1) phishing email with "
            "macro-enabled doc targeting engineer, (2) exploitation of unpatched VPN gateway, "
            "(3) lateral movement from already-compromised partner VPN session. Lateral movement "
            "scope unknown. 12 additional endpoints show suspicious DNS queries to known C2 domain."
        ),
    },
    {
        "id": "analysis_input_08",
        "label": "Insider threat — ambiguous intent",
        "corroborated_brief": (
            "MEDIUM CONFIDENCE: Employee in Product Engineering downloaded 847 files from internal "
            "repos over 5 days, including design documents and customer integration specs. Employee "
            "recently received a performance warning. Downloads occurred during business hours from "
            "corporate VPN. Two competing interpretations: (1) data hoarding in anticipation of "
            "termination, (2) legitimate research for a cross-team project they volunteered for."
        ),
    },
    {
        "id": "analysis_input_09",
        "label": "Supply chain — multiple injection points",
        "corroborated_brief": (
            "HIGH CONFIDENCE: Malicious dependency detected in CI/CD pipeline — npm package "
            "'lodash-utils-extended' (typosquat) injected into build. Three possible injection "
            "points: (1) compromised developer workstation pushed poisoned package-lock.json, "
            "(2) GitHub Actions workflow modified to pull from attacker-controlled registry, "
            "(3) Artifactory remote proxy cached a malicious package during a brief upstream "
            "compromise. Customer-facing builds from last 72h may be affected."
        ),
    },
    {
        "id": "analysis_input_10",
        "label": "BEC — financial fraud + data theft",
        "corroborated_brief": (
            "HIGH CONFIDENCE: CFO email account compromised via OAuth consent phishing. Two "
            "distinct threat activities observed: (1) wire transfer request for $2.1M sent to "
            "Accounts Payable (intercepted), (2) inbox rules created forwarding all emails "
            "containing 'acquisition', 'merger', and 'board' to external address. Competing "
            "hypotheses: single actor with dual objectives vs. access broker sold to two buyers."
        ),
    },
]
