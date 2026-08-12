from __future__ import annotations
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google.adk.agents.llm_agent import Agent
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

load_dotenv()

class OutputJSON(BaseModel):
    specificity_rating: int = Field(ge=1, le=4)
    specificity_explanation: str
    specificity_recommended_actions: Optional[str] = None

    decision_centricity_rating: int = Field(ge=1, le=4)
    decision_centricity_explanation: str
    decision_centricity_recommended_actions: Optional[str] = None

    feasibility_rating: int = Field(ge=1, le=4)
    feasibility_explanation: str
    feasibility_recommended_actions: Optional[str] = None

description = """An intelligence analysis evaluator that scores cybersecurity intelligence requirements 
for specificity, decision-centricity, and feasibility, and recommends improvements. Optimized for 
corporate leadership decision support and strict structured outputs.
"""

instruction = """Your task is
to assess the quality of the provided cybersecurity intelligence requirement.
Evaluate it across the following three variables, using the 1–4 scale:

1 = Poor
2 = Good
3 = Better
4 = Best

Definitions:
- Specificity: Whether the requirement asks a single, clearly defined, narrowly
  scoped question with explicit actors/assets/timeframes.
- Decision-Centricity: Whether the requirement directly supports one specific
  decision with a clear decision point.
- Feasibility: Whether the requirement can realistically be answered using typical
  cybersecurity telemetry, intelligence sources, or analytic capabilities.

For the intelligence requirement provided, perform the following:
1. Provide a rating (1–4) for Specificity and an explanation.
2. Provide a rating (1–4) for Decision-Centricity and an explanation.
3. Provide a rating (1–4) for Feasibility and an explanation.
4. For any variable scoring less than 4, provide clear recommended actions to
    improve the requirement to a “Best” rating.

Respond only in JSON using this structure:

{
  "specificity_rating": number,
  "specificity_explanation": "text",
  "specificity_recommended_actions": "text or null",
  "decision_centricity_rating": number,
  "decision_centricity_explanation": "text",
  "decision_centricity_recommended_actions": "text or null",
  "feasibility_rating": number,
  "feasibility_explanation": "text",
  "feasibility_recommended_actions": "text or null"
}

Here is an example of what a quality rated intelligence requirement looks like:
{
  "Intelligence Requirement": "What cyber threats should we worry about this year?",
  "specificity_rating": 1,
  "specificity_explanation": "Very broad, undefined and multi-dimensional.",
  "decision_centricity_rating": 1,
  "decision_centricity_explanation": "No single decision tied to requirement.",
  "feasibility_rating": 2,
  "feasibility_explanation": "High-level trends answerable but unfocused."
}

Now evaluate this intelligence requirement:
"""

# -------------------------
# Evaluator Agent (tool)
# -------------------------
evaluator_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="evaluator_agent",
    description=description,
    instruction=instruction,
    generate_content_config=types.GenerateContentConfig(temperature=0.0),
    output_schema=OutputJSON,
    output_key="evaluator_output")

evaluator_tool = AgentTool(agent=evaluator_agent)

# -------------------------
# Formatter Agent (root)
# -------------------------
root_agent = Agent(
    model="gemini-3.1-pro-preview",
    name="root_agent",
    description="Takes an intelligence requirement, gets evaluator JSON via tool-call in {evaluator_output}, then renders a table.",
    instruction=(
        "You will receive a cybersecurity intelligence requirement from the user.\n"
        "Step 1) Call the evaluator_agent tool exactly once, passing the user's message verbatim.\n"
        "Step 2) The tool will return JSON with the ratings/explanations/actions.\n"
        "Step 3) Output one markdown table (no code fences)\n\n"
        "Table rules:\n"
        "- Columns: Variable | Rating (1–4) | Explanation | Recommended actions\n"
        "- Rows: Specificity, Decision-Centricity, Feasibility\n"
        "- If recommended actions is null/missing, use —\n"
        "- Output only the table; no extra commentary.\n"
    ),
    tools=[evaluator_tool],
    generate_content_config=types.GenerateContentConfig(temperature=0.0),)