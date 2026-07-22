#dont add sh-bang because causes ModuleNotFoundErorr 'google' in windows
#all ADK required here
from google.adk.agents.llm_agent import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from google.adk.tools.google_search_tool import GoogleSearchTool
from google.genai import types
from google.adk.planners import BuiltInPlanner
from google.adk.tools import FunctionTool
from google.adk.apps.app import App
from google.adk.plugins import ReflectAndRetryToolPlugin
from google.adk.apps.app import EventsCompactionConfig
from google.adk.models import LlmResponse
from pydantic import BaseModel, Field
from typing import List, Literal, Optional

#main function and helper function needs
import os, asyncio, time, json, random
from pathlib import Path

#env variables need set before the external package tools that use them
#ADK agents use this region, but CTI tool calls use per-call round-robin via region_manager
os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'TRUE'

# Get project ID from environment or gcloud config
if 'GOOGLE_CLOUD_PROJECT' not in os.environ:
    try:
        import subprocess
        result = subprocess.run(['gcloud', 'config', 'get-value', 'project'],
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            os.environ['GOOGLE_CLOUD_PROJECT'] = result.stdout.strip()
            print(f"[CONFIG] Using gcloud project: {os.environ['GOOGLE_CLOUD_PROJECT']}")
        else:
            raise ValueError("GOOGLE_CLOUD_PROJECT not set and gcloud config has no default project")
    except Exception as e:
        raise ValueError(
            f"GOOGLE_CLOUD_PROJECT environment variable not set and could not get from gcloud config.\n"
            f"Set it with: export GOOGLE_CLOUD_PROJECT=your-project-id\n"
            f"Or configure gcloud: gcloud config set project your-project-id\n"
            f"Error: {e}"
        )

os.environ['GOOGLE_CLOUD_LOCATION'] = os.environ.get('GOOGLE_CLOUD_LOCATION', 'us-central1')  # ADK agents use fixed region

# Set timestamp environment variables at module load time (works for both CLI and ADK web)
from datetime import datetime, timezone, timedelta
_current_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
_seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
_three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
_fourteen_days_ago = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
os.environ['CURRENT_UTC_TIME'] = _current_utc
os.environ['LOOKBACK_7_DAYS'] = _seven_days_ago
os.environ['LOOKBACK_3_DAYS'] = _three_days_ago
os.environ['LOOKBACK_14_DAYS'] = _fourteen_days_ago

#custom functions as tools in tools folder
from gcphunter_agent.tools.gcloud_cli import gcloud_read
from gcphunter_agent.tools.load_cti_files import load_cti_files
from gcphunter_agent.tools.hallucination_detector import evaluate_outputs, HallucinationReport
from gcphunter_agent.tools.status_logger import log_status

#custom plugins
from gcphunter_agent.plugins import AutoSaveResultsPlugin, EvidenceInitPlugin

#sanitized google search wrapper
class SanitizedGoogleSearchTool(GoogleSearchTool):
    """GoogleSearchTool with automatic PII/project data sanitization"""

    def __call__(self, query: str, **kwargs):
        sanitized_query = self._sanitize(query)
        print(f"[SEARCH] Original: {query[:80]}...")
        print(f"[SEARCH] Sanitized: {sanitized_query[:80]}...")
        return super().__call__(sanitized_query, **kwargs)

    def _sanitize(self, query: str) -> str:
        """Remove sensitive project-specific information from search queries"""
        import re

        # Get project ID from environment
        project_id = os.environ.get('GOOGLE_CLOUD_PROJECT', '')

        # Replace project ID
        if project_id:
            query = query.replace(project_id, '[PROJECT]')

        # Replace IP addresses
        query = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', query)

        # Replace email addresses (service accounts and user emails)
        query = re.sub(r'[\w\.-]+@[\w\.-]+\.gserviceaccount\.com', '[SERVICE_ACCOUNT]', query)
        query = re.sub(r'[\w\.-]+@[\w\.-]+\.(com|net|org|io)', '[EMAIL]', query)

        # Replace bucket names (often contain project ID or sensitive names)
        query = re.sub(r'\b[a-z0-9\-_]+\.appspot\.com\b', '[BUCKET]', query, flags=re.IGNORECASE)
        query = re.sub(r'\b[a-z0-9\-_]{10,}bucket[a-z0-9\-_]*\b', '[BUCKET]', query, flags=re.IGNORECASE)

        # Replace instance names
        query = re.sub(r'\binstance-[a-z0-9\-]+\b', '[INSTANCE]', query, flags=re.IGNORECASE)

        # Replace GCS URIs
        query = re.sub(r'gs://[a-z0-9\-_/]+', 'gs://[BUCKET]/[PATH]', query, flags=re.IGNORECASE)

        return query

#needed this because ADK non-deterministic to outputschema causes errors without graceful handling
def safe_json_parse(state: dict, key: str, default=None):
    """Safely parse JSON from state with repair for incomplete JSON"""
    try:
        value = state.get(key, default)
        if isinstance(value, str):
            return json.loads(value)
        return value
    except (json.JSONDecodeError, TypeError) as e:
        print(f"[JSON REPAIR] {key} has invalid JSON: {e}")

        # Attempt repair for final_hunt_report only
        if key == 'final_hunt_report' and isinstance(value, str):
            repaired = repair_incomplete_json(value, state, e)
            if repaired:
                return repaired

        print(f"[JSON REPAIR] Falling back to default for {key}")
        return default


def repair_incomplete_json(raw_json: str, state: dict, original_error: Exception) -> dict:
    """Three-tier repair strategy for incomplete JSON from LLM output"""

    # Tier 1: Fix missing closing brackets/braces (common truncation issue)
    repaired = raw_json
    open_braces = repaired.count('{') - repaired.count('}')
    open_brackets = repaired.count('[') - repaired.count(']')

    if open_braces > 0 or open_brackets > 0:
        if open_braces > 0:
            repaired += '\n' + ('}' * open_braces)
        if open_brackets > 0:
            repaired += '\n' + (']' * open_brackets)

        try:
            parsed = json.loads(repaired)
            print(f"[JSON REPAIR] SUCCESS: Added {open_braces} braces, {open_brackets} brackets")

            # Add metadata about repair
            parsed['truncation_notice'] = (
                f"Output was truncated mid-generation. "
                f"JSON automatically repaired ({open_braces} braces, {open_brackets} brackets added). "
                f"Some data may be incomplete."
            )
            parsed.setdefault('_metadata', {})
            parsed['_metadata']['json_repaired'] = True
            parsed['_metadata']['repair_details'] = {
                'braces_added': open_braces,
                'brackets_added': open_brackets,
                'original_error': str(original_error)
            }
            return parsed
        except json.JSONDecodeError as e2:
            print(f"[JSON REPAIR] Tier 1 failed: {e2}")

    # Tier 2: Emergency fallback to hunt_results
    print("[JSON REPAIR] Using emergency fallback to hunt_results")
    return create_emergency_report(raw_json, state, original_error)


def create_emergency_report(incomplete_json: str, state: dict, error: Exception) -> dict:
    """Fallback to ExecutionResults when formatter completely fails"""

    # Get validated hunt_results from execution_agent (has output_schema)
    hunt_results = state.get('hunt_results', {})

    # If it's a Pydantic model, convert to dict
    if hasattr(hunt_results, 'model_dump'):
        hunt_results = hunt_results.model_dump()

    # If it's a string, try parsing
    if isinstance(hunt_results, str):
        try:
            hunt_results = json.loads(hunt_results)
        except (json.JSONDecodeError, ValueError):
            hunt_results = {}

    # Build minimal report from execution agent output
    return {
        "hunt_status": "PARTIAL",
        "execution_summary": hunt_results.get('execution_summary', {
            "commands_executed": 0,
            "commands_skipped": 0,
            "findings_detected": 0,
            "overall_status": "FORMATTER_FAILED"
        }),
        "command_results": hunt_results.get('command_results', []),
        "total_log_entries_analyzed": sum(
            r.get('log_entries_found', 0)
            for r in hunt_results.get('command_results', [])
        ),
        "total_security_findings": len(hunt_results.get('critical_findings', [])),
        "critical_findings": hunt_results.get('critical_findings', []),
        "recommendations": [
            "WARNING: Final report formatting failed - this is an emergency fallback",
            "Review command_results below for raw hunt outputs",
            "Consider re-running hunt if needed"
        ],
        "truncation_notice": f"Formatter crashed: {str(error)}",
        "_metadata": {
            "emergency_fallback": True,
            "formatter_error": str(error),
            "incomplete_output_preview": incomplete_json[:500] + "..." if len(incomplete_json) > 500 else incomplete_json
        }
    }

def get_state_value(state: dict, key: str, expect_json: bool = False, default=None):
    """Unified state accessor with Pydantic/JSON/dict handling

    Args:
        state: The workflow state dictionary
        key: State key to retrieve
        expect_json: If True, parse string values as JSON
        default: Default value if key missing

    Returns:
        State value with appropriate type conversion
    """
    value = state.get(key, default)

    # If Pydantic model, convert to dict
    if hasattr(value, 'model_dump'):
        return value.model_dump()

    # If expecting JSON and got string, parse it
    if expect_json and isinstance(value, str):
        return safe_json_parse(state, key, default)

    return value

def handle_validation_failure(error: Exception, field_name: str, original_value: str) -> str:
    """Handle Pydantic validation failures with graceful truncation"""
    log_status(f"Validation failure on {field_name}: {str(error)[:200]}")

    if 'max_length' in str(error).lower() or 'should have at most' in str(error).lower():
        import re
        max_len_match = re.search(r'at most (\d+)', str(error))
        if max_len_match:
            max_len = int(max_len_match.group(1))
            truncated = original_value[:max_len-200] if len(original_value) > max_len else original_value
            suffix = f"\n[TRUNCATED - Original length: {len(original_value)} chars. Review raw logs for full output]"
            return truncated + suffix

    return str(original_value)[:1000] + "\n[TRUNCATED DUE TO VALIDATION ERROR]"

def save_session_results(state: dict, session_id: str):
    """Save complete session results to disk"""
    output_dir = Path("hunt_results")
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hunt_session_{session_id}_{timestamp}.json"
    filepath = output_dir / filename
    
    # Evaluate outputs for hallucinations using pattern-based + LLM validation
    try:
        hallucination_report = evaluate_outputs(state)
    except Exception as e:
        # Don't fail entire workflow if hallucination detection fails
        log_status(f"WARNING: Hallucination detection failed: {e}")
        print(f"\n[WARNING] Hallucination detection failed: {e}")

        # Create minimal fallback report
        from gcphunter_agent.tools.hallucination_detector import HallucinationReport, HallucinationCheck
        hallucination_report = HallucinationReport(
            overall_status='SUSPICIOUS',
            confidence_score=0.5,
            checks_performed=[HallucinationCheck(
                check_type='error_fallback',
                status='WARNING',
                confidence=0.0,
                details=f'Hallucination detection failed: {str(e)}',
                flagged_content=[]
            )],
            critical_flags=[f'Hallucination validation failed: {str(e)[:200]}'],
            recommendations=['Manual review recommended - automated validation unavailable']
        )

    # Use unified state accessor for consistent type handling
    hypothesis = get_state_value(state, 'hypothesis_json', expect_json=True, default={})
    hunt_commands = get_state_value(state, 'hunt_commands', expect_json=False, default={})
    hunt_results = get_state_value(state, 'hunt_results', expect_json=False, default={})
    final_report = get_state_value(state, 'final_hunt_report', expect_json=True, default={})

    # Filter low-confidence findings (hallucination risk >0.4)
    # Use deepcopy to avoid modifying original nested structures
    import copy
    filtered_report = copy.deepcopy(final_report) if final_report else {}
    if 'command_results' in filtered_report:
        original_count = len(filtered_report['command_results'])
        filtered_results = []
        for result in filtered_report['command_results']:
            risk = result.get('hallucination_risk', 0.0)
            if risk < 0.4:  # Only keep high-confidence findings
                filtered_results.append(result)
            else:
                log_status(f"Filtered result due to hallucination risk {risk:.2f}: TTP {result.get('ttp_id', 'unknown')}")

        filtered_report['command_results'] = filtered_results
        filtered_count = len(filtered_results)
        if original_count > filtered_count:
            print(f"\nFiltered {original_count - filtered_count} low-confidence results (hallucination risk >0.4)")
            log_status(f"Hallucination filtering: {original_count - filtered_count} results removed")

    session_report = {
        "session_id": session_id,
        "timestamp": timestamp,
        "hypothesis": hypothesis,
        "attack_path_analysis": state.get('attack_path_analysis', ''),
        "hunt_commands": hunt_commands,
        "hunt_results": hunt_results,
        "final_report": filtered_report,
        "validation": {
            "hallucination_check": hallucination_report.model_dump(),
            "validation_timestamp": timestamp
        }
    }
    
    #output checks
    print(f"\nHallucination Check: {hallucination_report.overall_status}")
    print(f"Confidence: {hallucination_report.confidence_score:.2%}")
    if hallucination_report.critical_flags:
        print(f"Critical Flags: {len(hallucination_report.critical_flags)}")
        for flag in hallucination_report.critical_flags[:3]:
            print(f"  - {flag}")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(session_report, f, indent=2, ensure_ascii=False)
    
    print(f"\nSession results saved to: {filepath}")
    
    # Inline guardrail: warn if critical hallucinations detected but continue to save results
    if hallucination_report.overall_status == 'HALLUCINATED':
        warning_msg = (
            f"HALLUCINATION DETECTED - Results may be unreliable.\n"
            f"Confidence: {hallucination_report.confidence_score:.2%}\n"
            f"Flags: {hallucination_report.critical_flags[:5]}"
        )
        print(f"\n[CRITICAL WARNING] {warning_msg}")
        log_status(f"CRITICAL: {warning_msg}")
        # Continue to save results for manual review rather than failing workflow
    
    return str(filepath)

#prompt external because clutters agent.py
with open('gcphunter_agent/prompts/hypothesis_agent_prompt.md', 'r', encoding='utf-8') as f:
    HYPOTHESIS_AGENT_PROMPT = f.read()
with open('gcphunter_agent/prompts/jsonformat_agent_prompt.md', 'r', encoding='utf-8') as f:
    JSONFORMAT_AGENT_PROMPT = f.read()
with open('gcphunter_agent/prompts/attackpath_agent_prompt.md', 'r', encoding='utf-8') as f:
    ATTACKPATH_AGENT_PROMPT = f.read()
with open('gcphunter_agent/prompts/searchconstructor_agent_prompt.md', 'r', encoding='utf-8') as f:
    SEARCHCONSTRUCTOR_AGENT_PROMPT = f.read()
with open('gcphunter_agent/prompts/execution_agent_prompt.md', 'r', encoding='utf-8') as f:
    EXECUTION_AGENT_PROMPT = f.read()
with open('gcphunter_agent/prompts/results_formatter_agent_prompt.md', 'r', encoding='utf-8') as f:
    RESULTS_FORMATTER_PROMPT = f.read()

#this prompt is for llm as a judge using callbacks to eval
with open('gcphunter_agent/prompts/hallucination_validator_agent_prompt.md', 'r', encoding='utf-8') as f:
    HALLUCINATION_VALIDATOR_PROMPT = f.read()

#ADK requires pydantic schema definitions if you use output_schema for things like logging, parsing, callback evals
class hypothesisOutput(BaseModel):
    hypothesis: str = Field(description='The hypothesis statement for cyber threat hunts.')

class PrioritizedTTP(BaseModel):
    ttp_rank: int
    ttp_id: str
    ttp_name: str
    indicators: List[str]
    feasibility: Literal['FEASIBLE', 'LIMITED', 'INFEASIBLE']

class GCPProjectSummary(BaseModel):
    project_id: str
    enabled_apis: List[str]
    logging_coverage: List[str]
    key_resources: Optional[str] = None

class AttackPathAnalysis(BaseModel):
    feasibility_assessment: Literal['FEASIBLE', 'LIMITED', 'INFEASIBLE']
    prioritized_hunt_ttps: List[PrioritizedTTP]
    gcp_project_summary: GCPProjectSummary
    reasoning: Optional[str] = Field(default=None, max_length=10000)
    blocking_factors: Optional[List[str]] = None

class HuntCommand(BaseModel):
    ttp_rank: int
    ttp_id: str
    ttp_name: str
    command: str = Field(max_length=5000)
    target_log_source: str
    hunt_indicators_count: int
    estimated_results: str = Field(max_length=2000)
    validation_status: Literal['READY', 'NEEDS_TUNING', 'BLOCKED']

class ExecutionBatch(BaseModel):
    batch_id: int
    log_source_type: str
    commands: List[HuntCommand]

class ExecutionMetadata(BaseModel):
    total_commands: int
    total_batches: int
    estimated_runtime_seconds: int
    parallel_execution_enabled: bool
    max_concurrent_batches: int

class ValidationSummary(BaseModel):
    ready_commands: int
    needs_tuning_commands: int
    blocked_commands: int

class SearchCommandsOutput(BaseModel):
    feasibility_assessment: Literal['READY', 'INFEASIBLE']
    execution_batches: Optional[List[ExecutionBatch]] = None
    execution_metadata: Optional[ExecutionMetadata] = None
    validation_summary: Optional[ValidationSummary] = None
    reasoning: Optional[str] = Field(default=None, max_length=10000)
    blocking_factors: Optional[List[str]] = None
    attempted_ttps: Optional[int] = None
    failed_ttps: Optional[int] = None

class CommandResult(BaseModel):
    ttp_rank: int
    ttp_id: str
    ttp_name: str
    command_executed: str
    execution_status: Literal['SUCCESS', 'ERROR', 'SKIPPED']
    log_entries_found: int
    findings_summary: str
    raw_output: Optional[str] = Field(default=None, max_length=50000)
    hallucination_risk: Optional[float] = Field(default=0.0, ge=0.0, le=1.0)
    evidence_file: Optional[str] = Field(default=None)  # Phase 2: Path to full evidence on disk
    raw_output_size_bytes: Optional[int] = Field(default=None)  # Phase 2: Full output size

class ExecutionSummary(BaseModel):
    commands_executed: int
    commands_skipped: int
    findings_detected: int
    overall_status: Literal['THREATS_DETECTED', 'CLEAN', 'ERRORS']

class ExecutionResults(BaseModel):
    """Schema for execution agent output"""
    execution_summary: ExecutionSummary
    command_results: List[CommandResult]
    critical_findings: List[str] = Field(default_factory=list)

class FinalHuntReport(BaseModel):
    hunt_status: Literal['COMPLETE', 'PARTIAL', 'FAILED']
    execution_summary: ExecutionSummary
    command_results: List[CommandResult]
    total_log_entries_analyzed: int
    total_security_findings: int
    critical_findings: List[str]
    recommendations: List[str]
    truncation_notice: Optional[str] = Field(default=None, max_length=1000)
    verification_commands: Optional[List[str]] = Field(default=None)
    evidence_directory: Optional[str] = Field(default=None)  # Phase 2: Base directory for all evidence files

# Shared retry config for 30k RPM quota - need longer delays for quota recovery
# Delays: 15s, 90s, 90s (capped), 90s, 90s - gives quota time to reset
AGGRESSIVE_RETRY_CONFIG = types.HttpOptions(
    retry_options=types.HttpRetryOptions(
        initial_delay=15,        # Increased from 10s - more time for quota recovery
        attempts=6,              # More attempts with capped delays
        exp_base=6,              # Reduced from 7 - but with higher initial (15s, 90s, 90s...)
        max_delay=92,            # Increased from 60s - longer recovery window
        http_status_codes=[429, 500, 503, 504]  # Retry on these errors
    )
)

# Flash model retry - still shares 30k RPM quota, needs conservative delays
FLASH_RETRY_CONFIG = types.HttpOptions(
    retry_options=types.HttpRetryOptions(
        initial_delay=8,         # Increased from 5s - shares same quota pool
        attempts=4,              # More attempts
        exp_base=3,              # Increased from 2 (8s, 24s, 72s, 72s)
        max_delay=72,            # Increased from 30s - align with quota recovery
        http_status_codes=[429, 500, 503, 504]
    )
)

safety_settings = [
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold=types.HarmBlockThreshold.BLOCK_NONE
    )
]

#define agents that point to tools, prompts, and parameters
#workflow agents do NOT use output_key the output key is just the index in state passed between regular agents
hypothesis_agent = Agent(
    model='gemini-2.5-pro',
    name='hypothesis_agent',
    description='Analyzes threat intelligence files and generates GCP threat hunting hypotheses',
    instruction=str(HYPOTHESIS_AGENT_PROMPT),
    tools=[FunctionTool(load_cti_files), GoogleSearchTool(bypass_multi_tools_limit=True)],  # No sanitization - runs before project enumeration
    generate_content_config=types.GenerateContentConfig(
        temperature=1,
        max_output_tokens=5000,
        safety_settings=safety_settings,
        http_options=AGGRESSIVE_RETRY_CONFIG  # Pro model needs aggressive retries
    ),
    planner=BuiltInPlanner(
        thinking_config=types.ThinkingConfig(
            include_thoughts=True,
            thinking_budget=5000
        )
    ),
    output_key='raw_hypothesis'
)

jsonformat_agent = Agent(
    model='gemini-2.5-flash',
    name='jsonformat_agent',
    description='Formats hypothesis agent output into valid JSON structure',
    instruction=str(JSONFORMAT_AGENT_PROMPT),
    generate_content_config=types.GenerateContentConfig(
        temperature=0.2,  # Lowered from 0.5 - deterministic formatting task
        max_output_tokens=5000,
        safety_settings=safety_settings,
        http_options=FLASH_RETRY_CONFIG  # Flash has better rate limits
    ),
    output_schema=hypothesisOutput,
    output_key='hypothesis_json'
)

attackpath_agent = Agent(
    model='gemini-2.5-pro',
    name='attackpath_agent',
    description='Maps attack paths and validates hunt feasibility against real GCP project configurations',
    instruction=str(ATTACKPATH_AGENT_PROMPT),
    tools=[FunctionTool(gcloud_read), SanitizedGoogleSearchTool(bypass_multi_tools_limit=True)],  # Sanitized - has project access
    generate_content_config=types.GenerateContentConfig(
        temperature=0.8,  # Lowered from 1.0 - structured thinking with creativity
        max_output_tokens=30000,
        safety_settings=safety_settings,
        http_options=AGGRESSIVE_RETRY_CONFIG  # Pro model needs aggressive retries
    ),
    planner=BuiltInPlanner(
        thinking_config=types.ThinkingConfig(
            include_thoughts=True,
            thinking_budget=5000
        )
    ),
    output_schema=AttackPathAnalysis,
    output_key='attack_path_analysis'
)

searchconstructor_agent = Agent(
    model='gemini-2.5-pro',
    name='searchconstructor_agent',
    description='Translates attack path TTPs into executable gcloud logging commands for threat hunting',
    instruction=str(SEARCHCONSTRUCTOR_AGENT_PROMPT),
    generate_content_config=types.GenerateContentConfig(
        temperature=0.4,  # Lowered from 1.0 - has output_schema, needs consistency
        max_output_tokens=30000,
        safety_settings=safety_settings,
        http_options=AGGRESSIVE_RETRY_CONFIG  # Pro model needs aggressive retries
    ),
    planner=BuiltInPlanner(
        thinking_config=types.ThinkingConfig(
            include_thoughts=True,
            thinking_budget=4096
        )
    ),
    output_schema=SearchCommandsOutput,
    output_key='hunt_commands'
)

#imperfect when using CLI allow it to reason and set multi shot examples in prompt. this is a balance
execution_agent = Agent(
    model='gemini-2.5-pro',
    name='execution_agent',
    description='Executes all threat hunt commands sequentially and analyzes results with retry logic',
    instruction=str(EXECUTION_AGENT_PROMPT),
    tools=[FunctionTool(gcloud_read)],
    generate_content_config=types.GenerateContentConfig(
        temperature=0.7,
        max_output_tokens=50000,
        safety_settings=safety_settings,
        response_mime_type='application/json',  # Enforce JSON output
        http_options=AGGRESSIVE_RETRY_CONFIG  # Pro model needs aggressive retries
    ),
    planner=BuiltInPlanner(
        thinking_config=types.ThinkingConfig(
            include_thoughts=True,
            thinking_budget=8000
        )
    ),
    output_schema=ExecutionResults,  # ADDED: Structured output schema
    output_key='hunt_results'
)

#ADK has bugs that make tools plus output schema go into infinite loop. idk why still not fixed 1.23.
#Removed output_schema to prevent Pydantic validation crashes on incomplete JSON
#Post-processing in safe_json_parse() handles validation and repair
results_formatter_agent = Agent(
    model='gemini-2.5-flash',
    name='results_formatter_agent',
    description='Formats execution results into structured final hunt report',
    instruction=str(RESULTS_FORMATTER_PROMPT),
    generate_content_config=types.GenerateContentConfig(
        temperature=0.3,
        max_output_tokens=65000,  # Increased from 52000 to reduce truncation
        safety_settings=safety_settings,
        response_mime_type='application/json',  # Hint for JSON format, but no schema validation
        http_options=FLASH_RETRY_CONFIG  # Flash has better rate limits
    ),
    # output_schema=FinalHuntReport,  # REMOVED - causes crash on incomplete JSON. Repaired post-hoc in safe_json_parse()
    output_key='final_hunt_report'  # Stores raw string, validated and repaired in save_session_results()
)

#fast pattern-based + LLM hallucination validator (runs AFTER workflow completes)
hallucination_validator_agent = Agent(
    model='gemini-2.5-flash',  # Fast model for quick validation
    name='hallucination_validator',
    description='Validates outputs for hallucinations and fabricated content',
    instruction=str(HALLUCINATION_VALIDATOR_PROMPT),
    generate_content_config=types.GenerateContentConfig(
        temperature=0.1,  #stricter validation
        max_output_tokens=3000,
        safety_settings=safety_settings,
        http_options=FLASH_RETRY_CONFIG  # Flash has better rate limits
    ),
    output_schema=HallucinationReport,
    output_key='hallucination_report'
)

#define workflows where they are an abstract using workflow agents of runtime order
hypothesis_workflow = SequentialAgent(
    name='cti_to_hypothesis',
    sub_agents=[hypothesis_agent, jsonformat_agent],
    description='Analyze CTI files and create formatted hypothesis'
)

attackpath_workflow = SequentialAgent(
    name='hypothesis_to_searchcommands',
    sub_agents=[attackpath_agent, searchconstructor_agent],
    description='Map attack paths and construct hunt commands'
)

#the ROOT agent is naming convention prefix that SHOULD be kept as the DEFAULT entrypoint for ADK to kick off
root_agent = SequentialAgent(
    name='auto_cti_hunting',
    sub_agents=[
        hypothesis_workflow,
        attackpath_workflow,
        execution_agent,
        results_formatter_agent
    ],
    description='Full workflow: CTI -> hypothesis -> attack paths -> hunt commands -> execute -> report'
)

# App with tool retry and auto-save plugins
app = App(
    name="gcphunter_agent",
    root_agent=root_agent,
    plugins=[
        EvidenceInitPlugin(),  # MUST run first to create evidence directory
        ReflectAndRetryToolPlugin(max_retries=2, throw_exception_if_retry_exceeded=False),  # 3 total attempts (matches prompt)
        AutoSaveResultsPlugin(save_callback=save_session_results)
    ],
    events_compaction_config=EventsCompactionConfig(
        compaction_interval=3,
        overlap_size=1
    )
)

#async workflow main dunder that only imports for memory purposes the runners for non interactive
#prints details and calls the funtion to a log file if you're not interactive in web for supprted hunts
if __name__ == "__main__":
    from google.adk.runners import InMemoryRunner
    from google.genai.types import Content, Part
    from google.api_core.exceptions import ResourceExhausted
    
    async def main():
        runner = InMemoryRunner(app=app)

        session = await runner.session_service.create_session(
            app_name='gcphunter_agent',
            user_id='user'
        )

        # Evidence directory initialization now handled by EvidenceInitPlugin (works for both CLI and ADK web)

        # Update timestamps for CLI mode - get fresh timestamps at execution time
        # Note: Module-level timestamps (set at import) are used by ADK web
        # CLI mode updates them here for accuracy at execution time
        current_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        fourteen_days_ago = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Update environment variables for CLI execution (gcloud_cli.py reads these)
        os.environ['CURRENT_UTC_TIME'] = current_utc
        os.environ['LOOKBACK_7_DAYS'] = seven_days_ago
        os.environ['LOOKBACK_3_DAYS'] = three_days_ago
        os.environ['LOOKBACK_14_DAYS'] = fourteen_days_ago

        message = Content(role='user', parts=[Part(text=f'''start

CURRENT_UTC_TIME: {current_utc}
LOOKBACK_7_DAYS: {seven_days_ago}
LOOKBACK_3_DAYS: {three_days_ago}
LOOKBACK_14_DAYS: {fourteen_days_ago}

Use these exact timestamps in gcloud logging queries. Do NOT calculate timestamps yourself.''')])

        last_event = None
        print("\n=== Starting GCPHunter Agent Workflow ===\n")
        print(f"Current UTC: {current_utc}")
        log_status(f"=== GCPHunter workflow started at {current_utc} ===")
        
        # Simple retry wrapper with exponential backoff for session-level retries
        max_retries = 3  # Reduced because agents have their own retry logic
        for attempt in range(max_retries):
            try:
                async for event in runner.run_async(
                    user_id='user',
                    session_id=session.id,
                    new_message=message
                ):
                    try:
                        last_event = event
                        
                        if hasattr(event, 'content') and event.content:
                            if hasattr(event.content, 'parts') and event.content.parts:
                                for part in event.content.parts:
                                    if hasattr(part, 'text') and part.text:
                                        print(f"\n[{getattr(event, 'author', 'AGENT')}]")
                                        print(part.text)
                                        print("#######################")
                        
                        if hasattr(event, 'tool_calls') and event.tool_calls:
                            for tool_call in event.tool_calls:
                                print(f"\n[TOOL CALL: {tool_call.name}]")
                                log_status(f"Tool call: {tool_call.name}")
                                if hasattr(tool_call, 'args'):
                                    print(f"Arguments: {tool_call.args}")
                                print("#######################")
                        
                        if hasattr(event, 'tool_responses') and event.tool_responses:
                            for tool_response in event.tool_responses:
                                print(f"\n[TOOL RESPONSE: {tool_response.name}]")
                                if hasattr(tool_response, 'response'):
                                    response_text = str(tool_response.response)
                                    if len(response_text) > 2000:
                                        print(f"{response_text[:2000]}...\n[TRUNCATED - {len(response_text)} total chars]")
                                    else:
                                        print(response_text)
                                print("#######################")
                    
                    except Exception as e:
                        print(f"\nWarning: Event processing error: {e}")
                        print("Continuing workflow...")
                        continue
                
                # If we got here without exception, workflow completed successfully
                break
                
            except ResourceExhausted as e:
                if attempt == max_retries - 1:
                    print(f"\nFailed after {max_retries} attempts due to rate limiting")
                    raise
                
                # Exponential backoff: 12s, 24s, 48s (longer delays for 30k RPM quota)
                delay = min(12.0 * (2 ** attempt), 60.0)  # Increased from 5s base
                jitter = random.uniform(0, delay * 0.1)
                total_delay = delay + jitter
                
                print(f"\nSession-level rate limit. Waiting {total_delay:.1f}s before retry {attempt + 1}/{max_retries}")
                await asyncio.sleep(total_delay)
                continue
        
        print("##########Threat Hunt Workflow Completed#########")
        log_status("=== Workflow completed successfully ===")

        try:
            # Retrieve final session state
            final_session = await runner.session_service.get_session(
                app_name='gcphunter_agent',
                user_id='user',
                session_id=session.id
            )
            log_status("Retrieving final session state...")
            
            # Save results to disk
            if final_session and hasattr(final_session, 'state') and final_session.state:
                output_file = save_session_results(final_session.state, session.id)
                print(f"Full hunt report saved: {output_file}")
                log_status(f"Results saved to: {output_file}")
            else:
                print("Warning: No session state available to save")
        
        except Exception as e:
            print(f"Warning: Could not save session results: {e}")        
        try:
            if last_event and hasattr(last_event, 'content'):
                final_output = last_event.content.parts[0].text
                print(f"\n=== FINAL OUTPUT ===")
                print(final_output)
                return final_output
        except (AttributeError, IndexError):
            print("No final output text generated")
            return None
    
    #run this thing
    final_output = asyncio.run(main())
    print("\n=== All done! ===")