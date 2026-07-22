"""Hallucination detection for GCP threat hunting outputs"""
from typing import Dict, List, Literal
from pydantic import BaseModel, Field
import re

class HallucinationCheck(BaseModel):
    """Schema for hallucination detection results"""
    check_type: str = Field(description="Type of validation check performed")
    status: Literal['PASS', 'FAIL', 'WARNING']
    confidence: float = Field(description="Confidence score 0-1")
    details: str = Field(description="Explanation of findings")
    flagged_content: List[str] = Field(default_factory=list, description="Suspicious content found")

class HallucinationReport(BaseModel):
    """Complete hallucination analysis report"""
    overall_status: Literal['CLEAN', 'SUSPICIOUS', 'HALLUCINATED']
    confidence_score: float = Field(description="Overall confidence 0-1")
    checks_performed: List[HallucinationCheck]
    critical_flags: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

# Known valid GCP patterns
VALID_GCLOUD_COMMANDS = [
    r'^gcloud\s+logging\s+read\s+',
    r'^gcloud\s+projects\s+list',
    r'^gcloud\s+services\s+list',
    r'^gcloud\s+iam\s+',
    r'^gcloud\s+compute\s+',
    r'^gcloud\s+storage\s+',
    r'^gcloud\s+auth\s+'
]

VALID_LOG_FILTERS = [
    'protoPayload', 'timestamp', 'severity', 'resource.type',
    'logName', 'jsonPayload', 'labels', 'insertId', 'httpRequest'
]

INVALID_PATTERNS = [
    r'gcloud\s+hack\s+',
    r'gcloud\s+exploit\s+',
    r'gcloud\s+malware\s+',
    r'\$\{.*\}',  # Variable substitution (not valid in gcloud)
    r'--password\s+',  # gcloud doesn't use passwords
    r'sudo\s+gcloud',  # Never needed
]

def pattern_based_validation(text: str) -> HallucinationCheck:
    """Fast regex-based validation of gcloud commands"""
    flagged = []
    
    # Check for invalid patterns
    for pattern in INVALID_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            flagged.append(f"Invalid pattern: {pattern}")
    
    # Extract gcloud commands
    commands = re.findall(r'gcloud\s+[\w\s\-\.=\'"]+', text)
    
    invalid_commands = []
    for cmd in commands:
        # Check if matches valid patterns
        valid = any(re.match(pattern, cmd) for pattern in VALID_GCLOUD_COMMANDS)
        if not valid:
            invalid_commands.append(cmd)
    
    if flagged or invalid_commands:
        return HallucinationCheck(
            check_type="pattern_validation",
            status="FAIL",
            confidence=0.9,
            details=f"Found {len(flagged + invalid_commands)} suspicious patterns",
            flagged_content=flagged + invalid_commands
        )
    
    return HallucinationCheck(
        check_type="pattern_validation",
        status="PASS",
        confidence=0.95,
        details="All commands match valid GCP patterns",
        flagged_content=[]
    )

def calculate_finding_risk(finding_text: str, tool_output: str) -> float:
    """Calculate hallucination risk for a specific finding

    Args:
        finding_text: The finding/claim being evaluated
        tool_output: The actual tool output from execution

    Returns:
        float: Risk score 0.0-1.0 (0=verified, 1=likely fabricated)
    """
    risk = 0.0

    # Extract potential claims from finding
    # Look for specific assertions like "detected", "found", "discovered"
    if any(word in finding_text.lower() for word in ['detected', 'found', 'discovered', 'identified']):
        # Extract quoted strings, IPs, usernames, timestamps
        quoted_items = re.findall(r'["\']([^"\']+)["\']', finding_text)
        ip_addresses = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', finding_text)
        usernames = re.findall(r'[\w\.-]+@[\w\.-]+', finding_text)

        # Check if these appear in tool output
        all_claims = quoted_items + ip_addresses + usernames
        for claim in all_claims:
            if claim and claim not in tool_output:
                risk += 0.15  # Each unverified claim adds risk

    # Check for unrealistic values
    large_numbers = re.findall(r'\b\d{10,}\b', finding_text)
    if large_numbers:
        risk += 0.2  # Suspiciously large numbers

    # Check for impossible timestamps
    if re.search(r'T([2-9]\d|99):', finding_text):  # Hour > 23
        risk += 0.3

    # Check for invalid month/day
    if re.search(r'-(1[3-9]|[2-9]\d)-', finding_text):  # Month > 12
        risk += 0.3

    return min(risk, 1.0)

def logical_consistency_check(hunt_commands: Dict, hunt_results: str) -> HallucinationCheck:
    """Check if results match the commands that were executed"""
    flagged = []
    
    try:
        # Extract command count
        if isinstance(hunt_commands, dict):
            batches = hunt_commands.get('execution_batches', [])
            expected_commands = sum(len(b.get('commands', [])) for b in batches)
        else:
            expected_commands = 0
        
        # Check if results mention commands not in hunt_commands
        result_commands = re.findall(r'gcloud\s+[\w\s\-\.=\'"]+', hunt_results)

        # Filter out legitimate placeholders (not actual executed commands)
        legitimate_placeholders = [
            'gcloud config get-value project',  # Used in $(gcloud config get-value project) placeholder
        ]
        result_commands = [cmd for cmd in result_commands if not any(placeholder in cmd for placeholder in legitimate_placeholders)]

        if len(result_commands) > expected_commands * 2:
            flagged.append(f"Results contain {len(result_commands)} commands but only {expected_commands} were planned")
        
        if flagged:
            return HallucinationCheck(
                check_type="logical_consistency",
                status="WARNING",
                confidence=0.7,
                details="Potential mismatch between planned and executed commands",
                flagged_content=flagged
            )
        
        return HallucinationCheck(
            check_type="logical_consistency",
            status="PASS",
            confidence=0.85,
            details="Results align with planned commands",
            flagged_content=[]
        )
    
    except Exception as e:
        return HallucinationCheck(
            check_type="logical_consistency",
            status="WARNING",
            confidence=0.5,
            details=f"Could not validate: {e}",
            flagged_content=[]
        )

def evaluate_outputs(state: Dict) -> HallucinationReport:
    """
    Main evaluation function - checks all outputs for hallucinations
    
    Args:
        state: The workflow state dictionary containing all agent outputs
    
    Returns:
        HallucinationReport with validation results
    """
    checks = []
    critical_flags = []
    
    # 1. Validate hunt commands
    hunt_commands = state.get('hunt_commands', {})
    if hunt_commands:
        hunt_commands_str = str(hunt_commands)
        pattern_check = pattern_based_validation(hunt_commands_str)
        checks.append(pattern_check)
        
        if pattern_check.status == "FAIL":
            critical_flags.extend(pattern_check.flagged_content)
    
    # 2. Validate hunt results
    hunt_results = state.get('hunt_results', '')
    hunt_results_str = str(hunt_results) if hunt_results else ''  # Convert to string (may be dict or str)

    if hunt_results:
        results_pattern_check = pattern_based_validation(hunt_results_str)
        checks.append(results_pattern_check)

        if results_pattern_check.status == "FAIL":
            critical_flags.extend(results_pattern_check.flagged_content)

    # 3. Cross-validate commands vs results
    if hunt_commands and hunt_results:
        consistency_check = logical_consistency_check(hunt_commands, hunt_results_str)
        checks.append(consistency_check)

        if consistency_check.status == "FAIL":
            critical_flags.extend(consistency_check.flagged_content)
    
    # Calculate overall status
    fail_count = sum(1 for c in checks if c.status == "FAIL")
    warning_count = sum(1 for c in checks if c.status == "WARNING")
    
    if fail_count > 0:
        overall_status = "HALLUCINATED"
        confidence = 0.3
    elif warning_count > 1:
        overall_status = "SUSPICIOUS"
        confidence = 0.6
    else:
        overall_status = "CLEAN"
        confidence = 0.9
    
    # Generate recommendations
    recommendations = []
    if fail_count > 0:
        recommendations.append("Review flagged commands manually before execution")
        recommendations.append("Consider regenerating hunt commands with stricter validation")
    if warning_count > 0:
        recommendations.append("Verify logical consistency of results")
    
    return HallucinationReport(
        overall_status=overall_status,
        confidence_score=confidence,
        checks_performed=checks,
        critical_flags=critical_flags,
        recommendations=recommendations
    )