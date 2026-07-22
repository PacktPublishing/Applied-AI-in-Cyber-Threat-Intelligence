import subprocess
import shlex
import os
import platform
import re
import time
import json
from pathlib import Path
from datetime import datetime

# Global evidence tracking for this hunt session
_EVIDENCE_DIR = None
_EVIDENCE_COUNTER = 0

def set_evidence_directory(evidence_dir: Path):
    """Set global evidence directory for this hunt session"""
    global _EVIDENCE_DIR, _EVIDENCE_COUNTER
    _EVIDENCE_DIR = evidence_dir
    _EVIDENCE_COUNTER = 0
    print(f"[EVIDENCE] Saving gcloud outputs to: {evidence_dir}")


def save_raw_evidence(command: str, output: str) -> dict:
    """Save gcloud output to evidence file and return metadata"""
    global _EVIDENCE_COUNTER
    _EVIDENCE_COUNTER += 1

    # Extract operation name from command for descriptive filename
    ttp_match = re.search(r'methodName[=~]"([^"]+)"', command)
    if ttp_match:
        operation = ttp_match.group(1).split('.')[-1]  # Get last part (e.g., CreateServiceAccount)
    else:
        # Fallback: Try to extract from command type
        if "gcloud compute instances" in command:
            operation = "compute_instances"
        elif "gcloud iam service-accounts" in command:
            operation = "iam_service_accounts"
        else:
            operation = "unknown"

    filename = f"cmd_{_EVIDENCE_COUNTER:03d}_{operation}.json"
    filepath = _EVIDENCE_DIR / filename

    # Save structured evidence
    evidence_data = {
        "command": command,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "output": output,
        "size_bytes": len(output),
        "execution_order": _EVIDENCE_COUNTER
    }

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(evidence_data, f, indent=2, ensure_ascii=False)

    print(f"[EVIDENCE] Saved {len(output):,} bytes → {filename}")

    return {
        "evidence_file": str(filepath),
        "filename": filename,
        "size_bytes": len(output)
    }


ALLOWED_COMMANDS = [
    "gcloud compute instances list",
    "gcloud compute networks list",
    "gcloud compute firewall-rules list",
    "gcloud iam service-accounts list",
    "gcloud projects get-iam-policy",
    "gcloud projects list",
    "gcloud services list",
    "gcloud logging read",
    "gcloud logging sinks list",
    "gcloud storage buckets list",
    "gcloud functions list",
    "gcloud run services list",
    "gcloud container clusters list",
    "gcloud asset search-all-resources",
    "gcloud resource-manager org-policies list",
    "gcloud access-context-manager policies list",
    "gcloud access-context-manager perimeters list",
    "gcloud access-context-manager perimeters describe",
    "gcloud scc findings list",
    "gcloud scc sources list",
    "gcloud scc sources describe",
    "gcloud iam roles list",
    "gcloud iam service-accounts keys list",
    "gcloud organizations get-iam-policy",
    "gcloud logging buckets list",
    "gcloud logging views list",
    "gcloud compute zones list",
    "gcloud compute regions list",
    "gcloud compute disks list",
    "gcloud compute images list",
    "gcloud sql instances list",
    "gcloud run revisions list",
    "gcloud container node-pools list",
    "gcloud secrets list",
    "gcloud artifacts repositories list",
    "gcloud organizations list",
]

SHELL_INJECTION = ["&&", "||", ";", "`", "$(", "\n", "\r"]


def gcloud_read(command: str) -> dict:
    """
    Execute read-only gcloud commands safely (cross-platform).

    Automatically replaces PROJECT_ID placeholder with GOOGLE_CLOUD_PROJECT env var.

    Args:
        command: gcloud command string (e.g., "gcloud compute instances list")

    Returns:
        dict: {"result": "output or error message"}

    Security:
        - Allowlist-based command validation
        - Shell injection pattern blocking
        - No destructive operations permitted
    """
    print(f"[GCLOUD TOOL] Executing: {command[:100]}...")  # Debug logging

    # Get and validate project ID
    gcp_project_id = os.environ.get('GOOGLE_CLOUD_PROJECT')
    if not gcp_project_id:
        print("[GCLOUD TOOL] ERROR: GOOGLE_CLOUD_PROJECT not set")
        return {"result": "ERROR: GOOGLE_CLOUD_PROJECT environment variable not set"}

    if not re.match(r'^[a-z0-9\-_]+$', gcp_project_id, re.IGNORECASE):
        print(f"[GCLOUD TOOL] ERROR: Invalid project ID format: {gcp_project_id}")
        return {"result": f"ERROR: Invalid project ID format: {gcp_project_id}"}

    # Replace PROJECT_ID placeholder
    command = command.replace('PROJECT_ID', gcp_project_id)

    # Replace LOOKBACK timestamp placeholders
    lookback_replacements = {
        'LOOKBACK_7_DAYS': os.environ.get('LOOKBACK_7_DAYS', ''),
        'LOOKBACK_3_DAYS': os.environ.get('LOOKBACK_3_DAYS', ''),
        'LOOKBACK_14_DAYS': os.environ.get('LOOKBACK_14_DAYS', ''),
        'CURRENT_UTC_TIME': os.environ.get('CURRENT_UTC_TIME', '')
    }

    for placeholder, value in lookback_replacements.items():
        if placeholder in command:
            if not value:
                print(f"[GCLOUD TOOL] ERROR: {placeholder} environment variable not set")
                return {"result": f"ERROR: {placeholder} environment variable not set. Contact administrator."}
            command = command.replace(placeholder, f'"{value}"')

    # Validate no unresolved placeholders remain
    if 'LOOKBACK_' in command or 'CURRENT_UTC' in command:
        print(f"[GCLOUD TOOL] ERROR: Unresolved timestamp placeholder in command")
        return {"result": "ERROR: Unresolved timestamp placeholder in command. Contact administrator."}

    # Must start with gcloud
    if not command.strip().startswith("gcloud "):
        print(f"[GCLOUD TOOL] ERROR: Command doesn't start with 'gcloud': {command[:50]}")
        return {"result": f"ERROR: Command must start with 'gcloud'"}

    # Block shell injection patterns
    for pattern in SHELL_INJECTION:
        if pattern in command:
            print(f"[GCLOUD TOOL] ERROR: Shell injection pattern '{pattern}' detected")
            return {"result": f"ERROR: Blocked shell injection pattern detected: {pattern}"}

    # Block unquoted pipes (simple check - pipe followed by space and word)
    if re.search(r'\|\s+\w', command):
        # Additional check: ensure it's not inside quotes
        # This is a simple heuristic - pipes in filters should have quotes around entire filter
        if not re.search(r'''['"][^'"]*\|[^'"]*['"]''', command):
            print(f"[GCLOUD TOOL] ERROR: Unquoted pipe detected in: {command[:50]}")
            return {"result": "ERROR: Unquoted pipe detected (potential command chaining)"}

    # Allowlist validation (prefix match)
    if not any(command.strip().startswith(allowed) for allowed in ALLOWED_COMMANDS):
        print(f"[GCLOUD TOOL] ERROR: Command not in allowlist: {command[:50]}")
        return {"result": f"ERROR: Command not in allowlist. Command: {command[:100]}"}
    
    # Add JSON format if not present
    if "--format" not in command:
        command += " --format json"
    
    # Add project flag for logging commands if not present
    if "gcloud logging read" in command and "--project" not in command:
        command += f" --project {gcp_project_id}"
    
    # Platform-specific execution
    is_windows = platform.system() == "Windows"

    try:
        print(f"[GCLOUD TOOL] Running on {'Windows' if is_windows else 'Unix'}...")

        if is_windows:
            # Windows: gcloud.cmd is a batch file that requires shell=True
            # Security: Command is validated via allowlist and injection pattern blocking before reaching here
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=45,  # Reduced to 45s to fail faster and avoid network timeouts
                env=os.environ.copy()
            )
        else:
            # Linux/Mac: Use shell=False for security
            result = subprocess.run(
                shlex.split(command),
                shell=False,
                capture_output=True,
                text=True,
                timeout=45,  # Reduced to 45s to fail faster and avoid network timeouts
                env=os.environ.copy()
            )

        print(f"[GCLOUD TOOL] Command completed with exit code {result.returncode}")

        # Add delay before returning to prevent API rate limit bursts (RPM shared quota)
        # This throttles the agent's next API call when processing this tool response
        # Increased to 2.5s for Option B: more conservative quota management with 3 retry attempts
        time.sleep(2.5)  # Conservative delay between gcloud tool calls

        if result.returncode == 0:
            output = result.stdout or "Command executed successfully (no output)"

            # Save to evidence file if directory configured (Phase 2: Evidence storage)
            if _EVIDENCE_DIR:
                evidence_meta = save_raw_evidence(command, output)

                # Return preview + metadata (reduces token consumption by ~90%)
                PREVIEW_SIZE = 3000  # 3KB preview for agent analysis
                preview = output[:PREVIEW_SIZE]
                if len(output) > PREVIEW_SIZE:
                    preview += f"\n\n[OUTPUT PREVIEW - Full output ({len(output):,} bytes) saved to: {evidence_meta['filename']}]"

                return {
                    "result": preview,
                    "evidence_file": evidence_meta['evidence_file'],
                    "output_size_bytes": evidence_meta['size_bytes'],
                    "_full_output_available": True
                }
            else:
                # Fallback: No evidence directory configured (shouldn't happen in normal operation)
                # Truncate very large outputs to prevent ADK web interface issues
                if len(output) > 120000:  # 120KB limit
                    print(f"[GCLOUD TOOL] WARNING: Output truncated from {len(output)} to 120000 chars")
                    output = output[:120000] + f"\n\n[OUTPUT TRUNCATED - Original size: {len(output)} chars. Use --limit flag or add filters to reduce output.]"
                return {"result": output}
        else:
            error_msg = f"Command failed (exit code {result.returncode})"
            if result.stderr:
                stderr_truncated = result.stderr[:10000]  # Limit stderr to 10KB
                error_msg += f"\n{stderr_truncated}"
                if len(result.stderr) > 10000:
                    error_msg += f"\n[STDERR TRUNCATED - Original size: {len(result.stderr)} chars]"
            print(f"[GCLOUD TOOL] ERROR: {error_msg[:200]}...")
            return {"result": error_msg}

    except subprocess.TimeoutExpired as e:
        print(f"[GCLOUD TOOL] TIMEOUT: Command exceeded 45 seconds")
        time.sleep(2.5)  # Throttle even on errors (Option B: conservative quota management)
        return {"result": f"ERROR: Command timed out after 45 seconds. Query may be too broad - try adding --limit or narrower filters. Command: {command[:100]}"}

    except FileNotFoundError as e:
        print(f"[GCLOUD TOOL] ERROR: gcloud CLI not found - {e}")
        time.sleep(2.5)  # Throttle even on errors (Option B: conservative quota management)
        return {"result": "ERROR: gcloud CLI not found. Install Google Cloud SDK or check PATH"}

    except Exception as e:
        # Catch-all for unexpected errors (network issues, permission errors, etc.)
        error_detail = f"{type(e).__name__}: {str(e)}"
        print(f"[GCLOUD TOOL] UNEXPECTED ERROR: {error_detail}")
        time.sleep(2.5)  # Throttle even on errors (Option B: conservative quota management)
        return {"result": f"ERROR: {error_detail}\nCommand: {command[:100]}"}