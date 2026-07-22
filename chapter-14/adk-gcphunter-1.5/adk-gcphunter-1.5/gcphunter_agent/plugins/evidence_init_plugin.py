"""Plugin to initialize evidence directory before hunt starts"""

from google.adk.plugins.base_plugin import BasePlugin
from google.adk.agents.invocation_context import InvocationContext
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


class EvidenceInitPlugin(BasePlugin):
    """Initialize evidence directory at start of hunt workflow

    This runs before any agents execute, ensuring evidence storage
    is available regardless of invocation method (adk run vs python -m).
    """

    def __init__(self, name: str = "evidence_init_plugin"):
        super().__init__(name=name)
        self._initialized = False

    async def before_run_callback(
        self,
        *,
        invocation_context: InvocationContext,
        **kwargs
    ) -> None:
        """Initialize evidence directory before workflow starts"""

        if self._initialized:
            return  # Already initialized

        try:
            from gcphunter_agent.tools.gcloud_cli import set_evidence_directory

            # Create evidence directory with timestamp
            session_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            evidence_dir = Path("hunt_results") / f"raw_evidence_{session_timestamp}"
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Set global evidence directory
            set_evidence_directory(evidence_dir)

            print(f"[EVIDENCE INIT] Evidence directory: {evidence_dir}")

            from gcphunter_agent.tools.status_logger import log_status
            log_status(f"Evidence will be saved to: {evidence_dir}")

            self._initialized = True

        except Exception as e:
            print(f"[EVIDENCE INIT] Warning: Could not initialize evidence directory: {e}")
            import traceback
            traceback.print_exc()
            # Don't raise - allow workflow to continue without evidence storage
