"""Auto-save plugin for persisting hunt results to disk after workflow completion"""

from google.adk.plugins.base_plugin import BasePlugin
from google.adk.agents.callback_context import CallbackContext
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from google.adk.agents.invocation_context import InvocationContext


class AutoSaveResultsPlugin(BasePlugin):
    """Plugin that automatically saves session results to hunt_results/ directory

    This plugin hooks into the workflow lifecycle and persists results
    regardless of whether the agent runs via CLI or ADK web interface.
    """

    def __init__(self, save_callback: callable, name: str = "auto_save_results_plugin"):
        """Initialize plugin with callback function

        Args:
            save_callback: Function that takes (state: dict, session_id: str) and saves results
            name: Plugin name for identification
        """
        super().__init__(name=name)
        self.save_callback = save_callback
        self._saved_sessions = set()  # Track saved sessions to avoid duplicates

    async def after_agent_callback(
        self,
        *,
        agent: Any,
        callback_context: CallbackContext,
        **kwargs
    ) -> None:
        """Hook that runs after each agent completes

        Only saves results when the root agent (full workflow) completes.

        Args:
            agent: The agent that just completed
            callback_context: The callback context containing invocation details
        """
        # Only save when root agent completes (indicates full workflow done)
        # CallbackContext inherits from ReadonlyContext which provides direct access to session
        agent_name = callback_context.agent_name
        session = callback_context.session
        session_id = session.id

        if agent_name == 'auto_cti_hunting' and session_id not in self._saved_sessions:
            try:
                # Mark as saved immediately to prevent duplicate saves
                self._saved_sessions.add(session_id)

                # Get state from session directly to avoid MappingProxyType iteration issues
                state = {k: v for k, v in session.state.items()}  # Safe dict copy

                # Call save function (it handles all the filtering and validation)
                output_file = self.save_callback(state, session_id)

                print(f"\n[AUTO-SAVE] Hunt results saved: {output_file}")

                # Log to status file
                from gcphunter_agent.tools.status_logger import log_status
                log_status(f"Auto-saved results to: {output_file}")

            except Exception as e:
                print(f"\n[AUTO-SAVE] Warning: Could not save results: {e}")
                import traceback
                traceback.print_exc()
                # Don't raise - allow workflow to complete even if save fails

    async def after_run_callback(
        self,
        *,
        invocation_context: "InvocationContext",
        **kwargs
    ) -> None:
        """Fallback hook at invocation level if after_agent_callback doesn't trigger

        This ensures results are saved even if the agent-level hook fails.

        Args:
            invocation_context: The context for the entire invocation
        """
        session = invocation_context.session
        session_id = session.id

        if session_id not in self._saved_sessions:
            try:
                self._saved_sessions.add(session_id)

                # Get state from session
                state = dict(session.state)  # session.state is a dict

                output_file = self.save_callback(state, session_id)

                print(f"\n[AUTO-SAVE FALLBACK] Hunt results saved: {output_file}")

                from gcphunter_agent.tools.status_logger import log_status
                log_status(f"Auto-saved results (fallback) to: {output_file}")

            except Exception as e:
                print(f"\n[AUTO-SAVE FALLBACK] Warning: Could not save results: {e}")
                import traceback
                traceback.print_exc()
