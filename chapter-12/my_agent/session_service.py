"""Session service factory for Stage 7 Feedback Pipeline.

agent.py imports create_session_service at module load time.
Notebook callers always pass session_service= explicitly, so this
factory is only reached via adk web.
"""
from google.adk.sessions import InMemorySessionService


def create_session_service(persistent: bool = True):
    """Return an InMemorySessionService for adk web and evaluation use."""
    return InMemorySessionService()
