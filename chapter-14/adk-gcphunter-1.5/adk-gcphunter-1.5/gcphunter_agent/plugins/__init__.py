"""Custom ADK plugins for GCPHunter agent"""

from .auto_save_plugin import AutoSaveResultsPlugin
from .evidence_init_plugin import EvidenceInitPlugin

__all__ = ['AutoSaveResultsPlugin', 'EvidenceInitPlugin']
