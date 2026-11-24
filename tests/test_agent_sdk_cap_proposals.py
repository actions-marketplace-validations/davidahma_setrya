"""Qualification reports eligible SDK caps without editing the package requirements."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest

SPEC = spec_from_file_location("sdk_caps", Path(__file__).resolve().parents[1] / "scripts/check-latest-agent-sdks.py")
sdk_caps = module_from_spec(SPEC)
SPEC.loader.exec_module(sdk_caps)


class QualifiedBounds(unittest.TestCase):
    def test_only_a_successfully_qualified_newer_minor_is_proposed(self):
        current = {
            "agent-openai": ["openai-agents>=0.25,<0.26"],
            "agent-claude": ["claude-agent-sdk>=0.2.187,<0.3"],
            "traces-langfuse": ["langfuse>=5.2,<5.3"],
        }
        selected = {"openai-agents": "0.26.1", "claude-agent-sdk": "0.2.190", "langfuse": "5.2.4",
                    "langgraph": "1.2.24"}
        result = sdk_caps.proposals(selected, current)
        self.assertEqual(result["qualified"], selected)
        self.assertEqual(result["cap_proposals"], {"agent-openai": {
            "package": "openai-agents", "qualified_version": "0.26.1", "current": "openai-agents>=0.25,<0.26",
            "suggested": "openai-agents>=0.25,<0.27",
        }})
        self.assertEqual(current["agent-openai"], ["openai-agents>=0.25,<0.26"])
