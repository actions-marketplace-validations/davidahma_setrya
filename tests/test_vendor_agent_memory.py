import unittest
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from subprocess import TimeoutExpired
from unittest.mock import patch

from setrya.core.inputs import save
from setrya.vendor import fixtures
from setrya.vendor.report import LOCAL_AGENT_TARGETS, OBSERVATION_FILE, PHASES, SETUP, TARGETS, derive


class AgentMemoryConformanceTests(unittest.TestCase):
    def test_report_requires_observations_and_retains_hosted_gap(self):
        for target in sorted(LOCAL_AGENT_TARGETS):
            with self.subTest(target=target):
                evidence = {
                    "target": target, "observed_at": "2026-11-25T00:00:00+00:00", "error": None,
                    "versions": {package: "1.0" for package in SETUP[target]},
                    "observations": {
                        phase: {surface: {"target": phase == "baseline", "retained": True}
                                for surface in TARGETS[target]}
                        for phase in PHASES
                    },
                }
                receipt = derive(evidence)
                self.assertEqual(receipt["technical_verdict"], "PASS")
                self.assertEqual(receipt["review_status"], "OPEN_ITEMS")
                self.assertEqual(receipt["certification"], "UNQUALIFIED")
                self.assertTrue({"provider-internals", "cache", "backups"}.issubset(
                    {item["store"] for item in receipt["open_items"]}
                ))
                retry = evidence["observations"]["after_retry"][TARGETS[target][0]]
                retry["target"] = None
                self.assertEqual(derive(evidence)["technical_verdict"], "NOT TESTED")
                retry["target"] = True
                self.assertEqual(derive(evidence)["technical_verdict"], "FAIL")

    def test_missing_extra_stays_not_tested(self):
        with patch.object(fixtures, "agent_memory", side_effect=PackageNotFoundError("openai-agents")):
            evidence = fixtures.run_fixture("openai-agents-session")
        self.assertEqual(derive(evidence)["technical_verdict"], "NOT TESTED")

    def test_completed_residual_survives_a_retry_timeout(self):
        def stop_during_retry(command, *, cwd, timeout, **_):
            present = {"session-history": {"target": True, "retained": True}}
            save({"versions": {"openai-agents": "0.25.0", "sqlite": "3.50.4"},
                  "observations": {"baseline": present, "after_delete": present}, "error": None},
                 Path(cwd) / OBSERVATION_FILE)
            raise TimeoutExpired(command, timeout)

        with patch.object(fixtures.subprocess, "run", side_effect=stop_during_retry):
            receipt = derive(fixtures.run_fixture("openai-agents-session"))
        self.assertEqual(receipt["technical_verdict"], "FAIL")
        self.assertEqual(receipt["checks"][0]["status"], "FAIL")
