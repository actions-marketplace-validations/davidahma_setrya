"""Qualify the provider contracts locally with synthetic transports."""

import json
import sys
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from http.client import IncompleteRead
from importlib.resources import files
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from setrya.casework import profiles
from setrya.core.inputs import InvalidReport
from setrya.receipts import replay
from setrya.vendor import cli, hosted, report


class ProviderReadbackTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(TemporaryDirectory()))
        self.baseline = self.path / "before.json"
        self.bundle = self.path / "after"
        self.enterContext(patch.dict("os.environ", {
            "SETRYA_OPENAI_API_KEY": "synthetic-read-only-token",
            "SETRYA_ANTHROPIC_API_KEY": "synthetic-claude-token",
            "SETRYA_LETTA_API_KEY": "synthetic-letta-token",
            "SETRYA_MEM0_API_KEY": "synthetic-mem0-token",
        }))

    def test_signed_pipeline_uses_same_scoped_ids_and_replays_without_transport(self):
        responses = [
            {"data": [{"id": "file-target"}, {"id": "file-control"}], "has_more": False},
            {"data": [{"id": "file-first"}], "has_more": True, "last_id": "file-first"},
            {"data": [{"id": "file-control", "secret": "ignore returned content"}], "has_more": False},
        ]
        key = self.path / "local.key"
        key.touch()
        pair = ["--scope", "vector-01", "--record", "file-target", "--retain", "file-control"]
        with (
            patch.object(hosted, "_json_get", side_effect=responses) as get,
            patch("setrya.core.signing.sign_bytes", side_effect=lambda raw, path, **kw: path.write_bytes(b"test signature")),
            redirect_stdout(StringIO()),
        ):
            self.assertEqual(cli.command(["baseline", "--target", "openai-vector-files", "--synthetic",
                                          "--output", str(self.baseline), *pair]), 0)
            self.assertEqual(cli.command(["readback", str(self.baseline), "--after-delete", "--key", str(key),
                                          "--output", str(self.bundle), *pair]), 0)
        self.assertEqual(get.call_count, 3)
        origin, headers, route, query = get.call_args.args
        self.assertEqual(origin, "https://api.openai.com")
        self.assertEqual(headers["Authorization"], "Bearer synthetic-read-only-token")
        self.assertEqual(route, "/v1/vector_stores/vector-01/files")
        self.assertEqual(query["after"], "file-first")
        self.assertTrue((self.bundle / "conformance.sig").is_file())
        with patch.object(hosted, "_json_get", side_effect=AssertionError("replay is offline")):
            result = replay(self.bundle)
        self.assertEqual(result["technical_verdict"], "PASS")
        self.assertEqual(result["review_status"], "OPEN_ITEMS")
        self.assertIn("provider-internals", {item["store"] for item in result["open_items"]})
        for path in self.bundle.glob("*.json"):
            content = path.read_text()
            for raw in ("file-target", "file-control", "vector-01", "synthetic-read-only-token",
                        "ignore returned content", "principal_sha256"):
                self.assertNotIn(raw, content)
        try:
            import jsonschema
        except ImportError:
            return
        source = files("setrya.erasure").joinpath("receipt-v3.schema.json").read_text()
        jsonschema.Draft202012Validator(json.loads(source), format_checker=jsonschema.FormatChecker()).validate(result)

    def test_direct_non_success_cannot_establish_absence(self):
        for code in (302, 401, 403, 404, 429, 500):
            with self.subTest(code=code):
                key, url = "synthetic-opaque-key", "https://api.openai.com/v1/responses/response-target"
                opener = MagicMock()
                opener.open.side_effect = HTTPError(url, code, "provider details", {}, None)
                with patch.object(hosted, "build_opener", return_value=opener) as construct:
                    result = hosted._json_get("https://api.openai.com", {"Authorization": f"Bearer {key}"},
                                              "/v1/responses/response-target", {})
                self.assertIsNone(result)
                self.assertEqual(opener.open.call_args.args[0].get_method(), "GET")
                self.assertIsNone(construct.call_args.args[0].redirect_request(None, None, code, "", {}, ""))

        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.side_effect = IncompleteRead(b"[]")
        with patch.object(hosted, "build_opener", return_value=opener):
            self.assertIsNone(hosted._json_get("https://api.openai.com", {}, "/v1/files", {}))

        with patch.object(hosted, "_json_get", side_effect=[
            {"id": "response-1", "object": "response"}, {"id": "response-2", "object": "response"},
            None, {"id": "response-2", "object": "response"},
        ]):
            hosted.capture("openai-responses", None, "response-1", "response-2", self.baseline)
            evidence = hosted.follow(self.baseline, None, "response-1", "response-2")
        self.assertEqual(report.derive(evidence)["technical_verdict"], "NOT TESTED")

    def test_input_and_identity_changes_are_rejected_before_credential_use(self):
        with patch.object(hosted, "_json_get", side_effect=[
            {"id": "conv-01", "object": "conversation"}, {"id": "conv-02", "object": "conversation"},
        ]):
            hosted.capture("openai-conversations", None, "conv-01", "conv-02", self.baseline)
        with patch.object(hosted, "_json_get", side_effect=AssertionError("do not read another pair")):
            with self.assertRaisesRegex(InvalidReport, "differs"):
                hosted.follow(self.baseline, None, "conv-01", "conv-other")
            with self.assertRaisesRegex(InvalidReport, "distinct opaque"):
                hosted.follow(self.baseline, None, "../other", "conv-02")
            with (
                patch.dict("os.environ", {"SETRYA_OPENAI_API_KEY": "new-synthetic-token"}),
                self.assertRaisesRegex(InvalidReport, "same authorized"),
            ):
                hosted.follow(self.baseline, None, "conv-01", "conv-02")

    def test_incomplete_listing_preserves_positive_observation_and_leaves_unknown(self):
        for returns in (
            [(["control"], "next"), (None, None)],
            [(["control"], "next"), (["control"], None)],
            [(["control"], "next"), ([], "next")],
            [],
        ):
            get = MagicMock(side_effect=returns)
            with self.subTest(returns=returns):
                if not returns:
                    get = MagicMock(side_effect=lambda cursor: ([], f"next-{cursor}"))
                result = hosted._tracked(("target", "control"), get)
                self.assertIsNone(result["target"])
                self.assertIs(result["retained"], True if returns else None)

    def test_claude_cursor_and_letta_nested_listing(self):
        for target, scope, path, domain, before, after in (
            ("anthropic-files", None, "/v1/files", "api.anthropic.com",
             {"data": [{"id": "target"}, {"id": "control"}], "next_page": None},
             {"data": [{"id": "control"}], "next_page": None}),
            ("anthropic-session-events", "session-01", "/v1/sessions/session-01/events", "api.anthropic.com",
             {"data": [{"id": "target"}, {"id": "control"}], "next_page": None},
             {"data": [{"id": "control"}], "next_page": None}),
            ("letta-archival", "agent-01", "/v1/agents/agent-01/archival-memory", "api.letta.com",
             [{"id": "target"}, {"id": "control"}], [{"id": "control"}]),
        ):
            with self.subTest(target=target), patch.object(hosted, "_json_get", side_effect=[before, after]) as get:
                first = self.path / f"{target}.json"
                hosted.capture(target, scope, "target", "control", first)
                evidence = hosted.follow(first, scope, "target", "control")
                self.assertEqual(report.derive(evidence)["technical_verdict"], "PASS")
                origin, headers, route, _ = get.call_args.args
                self.assertEqual(origin, f"https://{domain}")
                self.assertEqual(route, path)
                if target == "anthropic-session-events":
                    self.assertEqual(headers["anthropic-beta"], "managed-agents-2026-04-01")

    def test_mem0_history_content_does_not_expose_response_text(self):
        def row(identifier):
            return {"id": "event", "memory_id": identifier, "old_memory": "synthetic original text"}

        with patch.object(hosted, "_json_get", side_effect=[
            [row("target")], [row("control")], [row("target")], [row("control")],
        ]) as get:
            hosted.capture("mem0-hosted-history", None, "target", "control", self.baseline)
            evidence = hosted.follow(self.baseline, None, "target", "control")
        self.assertEqual(get.call_args.args[1]["Authorization"], "Token synthetic-mem0-token")
        self.assertEqual(report.derive(evidence)["technical_verdict"], "FAIL")
        self.assertNotIn("synthetic original text", json.dumps(evidence))

    def test_mem0_history_needs_a_recognized_clean_response_to_pass(self):
        clean = {"id": "event", "memory_id": "target", "input": [], "old_memory": None, "new_memory": ""}
        cases = (
            ([], "PASS"), ([clean], "PASS"),
            ([{**clean, "old_memory": 1}], "NOT TESTED"),
            ([{**clean, "new_memory": False}], "NOT TESTED"),
            ([{**clean, "input": {}}], "NOT TESTED"),
            ([{**clean, "input": [{"role": "user", "content": 12}]}], "NOT TESTED"),
            ([{**clean, "input": [{"role": "user", "content": "raw input"}]}], "FAIL"),
        )
        before = [{**clean, "new_memory": "synthetic history"}]
        control = [{**before[0], "memory_id": "control"}]
        for index, (after, verdict) in enumerate(cases):
            baseline = self.path / f"history-{index}.json"
            with self.subTest(after=after), patch.object(hosted, "_json_get", side_effect=[before, control, after, control]):
                hosted.capture("mem0-hosted-history", None, "target", "control", baseline)
                self.assertEqual(report.derive(hosted.follow(baseline, None, "target", "control"))["technical_verdict"],
                                 verdict)

    def test_bedrock_uses_only_sts_identity_and_list_for_requested_scope(self):
        client = MagicMock()
        client.list_invocation_steps.side_effect = [
            {"invocationStepSummaries": [{"invocationStepId": "target"}, {"invocationStepId": "control"}]},
            {"invocationStepSummaries": [{"invocationStepId": "control"}]},
        ]
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Arn": "arn:aws:iam::111111111111:role/synthetic"}
        create_session = MagicMock()
        create_session.return_value.client.side_effect = [sts, client, sts, client]
        aws = {
            "boto3": SimpleNamespace(Session=create_session),
            "botocore.config": SimpleNamespace(Config=MagicMock()),
            "botocore.exceptions": SimpleNamespace(BotoCoreError=ValueError, ClientError=RuntimeError),
        }
        with patch.dict(sys.modules, aws):
            scope = "us-east-1:11111111-1111-1111-1111-111111111111"
            hosted.capture("bedrock-invocation-steps", scope, "target", "control", self.baseline)
            evidence = hosted.follow(self.baseline, scope, "target", "control")
        self.assertEqual(report.derive(evidence)["technical_verdict"], "PASS")
        self.assertEqual(create_session.call_args.kwargs["region_name"], "us-east-1")
        self.assertEqual({x[0] for x in client.mock_calls}, {"list_invocation_steps"})
        self.assertNotIn("111111111111", json.dumps(evidence))

    def test_provider_profile_rejects_bad_provenance_and_missing_control(self):
        with patch.object(hosted, "_json_get", side_effect=[
            {"data": [{"id": "target"}], "has_more": False},
            {"data": [{"id": "control"}], "has_more": False},
        ]):
            hosted.capture("openai-files", None, "target", "control", self.baseline)
            evidence = hosted.follow(self.baseline, None, "target", "control")
        self.assertEqual(report.derive(evidence)["technical_verdict"], "NOT TESTED")
        evidence["readback"]["baseline_at"] = datetime.max.replace(tzinfo=UTC).isoformat()
        with self.assertRaisesRegex(InvalidReport, "precedes"):
            profiles.issue("vendor-conformance", evidence, self.path)
