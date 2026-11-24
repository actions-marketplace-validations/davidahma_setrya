"""Exercise the fixture-free copy scan and its advisory PR boundary."""

import contextlib
from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from textwrap import dedent
import unittest
from unittest.mock import patch

from setrya.cli import main
from setrya.discovery import copy_sites


ROOT = Path(__file__).resolve().parents[1]
SPEC = spec_from_file_location("setrya_copy_action", ROOT / "scripts/action.py")
action = module_from_spec(SPEC)
SPEC.loader.exec_module(action)

REDIS_SOURCE = """from redis import Redis
cache = Redis.from_url(cache_url)
def save_answer(key, answer):
    cache.set(key, answer)
"""


class CopySites(unittest.TestCase):
    def test_qualified_calls_across_families_without_executing_source(self):
        source = dedent("""\
            from pathlib import Path
            import boto3 as aws
            from qdrant_client import QdrantClient
            from redis.asyncio import Redis
            from mem0 import Memory
            from openai import OpenAI
            from langfuse import get_client
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            raise RuntimeError("this file must never execute")
            Path("synthetic-local.txt").write_text(body)
            with open("another.txt", "wb") as output:
                output.write(body)
            s3 = aws.client("s3")
            s3.put_object(Body=body, Bucket=bucket, Key=key)
            vectors = QdrantClient()
            vectors.upsert(collection_name=name, points=points)
            cache = Redis.from_url(url)
            async def remember():
                await cache.set(key, answer)
            Memory.from_config(config).add(message, user_id=user)
            ai = OpenAI()
            ai.responses.create(input=message)
            ai.responses.create(input=message, store=False)
            ai.chat.completions.create(messages=messages)
            ai.chat.completions.create(messages=messages, store=True)
            ai.conversations.items.create(conversation_id=id, items=items)
            get_client().start_observation(input=message)
            OTLPSpanExporter().export(spans)
            unrelated.set(key, answer)
            Path("read-only.txt").open("r")
        """)
        with TemporaryDirectory() as tmp:
            path = Path(tmp, "answer.py")
            path.write_text(source)
            result = copy_sites.scan(Path(tmp))
            rename_stable = result["sites"]
            path.write_text("\n\n" + source)
            shifted = copy_sites.scan(Path(tmp))["sites"]
        self.assertEqual(result["format"], copy_sites.SCAN_FORMAT)
        self.assertEqual([site["kind"] for site in rename_stable],
                         ["file", "file", "object", "vector", "cache", "memory",
                          "model-state", "model-state", "model-state", "trace", "trace"])
        self.assertEqual([site["site_id"] for site in rename_stable], [site["site_id"] for site in shifted])
        self.assertEqual([site["line"] + 2 for site in rename_stable], [site["line"] for site in shifted])
        self.assertNotIn("synthetic-local.txt", json.dumps(result))
        self.assertEqual(rename_stable[4]["starter"]["store"], "redis-answer-cache")

    def test_vector_sql_sdk_and_document_rest_writes(self):
        source = dedent('''\
            from elasticsearch import AsyncElasticsearch, Elasticsearch
            from elasticsearch.helpers import bulk as bulk_index
            raise RuntimeError("the scanner must not execute this fixture")

            def write(cursor, client, index, key, doc):
                cursor.executemany("""INSERT INTO vector_index VALUES
                                      (%s, %s::public.vector)""", rows)
                cursor.execute("UPDATE index SET embedding = %s::halfvec", parameters)
                cursor.execute("INSERT INTO notes VALUES ('example ::vector')")
                cursor.execute("INSERT INTO notes VALUES (%s) -- query uses ::vector", parameters)
                cursor.execute("SELECT %s::vector", parameters)
                client.request("PUT", f"/{index}/_doc/{key}", doc)
                client.request("PUT", "/_doc/note?refresh=true", doc)
                client.request("POST", "/index/_update/note", doc)
                client.request("GET", "/_doc/note")
                client.request("PUT", "/index/other", doc)
                client.request("PUT", route, doc)
                engine = Elasticsearch()
                engine.options(refresh=True).index(index=index, document=doc)
                bulk_index(engine, actions)
                engine.search(index=index, query=query)

            async def async_write():
                engine = AsyncElasticsearch()
                await engine.bulk(operations=actions)
        ''')
        with TemporaryDirectory() as tmp:
            Path(tmp, "vectors.py").write_text(source, encoding="utf-8")
            sites = copy_sites.scan(tmp)["sites"]
        self.assertEqual([(site["kind"], site["operation"]) for site in sites], [
            ("vector", "pgvector.executemany"), ("vector", "pgvector.execute"),
            ("vector", "elasticsearch-http.document"), ("vector", "elasticsearch-http.document"),
            ("vector", "elasticsearch-http.update"), ("vector", "elasticsearch.index"),
            ("vector", "elasticsearch.helpers.bulk"), ("vector", "elasticsearch.bulk"),
        ])
        self.assertNotIn("index/_update/note", json.dumps(sites))
        self.assertTrue(all(site["starter"]["store"] == "vector-index" for site in sites))

    def test_bundled_vector_examples_are_seen(self):
        examples = ROOT / "setrya/examples"
        expected = {"pgvector_search/app.py": {"pgvector.executemany"},
                    "elasticsearch_search.py": {"elasticsearch-http.document"}}
        for name, operations in expected.items():
            with self.subTest(example=name):
                sites = copy_sites._inspect((examples / name).read_bytes(), name)
                self.assertTrue(operations <= {site.operation for site in sites if site.kind == "vector"})

    def git(self, path, *args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True, stderr=subprocess.DEVNULL).strip()

    def test_git_pr_compares_symbols_and_unreviewed_mapping_cannot_clear_gap(self):
        with TemporaryDirectory() as tmp, contextlib.redirect_stdout(StringIO()) as output:
            repo = Path(tmp)
            self.git(repo, "init")
            self.git(repo, "config", "user.email", "copy-scan@example.invalid")
            self.git(repo, "config", "user.name", "Copy Scan")
            app = repo / "answers.py"
            app.write_text(REDIS_SOURCE.replace("    cache.set(key, answer)", "    return answer"))
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "Answer without storage")
            base = self.git(repo, "rev-parse", "HEAD")
            app.write_text(REDIS_SOURCE)
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "Cache the answer")
            after = self.git(repo, "rev-parse", "HEAD")
            flags = ["--repo", str(repo), "--base", base, "--candidate", after]
            report = repo / "copy-report.json"
            self.assertEqual(main(["discovery", "copy-check", *flags, "--output", str(report)]), 3)
            data = json.loads(report.read_bytes())
            self.assertEqual(data["candidate_commit"], after)
            self.assertEqual(data["review_required"], 1)
            site, = data["sites"]
            self.assertEqual((site["kind"], site["path"], site["line"]), ("cache", "answers.py", 4))
            self.assertEqual(site["site_id"], "2ef1d1f56f60672111745aada96642b9313039653ab2302e3516188ca3669723")
            self.assertIn("NEEDS-REVIEW  answers.py:4", output.getvalue())
            mapping = {"format": copy_sites.MAP_FORMAT, "sites": [site["starter"]]}
            (repo / copy_sites.MAP_FILE).write_text(json.dumps(mapping))
            self.git(repo, "add", copy_sites.MAP_FILE)
            self.git(repo, "commit", "-m", "Propose a test mapping without evidence")
            app.write_text("raise RuntimeError('dirty work tree must not be read')\n")
            updated = copy_sites.check(repo, base)
            self.assertTrue(updated["map_changed"])
            self.assertEqual(updated["review_required"], 1)
            self.assertEqual(updated["sites"][0]["binding"], site["starter"])
            no_changes = copy_sites.check(repo, after)
            self.assertEqual(no_changes["sites"], [])

    def test_comment_uses_only_bounded_rows_and_separate_marker(self):
        head, site_id = "a" * 40, "b" * 64
        signals = [1, [["answers.py", 4, "cache", site_id]], False]
        rendered = action.copy_details(json.dumps(signals))
        self.assertIn("answers.py:4", rendered)
        self.assertIn("redis-answer-cache", rendered)
        for bad_signals in ([1, [["path with spaces.py", 4, "cache", site_id]], False],
                            [1, [["answers.py", 4, "cache", "bad-id"]], False],
                            [0, signals[1], False]):
            with self.subTest(bad=bad_signals), self.assertRaises(ValueError):
                action.copy_details(json.dumps(bad_signals))
        with TemporaryDirectory() as tmp:
            event = Path(tmp, "event.json")
            event.write_text(json.dumps({"number": 4, "pull_request": {"base": {"repo": {"full_name": "owner/repo"}},
                                                                          "head": {"sha": head}}}))
            env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event), "GITHUB_REPOSITORY": "owner/repo",
                   "GITHUB_RUN_ID": "27", "GITHUB_SERVER_URL": "https://github.com",
                   "SETRYA_COPY_SUMMARY": json.dumps(signals)}
            saved = [{"id": 67, "body": action.MARKER + "\nOriginal verdict",
                      "user": {"login": "github-actions[bot]", "type": "Bot"}}]
            writes = []

            def api(method, path, body=None):
                if method == "GET":
                    return saved if "/comments?" in path else {"head": {"sha": head}}
                writes.append((method, path, body))
                return None

            with patch.dict(os.environ, env), patch.object(action, "api", side_effect=api):
                self.assertEqual(action.copy_comment(), 0)
            method, dest, body = writes[0]
            self.assertEqual((method, dest), ("POST", "repos/owner/repo/issues/4/comments"))
            self.assertTrue(body["body"].startswith(action.COPY_MARKER + "\n"))
            self.assertIn("answers.py:4", body["body"])

    def test_committed_operator_binding_needs_replayed_candidate_provenance(self):
        with TemporaryDirectory() as tmp, contextlib.redirect_stdout(StringIO()):
            folder = Path(tmp)
            repo = folder / "app"
            repo.mkdir()
            self.git(repo, "init")
            self.git(repo, "config", "user.email", "copy-scan@example.invalid")
            self.git(repo, "config", "user.name", "Copy Scan")
            fixture = repo / "case.py"
            fixture.write_bytes((ROOT / "setrya/erasure/workspace_starter.py").read_bytes())
            app = repo / "answers.py"
            app.write_text(REDIS_SOURCE)
            site = next(row for row in copy_sites.scan(repo)["sites"] if row["kind"] == "cache")
            binding = {"site_id": site["site_id"], "test": fixture.name, "store": "notes", "key": "customer-note"}
            (repo / copy_sites.MAP_FILE).write_text(json.dumps({"format": copy_sites.MAP_FORMAT, "sites": [binding]}))
            app.write_text(REDIS_SOURCE.replace("    cache.set(key, answer)", "    return answer"))
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "Approve the synthetic test mapping")
            base = self.git(repo, "rev-parse", "HEAD")
            app.write_text(REDIS_SOURCE)
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "Enable answer copy")
            candidate = self.git(repo, "rev-parse", "HEAD")
            clean, dirty = folder / "clean", folder / "dirty"
            with contextlib.chdir(repo), patch.dict(os.environ, {"PYTHONPATH": str(ROOT)}):
                self.assertEqual(main(["run", "--starter", str(fixture), "--output", str(clean)]), 0)
                app.write_text("# Uncommitted code\n")
                self.assertEqual(main(["run", "--starter", str(fixture), "--output", str(dirty)]), 0)
            _, = copy_sites.check(repo, base, candidate)["sites"]
            reviewed, = copy_sites.check(repo, base, candidate, receipts=(clean,))["sites"]
            self.assertEqual(reviewed["status"], "evidence-replayed")
            self.assertEqual(reviewed["receipt_sha256"], sha256((clean / "erasure-receipt.json").read_bytes()).hexdigest())
            self.assertEqual(copy_sites.check(repo, base, candidate, receipts=(dirty,))["review_required"], 1)
