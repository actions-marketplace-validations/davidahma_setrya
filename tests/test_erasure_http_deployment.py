"""Exercise one declarative behavior through distinct authenticated HTTPS deployments."""

import json
import os
import shutil
import sqlite3
import ssl
import subprocess
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from hashlib import sha256
from http.server import BaseHTTPRequestHandler
from io import StringIO
from pathlib import Path
from socketserver import TCPServer
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import patch

from setrya.cli import main
from setrya.core.deployment import FORMAT, validate_record
from setrya.core.inputs import InvalidReport
from setrya.receipts import replay

YAML = "setrya[case-yaml] is required."
ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "docs/examples/http-case/case.yml"


class Endpoint(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def request_data(self):
        return json.load(StringIO(self.rfile.read(int(self.headers["Content-Length"])).decode()))

    def finish_reply(self, status, payload=None):
        target = self.server.build
        self.send_response(status)
        if target is not None:
            self.send_header("X-Setrya-Build", target)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        if payload is not None:
            self.wfile.write(json.dumps(payload).encode())

    def do_POST(self):
        self.server.requests.append(self.headers["Authorization"])
        if self.headers["Authorization"] != "Bearer reader-secret" or self.path != self.server.read_route:
            self.finish_reply(403)
            return
        data = self.request_data()
        question = data["question"]
        key = "delivery" if question == "When is dispatch?" else self.server.note
        with sqlite3.connect(self.server.database) as conn:
            row = conn.execute("SELECT body FROM notes WHERE id=?", (key,)).fetchone()
        self.finish_reply(200, {"caller": "duty-agent", "conversation": data["conversation"],
                                "route": self.path, "question": question, "text": row[0] if row else "No matching note."})

    def do_DELETE(self):
        self.server.requests.append(self.headers["Authorization"])
        if self.headers["Authorization"] != "Bearer eraser-secret" or self.path != self.server.erase_route:
            self.finish_reply(403)
            return
        if self.headers["If-Match"] != f'"{self.server.build}"':
            self.finish_reply(412)
            return
        if self.request_data()["subject_ref"] != "a" * 64:
            self.finish_reply(403)
            return
        with sqlite3.connect(self.server.database) as conn:
            conn.execute("DELETE FROM notes WHERE id=?", (self.server.note,))
        self.server.erased += 1
        self.finish_reply(204)
        if self.server.rollout:
            self.server.build = "different-build"


class DeploymentRecordTests(unittest.TestCase):
    def test_record_requires_one_canonical_https_origin(self):
        record = {"format": FORMAT, "environment": "review", "origin": "https://[::1]:444",
                  "build_id": "test-1", "tls_sha256": "a" * 64}
        self.assertEqual(validate_record(record), record)
        for origin in ("", "https://", "https://test:65536", "https://TEST", "https://test:443",
                       "https://test/", "https://test#fragment", "https://a@b", "http://localhost", "https://1"):
            with self.subTest(origin=origin), self.assertRaises(InvalidReport):
                validate_record({**record, "origin": origin})


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for a disposable test certificate.")
class HttpDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import yaml
        except ImportError:
            raise unittest.SkipTest(YAML) from None
        cls.yaml = yaml
        cls.directory = Path(cls.enterClassContext(TemporaryDirectory()))
        cls.cert, cls.key = cls.directory / "localhost.pem", cls.directory / "localhost.key"
        config = cls.directory / "test.cnf"
        config.write_text(
            "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = localhost\n"
            "[test]\nbasicConstraints = critical,CA:TRUE\n"
            "keyUsage = digitalSignature,keyEncipherment,keyCertSign\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n"
        )
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-config", config, "-extensions", "test", "-keyout", cls.key, "-out", cls.cert],
                       check=True, capture_output=True, timeout=30)
        cls.certificate_digest = sha256(ssl.PEM_cert_to_DER_cert(cls.cert.read_text())).hexdigest()

    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        raw = self.yaml.safe_load(CASE.read_bytes())
        self.behavior = self.root / "behavior.yml"
        self.behavior.write_text(self.yaml.safe_dump({"format": "setrya.http-behavior.v1", "facts": raw["facts"],
                                                     "samples": 1,
                                                     "artifacts": {"memory": raw["stores"]["memory"]["artifacts"]}}))
        self.out, self.error = StringIO(), StringIO()
        self.enterContext(redirect_stdout(self.out))
        self.enterContext(redirect_stderr(self.error))

    @contextmanager
    def application(self, name, *, rollout=False, wrong_cert=False, wrong_build=False, retain=False, build_header=True):
        database = self.root / f"{name}.sqlite"
        note = f"{name}-note"
        with sqlite3.connect(database) as conn:
            conn.execute("CREATE TABLE notes (id TEXT PRIMARY KEY, ticket TEXT NOT NULL, body TEXT NOT NULL)")
            conn.executemany("INSERT INTO notes VALUES (?,?,?)",
                             [(note, name, "Harbor-17"), ("delivery", name, "Thursday")])
        with ExitStack() as stack:
            socket = stack.enter_context(TCPServer(("127.0.0.1", 0), Endpoint))
            socket.database, socket.note, socket.build = database, note, f"{name}-build"
            socket.read_route, socket.erase_route = f"/{name}/answer", f"/{name}/erase"
            socket.requests, socket.erased, socket.rollout = [], 0, rollout
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert, self.key)
            socket.socket = context.wrap_socket(socket.socket, server_side=True)
            worker = Thread(target=socket.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            worker.start()
            stack.callback(worker.join)
            stack.callback(socket.shutdown)
            record = {"format": FORMAT, "environment": name, "origin": f"https://127.0.0.1:{socket.server_address[1]}",
                      "tls_sha256": "b" * 64 if wrong_cert else self.certificate_digest,
                      "build_id": "unexpected" if wrong_build else socket.build}
            if not build_header:
                socket.build = None
            config = {
                "format": "setrya.http-deployment.v1", "record": record, "conversation": name,
                "subject_ref_env": "TEST_SUBJECT", "read_route": socket.read_route, "erase_route": socket.erase_route,
                "caller_tokens": {"duty-agent": "TEST_READER"}, "erase_token_env": "TEST_ERASER",
                "stores": {"memory": {"kind": "sqlite", "connection_env": "TEST_STORE", "scope": name,
                                      "table": "notes", "key_column": "id", "content_column": "body",
                                      "scope_column": "ticket", "keys": {"note": note, "dispatch": "delivery"}}},
            }
            if retain:
                config["retention_exceptions"] = [{"store": "archive", "key": "t-45", "owner": "operations",
                                                   "evidence": "retention-register", "expires_on": "2027-02-05"}]
            client, pin = self.root / f"{name}.yml", self.root / f"{name}.json"
            client.write_text(self.yaml.safe_dump(config))
            pin.write_text(json.dumps(record))
            stack.enter_context(patch.dict(os.environ, {"TEST_SUBJECT": "a" * 64, "TEST_READER": "reader-secret",
                                                       "TEST_ERASER": "eraser-secret", "TEST_STORE": str(database),
                                                       "SSL_CERT_FILE": str(self.cert)}))
            yield socket, client, pin

    def start(self, deployment, output):
        return main(["run", "--case", str(self.behavior), "--deployment", str(deployment), "--output", str(output)])

    def test_one_behavior_two_deployments_and_independent_pins(self):
        production, staging = self.root / "production", self.root / "staging"
        with self.application("production", retain=True) as (app, config, production_pin):
            with patch.dict(os.environ, {"TEST_READER": ""}):
                self.assertEqual(main(["doctor", "--case", str(self.behavior), "--deployment", str(config)]), 3)
                self.assertIn(f"{config}:", self.out.getvalue())
            self.assertEqual(main(["doctor", "--case", str(self.behavior), "--deployment", str(config)]), 0)
            self.assertEqual(app.erased, 0)
            self.assertEqual(self.start(config, production), 0, self.error.getvalue())
            self.assertEqual(app.erased, 1)
        with self.application("staging") as (app, config, staging_pin):
            self.assertEqual(self.start(config, staging), 0, self.error.getvalue())
            self.assertEqual(app.erased, 1)
        first = replay(production)
        second = replay(staging)
        self.assertEqual(first["deployment"]["behavior_sha256"], second["deployment"]["behavior_sha256"])
        self.assertNotEqual(first["deployment"]["deployment_sha256"], second["deployment"]["deployment_sha256"])
        self.assertEqual(first["review_status"], "OPEN_ITEMS")
        self.assertEqual(first["open_items"][0]["follow_up"], "2027-02-05")
        self.assertEqual(main(["replay", str(production), "--expect-deployment", str(production_pin), "--case-review"]), 3)
        self.assertEqual(main(["replay", str(staging), "--expect-deployment", str(production_pin)]), 2)
        self.assertEqual(main(["replay", str(staging), "--expect-deployment", str(staging_pin)]), 0)
        evidence = (staging / "erasure-evidence.json").read_bytes()
        transport = json.loads(evidence)["deployment"]
        self.assertEqual(len(transport["reads"]), 9)
        self.assertTrue(all(row["tls_sha256"] == self.certificate_digest and row["build_id"] == "staging-build"
                            and row["origin"] == second["deployment"]["record"]["origin"] for row in transport["reads"]))
        self.assertNotIn(b"reader-secret", evidence)
        self.assertNotIn(b"eraser-secret", evidence)

    def test_wrong_certificate_never_sends_bearer_or_erases(self):
        folder = self.root / "receipt"
        with self.application("sample", wrong_cert=True) as (app, config, pin):
            self.assertEqual(self.start(config, folder), 3, self.error.getvalue())
            self.assertEqual(app.requests, [])
            self.assertEqual(app.erased, 0)
        self.assertEqual(replay(folder)["deployment"]["status"], "unverified")
        self.assertEqual(main(["replay", str(folder), "--expect-deployment", str(pin)]), 2)
        view = json.loads((folder / "erasure-evidence.json").read_bytes())["deployment"]["reads"][0]
        self.assertEqual(view["tls_sha256"], self.certificate_digest)
        self.assertIsNone(view["build_id"])

    def test_build_mismatch_and_missing_build_refuse_to_erase(self):
        for name, kwargs in (("drifted", {"wrong_build": True}), ("missing", {"build_header": False})):
            with self.subTest(name=name), self.application(name, **kwargs) as (app, config, _):
                folder = self.root / name
                self.assertEqual(self.start(config, folder), 3, self.error.getvalue())
                self.assertEqual(app.erased, 0)
                self.assertEqual(replay(folder)["deployment"]["status"], "unverified")

    def test_build_change_after_erase_cannot_pass(self):
        folder = self.root / "receipt"
        with self.application("sample", rollout=True) as (app, config, _):
            self.assertEqual(self.start(config, folder), 3, self.error.getvalue())
            self.assertEqual(app.erased, 1)
        result = replay(folder)
        self.assertEqual(result["technical_verdict"], "NOT TESTED")
        self.assertEqual(result["deployment"]["status"], "unverified")

    def test_signed_review_commands_reject_a_different_deployment_pin(self):
        folder = self.root / "receipt"
        with self.application("staging") as (_, config, pin):
            self.assertEqual(self.start(config, folder), 0, self.error.getvalue())
        wrong_pin, exchange, report, signature = (self.root / name for name in
                                                   ("wrong.json", "exchange", "assessment", "receipt.sig"))
        wrong_pin.write_text(json.dumps({**json.loads(pin.read_bytes()), "environment": "production"}))
        key, intake = self.root / "trusted.pub", self.root / "plan.json"
        intake.write_text(json.dumps({"format": "setrya.assessment-input.v1", "client": "review",
                                      "repositories": [{"name": "sample", "commit": "1" * 40,
                                                        "checks": [], "receipts": [folder.name]}]}))
        receipt = folder / "erasure-receipt.json"

        def sign(raw, output, *, key):
            output.write_bytes(sha256(raw).digest())

        def verify(raw, signature, **_):
            if sha256(raw).digest() != signature:
                raise InvalidReport("Signature mismatch.")

        with (patch("setrya.core.signing.sign_bytes", side_effect=sign),
              patch("setrya.core.signing.verify_bytes", side_effect=verify)):
            pair = ["--receipt", str(receipt), "--bundle", str(signature), "--key", str(key)]
            self.assertEqual(main(["erasure", "sign", *pair]), 0, self.error.getvalue())
            self.assertEqual(main(["receipt", "pack", str(folder), "--output", str(exchange), "--synthetic",
                                   "--system", "sample", "--system-version", "1", "--key", str(key)]),
                             0, self.error.getvalue())
            build = ["assess", "build", "--plan", str(intake), "--key", str(key)]
            self.assertEqual(main([*build, "--output", str(self.root / "bad"), "--expect-deployment", str(wrong_pin)]),
                             2, self.error.getvalue())
            self.assertEqual(main([*build, "--output", str(report), "--expect-deployment", str(pin)]),
                             0, self.error.getvalue())
            for command in (["verify", *pair],
                            ["receipt", "verify-exchange", str(exchange), "--key", str(key)],
                            ["assess", "verify", str(report), "--key", str(key)]):
                self.assertEqual(main([*command, "--expect-deployment", str(pin)]), 0, self.error.getvalue())
                self.assertEqual(main([*command, "--expect-deployment", str(wrong_pin)]), 2, self.error.getvalue())

    def test_retention_exception_cannot_override_required_store(self):
        folder = self.root / "receipt"
        with self.application("sample", retain=True) as (app, config, _):
            data = self.yaml.safe_load(config.read_bytes())
            data["retention_exceptions"][0]["store"] = "memory"
            config.write_text(self.yaml.safe_dump(data))
            self.assertEqual(self.start(config, folder), 2)
            self.assertIn("Required stores cannot be external exceptions", self.error.getvalue())
            self.assertEqual(app.requests, [])
            self.assertFalse(folder.exists())
