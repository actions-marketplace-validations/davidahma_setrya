"""A clean endpoint cannot hide a surviving fact in a rewritten database record."""
from contextlib import closing
from importlib.util import find_spec
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from setrya.erasure import TextAnswer, run_shared
from setrya.erasure.case_starters import init_stack
from setrya.erasure.casefile import load_case
from setrya.receipts import replay


@unittest.skipUnless(find_spec("yaml"), "install setrya[case-yaml]")
class SharedStoreFacts(unittest.TestCase):
    def test_rewrite_checks_reviewed_positive_phrases_and_exact_negative_payloads(self):
        import yaml
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = init_stack(root / "fixture", "openai-agents")
            config = yaml.safe_load(path.read_text())
            config["stores"]["memory"].update(kind="sqlite", table="notes", scope_column="ticket",
                                               key_column="id", content_column="body", artifacts={"note": "rewrite"})
            safe = "Dispatch is still on Thursday."
            config["facts"]["target"]["stored"] = {"absent": [safe], "present": ["Dock 17"]}
            path.write_text(yaml.safe_dump(config))
            spec = load_case(path)
            db = root / "app.sqlite"
            with closing(sqlite3.connect(db)) as connection:
                connection.execute("CREATE TABLE notes(ticket TEXT, id TEXT, body TEXT)")
                connection.execute("INSERT INTO notes VALUES ('ticket-204','note','')")
                cases = [
                    ("Harbor seventeen. Dispatch is still on Thursday.", "FAIL"),
                    ("Dispatch is still on Thursday. The manifest says Dock 17.", "FAIL"),
                    (safe + " An unreviewed sentence follows.", "NOT TESTED"),
                    (safe, "PASS"),
                ]
                for i, (after, expected) in enumerate(cases):
                    with self.subTest(expected=expected, content=after):
                        connection.execute("UPDATE notes SET body='Harbor-17 and Thursday'")
                        connection.commit()
                        erased = False

                        def erase(subject):
                            nonlocal erased
                            connection.execute("UPDATE notes SET body=?", (after,))
                            connection.commit()
                            erased = True

                        def read(subject, caller, conversation, question):
                            answer = "Thursday" if question == spec.case.control_question else (
                                "No matching note." if erased else "Harbor-17")
                            return TextAnswer(caller, conversation, spec.case.route, question, answer)

                        out = root / str(i)
                        with patch.dict(os.environ, SETRYA_SUBJECT_REF="f" * 64, SETRYA_TEST_AGENTS_DB=str(db)):
                            with spec.open_stores() as (subject, app, _):
                                app.erase, app.read = erase, read
                                receipt = run_shared(subject, case=spec.case, application=app, mode="deletion", output=out)
                        self.assertTrue(erased)
                        self.assertEqual(receipt["technical_verdict"], expected)
                        self.assertEqual(receipt, replay(out))
                        self.assertEqual(receipt["answer_sampling"]["stages"]["final"]["target_positive"], 0)
