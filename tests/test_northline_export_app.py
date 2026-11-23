"""Check the staged rewrite and residual against the archive's physical bytes."""

import unittest
from dataclasses import asdict
from hashlib import sha256

from setrya.examples import northline_app as northline
from setrya.examples import northline_export_app as export
from setrya.examples.northline_pdf import read_pdf_labels


class NorthlineExportTests(unittest.TestCase):
    def test_delayed_archive_refresh_can_restore_only_the_archive(self):
        source = {"store": northline.SOURCE_STORE, "key": northline.SOURCE_KEY,
                  "revision": northline.SOURCE_REVISION, "action": "rewrite"}
        actions = tuple(asdict(a) for a in export.ARTIFACTS)
        for guarded in (False, True):
            with self.subTest(guarded=guarded), export.open_fixture(revision="0" * 40, guarded=guarded) as settings:
                app, subject = settings["application"], settings["subject"]
                before = app.archive_path.read_bytes()
                self.assertNotEqual(app.archive_path, app.pdf_path)
                self.assertIn(northline.TARGET_FACT, "\n".join(read_pdf_labels(before)))
                self.assertEqual(app.inspect(subject, export.ARCHIVE_STORE, export.ARCHIVE_KEY).revision,
                                 sha256(before).hexdigest())
                attempt = app.hold(subject)
                self.assertEqual(app.checkpoint(subject), attempt)
                self.assertFalse(app.erase_approved(subject, source, actions[:-1]))
                self.assertEqual(app.archive_path.read_bytes(), before)
                self.assertTrue(app.erase_approved(subject, source, actions))
                clean = app.archive_path.read_bytes()
                clean_text = "\n".join(read_pdf_labels(clean))
                self.assertNotIn(northline.TARGET_FACT, clean_text)
                self.assertIn(northline.CONTROL_FACT, clean_text)
                self.assertTrue(app.release_and_drain(subject, attempt.attempt).drained)
                self.assertEqual(app.archive_path.read_bytes(), clean if guarded else before)
                archive = app.inspect(subject, export.ARCHIVE_STORE, export.ARCHIVE_KEY)
                self.assertEqual(archive.target_present, not guarded)
                self.assertTrue(archive.control_present)
                self.assertEqual(app.pdf_path.read_bytes(), clean)
                for caller in northline.CALLERS:
                    self.assertFalse(app.read(subject, caller, northline.CONVERSATION,
                                              northline.TARGET_QUESTION).target_present)
                    self.assertTrue(app.read(subject, caller, northline.CONVERSATION,
                                             northline.CONTROL_QUESTION).control_present)
                archive_events = [event.wire() for event in settings["journal"].history(subject)
                                  if event.store == export.ARCHIVE_STORE]
                self.assertEqual([event.get("turn") for event in archive_events],
                                 [None] if guarded else [None, "northline-archive-refresh"])

    def test_archive_reader_is_bound_to_the_exact_subject_and_key(self):
        with export.open_fixture(revision="0" * 40) as settings:
            app, subject = settings["application"], settings["subject"]
            with self.assertRaises(ValueError):
                app.inspect(subject, export.ARCHIVE_STORE, northline.PDF_KEY)
            with self.assertRaises(ValueError):
                app.inspect(None, export.ARCHIVE_STORE, export.ARCHIVE_KEY)
            app.archive_path.write_bytes(b"unreadable PDF")
            self.assertTrue(app.inspect(subject, northline.PDF_STORE, northline.PDF_KEY).target_present)
            with self.assertRaises(ValueError):
                app.inspect(subject, export.ARCHIVE_STORE, export.ARCHIVE_KEY)
