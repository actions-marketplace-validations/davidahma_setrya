"""Check the actual PDF and authentication boundaries of the Northline fixture."""

import unittest
from contextlib import closing
from hashlib import sha256
from http.client import HTTPConnection

from setrya.examples import northline_app as northline
from setrya.examples.northline_pdf import read_pdf_labels, render_pdf


class NorthlineAppTests(unittest.TestCase):
    def test_pdf_read_uses_the_file_bytes_and_rejects_unreadable_exports(self):
        with northline.open_fixture(revision="0" * 40) as settings:
            app, subject = settings["application"], settings["subject"]
            raw = app.pdf_path.read_bytes()
            self.assertIn(northline.TARGET_FACT, "\n".join(read_pdf_labels(raw)))
            recorded = app.inspect(subject, northline.PDF_STORE, northline.PDF_KEY)
            self.assertEqual(recorded.revision, sha256(raw).hexdigest())
            self.assertTrue(recorded.target_present)
            self.assertTrue(recorded.control_present)

            app.pdf_path.write_bytes(raw[:-5])
            with self.assertRaises(ValueError):
                app.inspect(subject, northline.PDF_STORE, northline.PDF_KEY)

            app.pdf_path.unlink()
            missing = app.inspect(subject, northline.PDF_STORE, northline.PDF_KEY)
            self.assertFalse(missing.exists)

    def test_pdf_preserves_parentheses_and_backslashes_in_visible_labels(self):
        labels = ("Finding F-42", northline.CONTROL_FACT, northline.TARGET_FACT + " \\on call")
        document = render_pdf(labels)
        self.assertEqual(read_pdf_labels(document), labels)

    def test_unknown_http_caller_cannot_reopen_the_investigation(self):
        with northline.open_fixture(revision="0" * 40) as settings:
            app = settings["application"]
            with closing(HTTPConnection(*app.server.server_address, timeout=3)) as client:
                client.request("POST", northline.ROUTE, '{"question":"Who owned the dataset in finding F-42?"}',
                               {"Authorization": "Bearer unrecognized-reader"})
                self.assertEqual(client.getresponse().status, 403)


if __name__ == "__main__":
    unittest.main()
