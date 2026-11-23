"""Exercise the PDF source scanner independently of the bundled app."""

import tempfile
import unittest
from itertools import pairwise
from pathlib import Path
from textwrap import dedent
from unittest.mock import patch

from setrya.core.inputs import InvalidReport
from setrya.discovery import source_scan


class SourceScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, source, filename="app.py"):
        path = self.root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(source), encoding="utf-8")
        return path

    def scan(self):
        return source_scan.scan_pdf_writes(self.root)

    def test_simple_path_aliases_resolve_without_executing_source(self):
        self.write("""
            from pathlib import Path as P
            raise RuntimeError('The scanner must never execute the source')
            reports = P('reports')
            out: P = reports / ('daily/' + 'report.PDF')
            out.write_bytes(payload)
            out.open('wb')
            open('backups/latest.pdf', mode='r+b')
            P('staged.tmp').replace('reports/replacement.pdf')
            open('backups/read-only.pdf', 'rb')
            open('backups/invalid-mode.pdf', 'w/')
            P('records.json').write_text(payload)
        """, "nested/app.py")

        sites = self.scan()
        self.assertEqual([(site.operation, site.destination) for site in sites], [
            ("path.write_bytes", "reports/daily/report.PDF"),
            ("path.open", "reports/daily/report.PDF"),
            ("open", "backups/latest.pdf"),
            ("path.replace", "reports/replacement.pdf"),
        ])
        self.assertEqual({site.path for site in sites}, {"nested/app.py"})
        self.assertEqual(sites[0].hint, "report.PDF")

    def test_dynamic_pdf_destinations_are_unresolved_and_bounded_to_pdf_signals(self):
        self.write("""
            import pathlib as paths
            def export(folder, filename):
                (paths.Path(folder) / 'archive.pdf').write_bytes(payload)
                paths.Path(f'{filename}.pdf').write_text(payload)
                paths.Path(filename).write_bytes(renderer.render_pdf(record))
                paths.Path(filename).write_bytes(payload)
                paths.Path('/outside/private/absolute.pdf').write_bytes(payload)
                paths.Path('../parent.pdf').write_bytes(payload)
        """)

        sites = self.scan()
        self.assertEqual([site.hint for site in sites], ["archive.pdf", None, None, "absolute.pdf", "parent.pdf"])
        self.assertTrue(all(site.destination is None for site in sites))

    def test_local_bindings_do_not_shadow_independent_functions(self):
        self.write("""
            from pathlib import Path

            def save_original():
                path = Path('original.pdf')
                path.write_bytes(payload)

            def save_archive():
                path = Path('archive.pdf')
                path.write_bytes(payload)

            def shadowed(Path, open):
                path = Path('unknown.pdf')
                path.write_bytes(payload)
                open('unknown.pdf', 'wb')

            def reassigned():
                path = Path('ambiguous.pdf')
                if use_config:
                    path = load_path()
                path.write_bytes(payload)

            class App:
                Path = fallback

                def save_copy(self):
                    path = Path('copy.pdf')
                    path.write_bytes(payload)
        """)
        self.assertEqual([site.destination for site in self.scan()], ["original.pdf", "archive.pdf", "copy.pdf"])

    def test_candidate_identity_survives_line_shifts_and_tracks_destinations(self):
        source = """\
from pathlib import Path
folder = Path('reports')
def save():
    (folder / 'out.pdf').write_bytes(payload)
"""
        self.write(source)
        first, = self.scan()
        self.write("\n\n" + source.replace("payload", "different_payload"))
        shifted, = self.scan()
        self.assertEqual(first.id, shifted.id)
        self.assertEqual(first.line + 2, shifted.line)

        self.write(source + "    (folder / 'out.pdf').write_bytes(other_payload)\n")
        one, two = self.scan()
        self.assertEqual(first.id, one.id)
        self.assertNotEqual(first.id, two.id)

        self.write(source.replace("'reports'", "'new-folder'"))
        moved, = self.scan()
        self.assertEqual(moved.destination, "new-folder/out.pdf")
        self.assertNotEqual(first.id, moved.id)

        self.write(source.replace("'reports'", "'/outside/a'"))
        absolute, = self.scan()
        self.write(source.replace("'reports'", "'/outside/b'"))
        another_absolute, = self.scan()
        self.assertNotEqual(absolute.id, another_absolute.id)

    def test_candidate_identity_tracks_dynamic_alias_changes(self):
        for before, after in (
            ("Path(f'private/{partition}/report.pdf')", "Path(f'public/{partition}/report.pdf')"),
            ("Path(first() + '.pdf')", "Path(second() + '.pdf')"),
            ("Path(first()) / 'report.pdf'", "Path(second()) / 'report.pdf'"),
        ):
            with self.subTest(before=before, after=after):
                source = "from pathlib import Path\ntarget = {expr}\ntarget.write_bytes(payload)\n"
                self.write(source.format(expr=before))
                original, = self.scan()
                self.write(source.format(expr=after))
                changed, = self.scan()
                self.assertIsNone(original.destination)
                self.assertIsNone(changed.destination)
                self.assertEqual(original.hint, changed.hint)
                self.assertNotEqual(original.id, changed.id)

    def test_read_errors_and_candidate_budget_cannot_return_partial_scan(self):
        self.write("open('present.pdf', 'wb')\n")
        with (patch.object(source_scan, "MAX_SOURCE_CANDIDATE_BYTES", 32),
              self.assertRaisesRegex(InvalidReport, "candidate byte limit")):
            self.scan()

        bad = self.write("\ninvalid ! syntax\n", "broken.py")
        with self.assertRaisesRegex(InvalidReport, "Could not parse Python source: broken[.]py"):
            self.scan()
        bad.unlink()
        (self.root / "linked.py").symlink_to(self.root / "app.py")
        with self.assertRaisesRegex(InvalidReport, "symbolic links"):
            self.scan()

    def test_reused_dynamic_aliases_do_not_require_expanding_all_components(self):
        source = "from pathlib import Path\nfirst = Path(dynamic) / 'name.pdf'\n"
        aliases = ["first", *(f"part{index}" for index in range(64))]
        for before, after in pairwise(aliases):
            source += f"{after} = {before} / {before}\n"
        self.write(source + f"{aliases[-1]}.write_bytes(payload)\n")
        candidate, = self.scan()
        self.assertIsNone(candidate.destination)
        self.assertEqual(candidate.hint, "name.pdf")
