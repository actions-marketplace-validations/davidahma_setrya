"""Northline fixture with a second PDF export and its own refresh job."""

from contextlib import closing, contextmanager
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from setrya.erasure import Artifact, Stored
from setrya.erasure.journal import CopyJournal
from setrya.erasure.lineage import VersionRef
from setrya.erasure.subject import Turn

from . import northline_app as northline
from .northline_pdf import MAX_PDF_BYTES, read_pdf_labels

ARCHIVE_STORE = "archive-exports"
ARCHIVE_KEY = "archive-f42.pdf"
ARCHIVE_ARTIFACT = Artifact(ARCHIVE_STORE, ARCHIVE_KEY, "rewrite")
ARTIFACTS = (*northline.ARTIFACTS, ARCHIVE_ARTIFACT)


def case_spec():
    return replace(northline.case_spec(), artifacts=ARTIFACTS)


class NorthlineExport(northline.Northline):
    def __init__(self, folder, subject, journal, *, guarded):
        super().__init__(folder, subject, journal, guarded=guarded)
        self.archive_folder = folder / "archive"
        self.archive_folder.mkdir()
        self.archive_path = self.archive_folder / ARCHIVE_KEY

    def _write_archive(self, payload):
        folder = self.archive_folder
        (Path(folder) / "archive-f42.pdf").write_bytes(payload)

    def _read_archive(self):
        with self.archive_path.open("rb") as stream:
            raw = stream.read(MAX_PDF_BYTES + 1)
        title, *labels = read_pdf_labels(raw)
        if title != northline._PDF_TITLE:
            raise ValueError("The archive PDF belongs to a different finding.")
        return raw, "\n".join(labels)

    def _publish(self, publication):
        super()._publish(publication)
        self._write_archive(publication.pdf)

    def _record_archive(self, finding, chart, raw):
        archive = VersionRef(ARCHIVE_STORE, ARCHIVE_KEY, sha256(raw).hexdigest())
        source = VersionRef(northline.CHART_STORE, northline.CHART_KEY, sha256(chart).hexdigest())
        self.versions.record(archive, inputs=[source])
        if finding.owner:
            self.journal.record(self.target, store=archive.store, key=archive.key, source=northline.SOURCE_KEY,
                                action="derived", details={"revision": archive.revision, "stage": "committed"})

    def _record_versions(self, finding, publication):
        super()._record_versions(finding, publication)
        self._record_archive(finding, publication.chart, publication.pdf)

    def _refresh(self, subject, before_write):
        self._check_subject(subject)
        with self.lock:
            captured = self._finding()
            chart = self._saved(northline.CHART_STORE)
            if captured is None or chart is None:
                raise ValueError("The archive refresh requires the original chart and finding.")
            raw, _ = self._read_archive()
        before_write()
        with self.lock, Turn("northline-archive-refresh", "analyst-east", "archive-worker").activate():
            if self.guarded and self._finding() != captured:
                return
            self._write_archive(raw)
            self._record_archive(captured, chart, raw)

    def erase_approved(self, subject, source, actions):
        self._check_subject(subject)
        if actions != tuple(asdict(artifact) for artifact in ARTIFACTS):
            return False
        return super().erase_approved(subject, source, actions[:len(northline.ARTIFACTS)])

    def inspect(self, subject, store, key):
        if store != ARCHIVE_STORE:
            return super().inspect(subject, store, key)
        self._check_subject(subject)
        if key != ARCHIVE_KEY:
            raise ValueError("No direct reader for that fixture location.")
        with self.lock:
            try:
                raw, labels = self._read_archive()
            except FileNotFoundError:
                return Stored(key, False, False, False, None)
        return Stored(key, True, northline._target_in(labels), northline.CONTROL_FACT in labels,
                      sha256(raw).hexdigest())


@contextmanager
def open_fixture(binding=None, *, revision, guarded=True):
    """Open a disposable Northline runtime with the archive in its drill scope."""
    target = northline.subject()
    with TemporaryDirectory(prefix="setrya-northline-export-") as directory:
        folder = Path(directory)
        journal = CopyJournal(folder / "journal.sqlite")
        app = NorthlineExport(folder, target, journal, guarded=guarded)
        with closing(app.db), app.worker, northline._LoopbackServer(("127.0.0.1", 0), northline._Endpoint) as server:
            app.seed()
            server.app = app
            app.server = server
            thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                yield {"subject": target, "case": case_spec(), "application": app, "environment": northline.ENVIRONMENT,
                       "revision": revision, "journal": journal}
            finally:
                server.shutdown()
                thread.join()
