"""A synthetic erasure drill with a held memory writer and a local Git history."""

from contextlib import contextmanager
from datetime import date, timedelta
from hashlib import sha256
from pathlib import Path
import secrets
from shlex import join
import shutil
import subprocess
from tempfile import TemporaryDirectory
from threading import RLock

from setrya.drill import InputError
from setrya.erasure import (
    AnswerJudges, Artifact, CopyJournal, ExternalItem, Marker, ReviewedAnswers, SharedCase, Stored, Subject,
    TextAnswer, Turn, run_shared,
)
from setrya.erasure.fs_canary import FilesystemCanaryScanner, GitHistoryCanaryScanner, _git_env
from setrya.erasure.hooks import CopyHooks
from setrya.erasure.lineage import VersionRef
from setrya.erasure.worker_fixture import WorkerFixture


TARGET_FILE = "users/alice/memory_log.md"
CONTROL_FILE = "clients/acme/team_log.md"
DERIVED_FILE = "clients/acme/memory_current.md"
TARGET = "Alder-417-needs-reimage"
CONTROL = "Acme plans a Thursday deployment."
NO_MATCH = "No matching memory."
QUESTIONS = ("Which laptop needs a reimage?", "When does Acme plan to deploy?")
ROUTE = "/clients/acme/memory/ask"
CONVERSATION = "acme"
CALLERS = ("support-lead", "security-analyst")
JUDGES = AnswerJudges(
    (Marker(TARGET), ReviewedAnswers((TARGET,), (CONTROL, NO_MATCH))),
    (Marker(CONTROL), ReviewedAnswers((CONTROL,), (TARGET, NO_MATCH))),
)


class MemoryFiles:
    def __init__(self, root, executable, subject, *, guarded):
        self.root, self.executable, self.guarded = root, executable, guarded
        self.lock = RLock()
        self.journal = CopyJournal(root / "observations.sqlite")
        self.hooks = CopyHooks(self.journal, subject, infer_lineage=True)
        self.lineage = self.hooks.lineage
        self.git("init", "-b", "main", "--template=")
        self.git("config", "core.logAllRefUpdates", "true")
        self.git("config", "gc.auto", "0")
        self._write(CONTROL_FILE, CONTROL.encode())
        self.git("add", "--", CONTROL_FILE)
        self.git("commit", "--no-gpg-sign", "-m", "Add the team deployment note")
        self.clean = self.git("rev-parse", "HEAD").decode().strip()
        self._write(TARGET_FILE, TARGET.encode())
        self.git("add", "--", TARGET_FILE)
        self.git("commit", "--no-gpg-sign", "-m", "Add the synthetic incident note")
        self.private = self.git("rev-parse", "HEAD").decode().strip()
        with Turn("ingest-incident", "support-lead", "memory-index").activate():
            self.hooks.record_copy(VersionRef("git", f"{self.private}:{TARGET_FILE}", sha256(TARGET.encode()).hexdigest()),
                                   action="stored")
        with Turn("initial-memory", "support-lead", "dreaming-agent", parent="ingest-incident").activate():
            self._publish(self._capture())
        self.files = FilesystemCanaryScanner(root)
        self.history = GitHistoryCanaryScanner(root)
        self.worker = WorkerFixture(self._dream, self.read, timeout=25)
        self.hold = self.worker.hold
        self.checkpoint = self.worker.checkpoint
        self.release_and_drain = self.worker.release_and_drain
        self.cancel_and_drain = self.worker.cancel_and_drain

    def git(self, *args):
        return subprocess.check_output(
            [self.executable, "-c", "user.name=Setrya demo", "-c", "user.email=demo@setrya.example",
             "-c", "core.hooksPath=" + str(self.root / "disabled-hooks"), *args],
            cwd=self.root, env=_git_env(), stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )

    def _write(self, relative, content):
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    def _sources(self):
        return {relative: (self.root / relative).read_bytes() for relative in (TARGET_FILE, CONTROL_FILE)
                if (self.root / relative).exists()}

    def _capture(self):
        sources = self._sources()
        if TARGET_FILE in sources:
            self.hooks.record_copy(VersionRef("files", TARGET_FILE, sha256(sources[TARGET_FILE]).hexdigest()),
                                   action="retrieved")
        return sources

    def _publish(self, sources):
        content = b"\n".join(sources.values())
        self._write(DERIVED_FILE, content)
        if TARGET_FILE in sources:
            self.hooks.record_copy(VersionRef("files", DERIVED_FILE, sha256(content).hexdigest()), action="derived")

    def _dream(self, subject, before_write):
        with Turn("late-memory", "scheduled-job", "dreaming-agent", parent="initial-memory").activate():
            with self.lock:
                captured = self._capture()
                # In this disposable workspace the file bytes are the input versions.
                revisions = {path: sha256(data).digest() for path, data in captured.items()}
            before_write()
            with self.lock:
                current = {path: sha256(data).digest() for path, data in self._sources().items()}
                if self.guarded and revisions != current:
                    return
                self._publish(captured)

    def erase(self, subject):
        with self.lock:
            target = self.root / TARGET_FILE
            target.unlink()
            target.parent.rmdir()
            self._publish(self._sources())
            # Each lane owns its disposable repository. Rewrite the synthetic
            # history in both lanes so the broken scan must find the orphan blob.
            self.git("reset", "--mixed", self.clean)
            self.git("reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all")
            if self.guarded:
                self.git("prune", "--expire=now")

    def read(self, subject, caller, conversation, question):
        with self.lock:
            memory = (self.root / DERIVED_FILE).read_text()
        fact = dict(zip(QUESTIONS, (TARGET, CONTROL)))[question]
        return TextAnswer(caller, conversation, ROUTE, question, fact if fact in memory else NO_MATCH)

    def inspect(self, subject, store, key):
        with self.lock:
            if store == "git":
                commit, _, relative = key.partition(":")
                if commit == "blob":
                    objects = self.git("cat-file", "--batch-all-objects", "--batch-check=%(objectname)").decode().splitlines()
                    content = self.git("cat-file", "blob", relative) if relative in objects else None
                else:
                    if relative not in (TARGET_FILE, CONTROL_FILE):
                        raise InputError("memory demo encountered an unexpected Git location")
                    commits = self.git("rev-list", "--all", "--reflog").decode().splitlines()
                    content = self.git("show", key) if commit in commits else None
            else:
                if key not in (TARGET_FILE, CONTROL_FILE, DERIVED_FILE):
                    raise InputError("memory demo encountered an unexpected file location")
                path = self.root / key
                content = path.read_bytes() if path.exists() else None
        if content is None:
            return Stored(key, False, False, False, None)
        return Stored(key, True, TARGET.encode() in content, CONTROL.encode() in content,
                      sha256(content).hexdigest())

    def scan(self, subject, store):
        scanner = self.files if store == "files" else self.history
        with self.lock:
            return scanner.find(scope=".", marker=TARGET)

    def case(self):
        artifacts = (Artifact("files", TARGET_FILE, "delete"), Artifact("files", DERIVED_FILE, "rewrite"),
                     Artifact("files", CONTROL_FILE, "preserve"),
                     Artifact("git", f"{self.private}:{TARGET_FILE}", "delete"),
                     Artifact("git", f"{self.clean}:{CONTROL_FILE}", "preserve"))
        return SharedCase(CONVERSATION, ROUTE, CALLERS, *QUESTIONS, artifacts, ("files", "git"),
                          require_lineage=True, judges=JUDGES)


@contextmanager
def open_fixture(executable, *, guarded):
    subject = Subject.derive(secrets.token_bytes(32), CONVERSATION, "alice", "synthetic-test")
    with TemporaryDirectory(prefix="setrya-memory-workspace-") as folder:
        app = MemoryFiles(Path(folder), executable, subject, guarded=guarded)
        with app.worker:
            item = ExternalItem("provider", "earlier-plaintext", "model-platform", "configuration",
                                "fixture-provider-settings",
                                follow_up=(date.today() + timedelta(days=7)).isoformat(), subject_ref=subject.ref)
            yield subject, app, (item,)


def demo(output, mode):
    executable = shutil.which("git")
    if executable is None:
        raise InputError("install git to run the memory-files demo")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    print("Alice's incident note was deleted. A held agent can still write the captured memory.")
    exit_code = 0
    for lane, expected in (("broken", "FAIL"), ("guarded", "PASS")):
        directory = output / lane
        with open_fixture(executable, guarded=lane == "guarded") as (subject, app, items):
            receipt = run_shared(subject, case=app.case(), application=app, external_items=items,
                                 output=directory, mode=mode, journal=app.journal, cancel_hold=app.cancel_and_drain)
        print(f"{receipt['technical_verdict']}  {lane} · {receipt['review_status']}")
        print("  Replay  " + join(["setrya", "replay", str(directory)]))
        if receipt["technical_verdict"] != expected:
            exit_code = 1
    return exit_code
