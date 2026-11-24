"""Create and verify a signed assessment of two disposable repositories."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def run(*args, cwd=None, expected=0, env=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, env=env, timeout=90, check=False)
    if result.returncode != expected:
        raise RuntimeError(f"{args[:4]} returned {result.returncode}.\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def git(repo, *args):
    return run("git", "-C", str(repo), *args)


def write_repo(repo, old, new):
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Setrya fixture")
    git(repo, "config", "user.email", "fixture@example.invalid")
    app = repo / "app.py"
    app.write_text(old)
    git(repo, "add", "app.py")
    git(repo, "commit", "-qm", "Add fixture")
    base = git(repo, "rev-parse", "HEAD")
    app.write_text(new)
    git(repo, "commit", "-qam", "Change fixture app")
    return base, git(repo, "rev-parse", "HEAD")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir()
    cli = (sys.executable, "-m", "setrya")
    with TemporaryDirectory(prefix="setrya-assessment-") as temp:
        scratch = Path(temp)
        support, billing = scratch / "support", scratch / "billing"
        base, head = write_repo(support, "from redis import Redis\ncache = Redis()\n",
                                "from redis import Redis\ncache = Redis()\ncache.set('note', 'fixture')\n")
        _, billing_head = write_repo(billing, 'name = "original"\n', 'name = "updated"\n')
        review = scratch / "copy-review.json"
        run(*cli, "discovery", "copy-check", "--repo", str(support), "--base", base,
            "--candidate", head, "--output", str(review), expected=3)
        report = json.loads(review.read_bytes())
        if not any(row["kind"] == "cache" and row["path"] == "app.py" and row["line"] == 3
                   and isinstance(row.get("starter"), dict) and row["status"] == "needs-review"
                   for row in report["sites"]):
            raise RuntimeError("The Redis change needs a copy coverage mapping.")
        workspace = scratch / "workspace"
        run(*cli, "demo", "--output", str(workspace))
        plan = scratch / "plan.json"
        plan.write_text(json.dumps({"format": "setrya.assessment-input.v1", "repositories": [
            {"name": "support", "commit": head, "checks": ["copy-review.json"],
             "receipts": ["workspace/guarded"]},
            {"name": "billing", "commit": billing_head, "checks": [], "receipts": []},
        ]}))
        env = {**os.environ, "COSIGN_PASSWORD": ""}
        run("cosign", "generate-key-pair", cwd=scratch, env=env)
        bundle = out / "assessment"
        run(*cli, "assess", "build", "--plan", str(plan), "--output", str(bundle),
            "--key", str(scratch / "cosign.key"), env=env)
        public = out / "synthetic-issuer.pub"
        public.write_bytes((scratch / "cosign.pub").read_bytes())
        text = run(*cli, "assess", "verify", str(bundle), "--key", str(public))
        if "1 of 1" not in text or "1 PASS" not in text or "## billing" not in text:
            raise RuntimeError("The verified assessment lacks the expected results.")
        exchange = out / "exchange"
        run(*cli, "receipt", "pack", str(workspace / "guarded"), "--output", str(exchange), "--synthetic",
            "--system", "synthetic-support", "--system-version", "1",
            "--key", str(scratch / "cosign.key"), env=env)
    print(text)


if __name__ == "__main__":
    main()
