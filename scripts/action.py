"""Run the installed CLI, or update a PR comment using only bounded review signals."""
from collections import Counter
from importlib import metadata
import json
import os
from pathlib import Path
import re
import sys
import tomllib
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

LABELS = ("PASS", "FAIL", "ERROR", "NOT TESTED")
EXPECTED = {"PASS": {"OPEN_ITEMS", "READY_FOR_REVIEW"}, "FAIL": {"RESIDUAL_FOUND"},
            "ERROR": {"OPEN_ITEMS", "UNAVAILABLE"}, "NOT TESTED": {"OPEN_ITEMS", "UNAVAILABLE"}}
MARKER = "<!-- setrya:erasure-verdict:v1 -->"
# Only these public descriptions can cross from fixture execution into the privileged comment job.
REASONS = {
    "answer": ("The endpoint returned the erased finding", "answers"),
    "control": ("A required retained finding disappeared", "answers"),
    "store": ("A direct store read found a residual or an unexpected change", "stored"),
    "discovered": ("A discovered copy still exists", "discovered"),
    "canary": ("A scanner found the synthetic marker", "scans"),
    "failure": ("A required erasure check failed", None),
    "worker": ("A required worker observation is missing", None),
    "baseline": ("The pre-erasure baseline is incomplete", None),
    "gap": ("A required observation is missing or uncertain", None),
    "provider": ("Provider configuration needs review", None),
    "retention": ("A retention obligation needs review", None),
    "open": ("An external obligation needs review", None),
    "error": ("An adapter reported an error", None),
}
PHASES = {"baseline": "baseline", "immediate": "after erasure", "final": "final read", "case": "case"}

def summary(code, review):
    if code not in ("0", "1", "2", "3") or review not in EXPECTED[LABELS[int(code)]]:
        raise ValueError("invalid receipt summary")
    return f"**Setrya · {LABELS[int(code)]}** (exit {code})  \nCase review: `{review}`."

def signals(receipt):
    counts = Counter()
    case = receipt["case"]
    callers = set(case["callers"])
    stores = {f"{row['store']}/{row['key']}" for row in case["artifacts"]}
    for failure in receipt["failures"]:
        kind = "failure"
        if "recovered the erased finding" in failure:
            kind = "answer"
        elif "lost the retained finding" in failure:
            location = failure.rsplit(" lost the retained finding at ", 1)[0]
            if location in callers and location not in stores:
                kind = "control"
            elif location in stores and location not in callers:
                kind = "store"
        elif failure.startswith("Discovered copy ") and " still exists at " in failure:
            kind = "discovered"
        elif "Canary found in " in failure:
            kind = "canary"
        elif any(fragment in failure for fragment in ("still exists at ", "contains the erased finding", "artifact ")):
            kind = "store"
        phase = next((p for p, label in PHASES.items() if failure.endswith(f" at {label}.")), "case")
        counts[kind, phase] += 1
    for gap in receipt["gaps"]:
        kind = "worker" if "attempt through erasure" in gap else "baseline" if "positive baseline" in gap else "gap"
        counts[kind, "case"] += 1
    for item in receipt["open_items"]:
        kind = {"configuration": "provider", "retained": "retention"}.get(item["kind"], "open")
        counts[kind, "case"] += 1
    if receipt["errors"]:
        counts["error", "case"] = len(receipt["errors"])
    return [[kind, phase, min(n, 9999)] for (kind, phase), n in sorted(counts.items())]

def detail_lines(encoded):
    if len(encoded) > 4096:
        raise ValueError("oversized evidence summary")
    rows = json.loads(encoded or "[]")
    if not isinstance(rows, list) or len(rows) > len(REASONS) * len(PHASES):
        raise ValueError("invalid evidence summary")
    lines = []
    for row in rows:
        if type(row) is not list or len(row) != 3:
            raise ValueError("invalid evidence row")
        kind, phase, n = row
        if kind not in REASONS or phase not in PHASES or type(n) is not int or not 1 <= n <= 9999:
            raise ValueError("invalid evidence summary")
        label, group = REASONS[kind]
        location = f" (`erasure-evidence.json#/{phase}/{group}`)" if group and phase != "case" else ""
        lines.append(f"- {label} · {PHASES[phase]} ({n}){location}")
    return "\n".join(lines)

def append(variable, message):
    with Path(os.environ[variable]).open("a", encoding="utf-8") as out:
        print(message, file=out)

def require_version():
    import setrya
    source = Path(__file__).resolve().parents[1] / "pyproject.toml"
    expected = tomllib.loads(source.read_text(encoding="utf-8"))["project"]["version"]
    if metadata.version("setrya") != expected or setrya.__version__ != expected:
        raise ValueError(f"Install setrya=={expected} for this Action.")

def run():
    folder = Path(os.environ["SETRYA_OUTPUT"]).absolute()
    review, code, rows = "UNAVAILABLE", 2, []
    try:
        require_version()
    except (ImportError, metadata.PackageNotFoundError, ValueError) as exc:
        print(f"Setrya Action requires its matching Python package. {exc}", file=sys.stderr)
    else:
        try:
            from setrya.erasure.cli import run_person_starter
            from setrya.receipts import report
            code, receipt = run_person_starter(Path(os.environ["SETRYA_STARTER"]), os.environ["SETRYA_MODE"], folder)
            if receipt is not None:
                report(receipt)
                review = receipt["review_status"]
                rows = signals(receipt)
        except Exception as exc:
            print(f"Setrya action error ({type(exc).__name__}).", file=sys.stderr)
            code, review, rows = 2, "UNAVAILABLE", []
    encoded = json.dumps(rows, separators=(",", ":"))
    append("GITHUB_OUTPUT", f"exit-code={code}\nreview-status={review}\nevidence-summary={encoded}")
    append("GITHUB_STEP_SUMMARY", summary(str(code), review) + "\n\n" + detail_lines(encoded))
    return code

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def api(method, path, body=None):
    root = os.environ["GITHUB_API_URL"].rstrip("/")
    url = root + "/" + path
    if urlsplit(root).scheme != "https":
        raise ValueError("expected an HTTPS GitHub API")
    req = Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                  headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json",
                           "Content-Type": "application/json", "User-Agent": "setrya-action"})
    with build_opener(NoRedirect()).open(req, timeout=20) as result:
        return json.load(result)

def comment():
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise ValueError("use the comment operation only on a pull_request event")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    repo = os.environ["GITHUB_REPOSITORY"]
    number, run_id = event["number"], os.environ["GITHUB_RUN_ID"]
    pr = event["pull_request"]
    server = os.environ["GITHUB_SERVER_URL"].rstrip("/")
    if (type(number) is not int or number < 1 or not re.fullmatch(r"[\w.-]+/[\w.-]+", repo, re.ASCII)
            or not re.fullmatch(r"[0-9]+", run_id) or pr["base"]["repo"]["full_name"] != repo
            or not re.fullmatch(r"[0-9a-f]{40}", pr["head"]["sha"]) or urlsplit(server).scheme != "https"):
        raise ValueError("invalid pull request coordinates")
    review = os.environ["SETRYA_REVIEW"]
    body = MARKER + "\n" + summary(os.environ["SETRYA_CODE"], review)
    details = detail_lines(os.environ.get("SETRYA_SUMMARY", ""))
    if details:
        body += "\n\n" + details
    run_url = f"{server}/{repo}/actions/runs/{run_id}"
    artifact = os.environ.get("SETRYA_ARTIFACT", "")
    if artifact and not re.fullmatch(r"[1-9][0-9]{0,20}", artifact):
        raise ValueError("invalid receipt artifact ID")
    body += f"\n\n[Workflow run]({run_url})"
    if review != "UNAVAILABLE":
        if artifact:
            body += f" · [Download the receipt]({run_url}/artifacts/{artifact})"
        body += "\n\nUnzip `setrya-receipt` and run `setrya replay .` inside it."
    prefix = f"repos/{repo}"
    path = f"{prefix}/issues/{number}/comments"
    page = 1
    comment_id = None
    while True:
        comments = api("GET", f"{path}?per_page=100&page={page}")
        for row in comments:
            if (row["user"]["login"] == "github-actions[bot]" and row["user"]["type"] == "Bot"
                    and (row.get("body") or "").startswith(MARKER + "\n")):
                comment_id = int(row["id"])
                break
        if comment_id or len(comments) < 100:
            break
        page += 1
    if api("GET", f"{prefix}/pulls/{number}")["head"]["sha"] != pr["head"]["sha"]:
        print("Skipped the verdict for a superseded PR commit.")
        return 0
    if comment_id:
        api("PATCH", f"{prefix}/issues/comments/{comment_id}", {"body": body})
    else:
        api("POST", path, {"body": body})
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit({"run": run, "comment": comment}[sys.argv[1]]())
    except (KeyError, TypeError, OSError, ValueError) as exc:
        print(f"Setrya action error ({type(exc).__name__}).", file=sys.stderr)
        raise SystemExit(2)
