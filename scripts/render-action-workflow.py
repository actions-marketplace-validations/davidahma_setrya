"""Generate or verify the quickstart workflow for an immutable release commit."""

import argparse
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
ACTION_REFERENCE = re.compile(rb"(uses: davidahma/setrya@)[a-f0-9]{40}(?=\s)")


def render(template, commit):
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Use the full release commit SHA.")
    workflow, count = ACTION_REFERENCE.subn(lambda match: match[1] + commit.encode("ascii"), template)
    if count != 2 or workflow.count(b"uses: davidahma/setrya@") != 2:
        raise ValueError("Expected both Setrya uses in the two-job quickstart.")
    return workflow


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--expect", type=Path)
    args = parser.parse_args()
    workflow = render((ROOT / "docs/examples/first-pr/setrya.yml").read_bytes(), args.commit)
    if args.expect:
        if args.expect.read_bytes() != workflow:
            parser.error("Published quickstart differs from the release commit's generated workflow.")
    else:
        with args.output.open("xb") as stream:
            stream.write(workflow)


if __name__ == "__main__":
    main()
