"""Build the standalone Setrya verifier from its HTML, schema, and locked Go module."""

import argparse
import base64
import gzip
import json
import os
import shutil
import stat
import subprocess
from html import escape
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
BROWSER = ROOT / "scripts/browser-verifier"
REVISION = "go1.27.4"
IN_TOTO = "github.com/in-toto/in-toto-golang"
PATCH = """//go:build js && wasm

package in_toto

import "io/fs"

// Browser verification cannot provide the unrelated filesystem-write helper.
func isWritable(string) error { return fs.ErrPermission }
"""


def render(go, output):
    if output.exists():
        raise ValueError("Choose a new output path for the standalone verifier.")
    environment = dict(os.environ, GOTOOLCHAIN=REVISION, GOOS="js", GOARCH="wasm",
                       CGO_ENABLED="0", GOWORK="off", GOFLAGS="")

    with TemporaryDirectory(prefix="setrya-browser-") as temp:
        module = Path(temp)
        for name in ("go.mod", "go.sum", "main.go"):
            shutil.copyfile(BROWSER / name, module / name)

        def run(*args):
            return subprocess.check_output([go, *args], cwd=module, env=environment, text=True)

        if run("env", "GOVERSION").strip() != REVISION:
            raise ValueError("The browser verifier requires the pinned Go toolchain.")
        downloaded = json.loads(run("mod", "download", "-json", IN_TOTO + "@v0.11.0"))
        if downloaded["Version"] != "v0.11.0":
            raise ValueError("The browser in-toto adjustment applies only to v0.11.0.")
        patched = shutil.copytree(downloaded["Dir"], module / "in-toto-wasm")
        helper = patched / "in_toto/util_unix.go"
        helper.chmod(stat.S_IRUSR | stat.S_IWUSR)
        helper.write_text(PATCH, encoding="utf-8")
        run("mod", "edit", "-replace", f"{IN_TOTO}=./in-toto-wasm")

        goroot = Path(run("env", "GOROOT").strip())
        run("build", "-mod=readonly", "-trimpath", "-ldflags=-s -w -buildid=", "-o", "verifier.wasm", ".")
        # Go's browser runtime must come from the same toolchain as the WASM.
        runtime = (goroot / "lib/wasm/wasm_exec.js").read_text(encoding="utf-8")
        if "</script" in runtime.lower():
            raise ValueError("Unsafe script marker in the embedded Go runtime.")
        compressed = gzip.compress((module / "verifier.wasm").read_bytes(), compresslevel=9, mtime=0)
        engine = base64.b64encode(compressed).decode("ascii")
        module_rows = run("list", "-mod=readonly", "-deps", "-f",
                          '{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Dir}}{{end}}{{end}}', ".")
        notices = [("Go", goroot), ("Setrya", ROOT)]
        notices.extend((name, Path(folder)) for name, folder in sorted({
            tuple(row.split("\t", 1)) for row in module_rows.splitlines() if row
        }))
        license_text = "\n\n".join(f"{name}/{notice.name}\n{notice.read_text(encoding='utf-8', errors='replace')}"
                                   for name, folder in notices
                                   for notice in sorted(folder.iterdir())
                                   if notice.is_file() and notice.name.upper().startswith(("LICENSE", "NOTICE", "COPYING", "PATENTS")))

    source = (ROOT / "docs/verify-offline.html").read_text(encoding="utf-8")
    schema = json.loads((ROOT / "setrya/casework/receipt-exchange-v1.schema.json").read_bytes())
    receipt = json.loads((ROOT / "setrya/erasure/receipt-v3.schema.json").read_bytes())
    producer = {"$schema": receipt["$schema"], "$id": "urn:setrya:producer-provenance:v1",
                "$defs": {name: receipt["$defs"][name] for name in ("producerProvenance", "sha256")},
                "$ref": "#/$defs/producerProvenance"}

    def schema_tag(name, document):
        encoded = json.dumps(document, ensure_ascii=True, separators=(",", ":")).replace("<", r"\u003c")
        return f'<script id="{name}" type="application/json">{encoded}</script>\n'

    embed = (schema_tag("exchange-schema", schema) + schema_tag("producer-schema", producer)
             + f'<script id="offline-wasm" type="application/octet-stream">{engine}</script>\n'
             f'<script>\n{runtime}\n</script>')
    html = source.replace("<!-- SETRYA_BROWSER_ENGINE -->", embed)
    html = html.replace("<!-- SETRYA_BROWSER_LICENSES -->",
                        f"<details><summary>Third-party notices</summary><pre>{escape(license_text)}</pre></details>")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as destination:
        destination.write(html)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go executable to use for the pinned toolchain")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        render(args.go, args.output)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"Browser verifier build failed. {error}\n")
