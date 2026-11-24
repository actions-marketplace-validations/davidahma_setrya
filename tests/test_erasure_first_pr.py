"""Keep the first-PR instructions, downloaded workflow and generated starter in sync."""
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from setrya import __version__


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = "docs/examples/first-pr/setrya.yml"


def installation_block(path):
    blocks = re.findall(r"```sh\n(.*?)\n```", (ROOT / path).read_text(), re.S)
    return next(block for block in blocks if "git add " in block)


class FirstPrInstructions(unittest.TestCase):
    def test_marketplace_description_fits_the_publishing_limit(self):
        lines = (ROOT / "action.yml").read_text().splitlines()
        description = next(line.removeprefix("description: ").strip() for line in lines
                           if line.startswith("description: "))
        self.assertTrue(description)
        self.assertLess(len(description), 125)

    def test_two_committed_files_match_the_release_workflow(self):
        commands = installation_block("README.md")
        self.assertEqual(commands, installation_block("docs/github-action.md"))
        name = "setrya-case"
        starter = f"{name}/test_erasure.py"
        destination = ".github/workflows/setrya.yml"
        self.assertIn(f"setrya init --output {name}\n", commands)
        self.assertIn(f"setrya doctor --starter {starter} --mode deletion\n", commands)
        self.assertIn(f"git add {starter} {destination}\n", commands)
        self.assertIn(f"/releases/download/v{__version__}/setrya-quickstart.yml -o {destination}\n", commands)
        workflow = (ROOT / TEMPLATE).read_text()
        for text in (commands, workflow):
            self.assertIn(f"python -m pip install setrya=={__version__}\n", text)
        pins = re.findall(r"uses: davidahma/setrya@(\S+) # (\S+)", workflow)
        self.assertEqual(len(pins), 2)
        self.assertEqual(pins[0], pins[1])
        self.assertRegex(pins[0][0], r"^[a-f0-9]{40}$")
        self.assertEqual(pins[0][1], __version__)
        self.assertEqual(re.findall(r"^\s+starter: (\S+)$", workflow, re.M), [starter])
        self.assertEqual(re.findall(r"^\s+mode: (\S+)$", workflow, re.M), ["deletion"])


    def test_release_gate_requires_both_quickstart_pins_at_the_tag_commit(self):
        secret_free_commit = "a5" * 20
        script = ROOT / "scripts/render-action-workflow.py"
        with TemporaryDirectory() as temp:
            path = Path(temp) / "setrya-quickstart.yml"
            cli = [sys.executable, "-I", str(script), "--commit", secret_free_commit]
            subprocess.run([*cli, "--output", str(path)], check=True, capture_output=True)
            text = path.read_text()
            self.assertEqual(text.count(f"uses: davidahma/setrya@{secret_free_commit}"), 2)
            subprocess.run([*cli, "--expect", str(path)], check=True, capture_output=True)
            path.write_text(text.replace(secret_free_commit, "b6" * 20, 1))
            result = subprocess.run([*cli, "--expect", str(path)], capture_output=True)
            self.assertEqual(result.returncode, 2)
