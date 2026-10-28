"""Exercise the exact CI shell loop against safe temporary fixtures."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ShellChecks(unittest.TestCase):
    def test_later_invalid_script_fails_ci_command(self):
        workflow = (ROOT / '.github/workflows/tests.yml').read_text()
        # No YAML dependency: extract the literal shell-check block used by CI.
        block = workflow.split('      - name: Shell syntax checks\n        run: |\n', 1)[1]
        command = '\n'.join(line[10:] for line in block.splitlines() if line.startswith('          '))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts').mkdir()
            (root / 'docker').mkdir()
            first = root / 'scripts/a.sh'
            later = root / 'scripts/z.sh'
            entry = root / 'docker/entrypoint.sh'
            for file in (first, later, entry):
                file.write_text('echo valid\n')
            def run():
                return subprocess.run(['bash', '-c', command], cwd=root, capture_output=True).returncode
            self.assertEqual(0, run())
            later.write_text('if then\n')
            self.assertNotEqual(0, run())
            later.write_text('echo valid\n')
            entry.write_text('if then\n')
            self.assertNotEqual(0, run())
