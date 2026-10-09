from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('mas1_install', ROOT / 'scripts/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name).resolve() / 'project with spaces'
        self.project.mkdir()

    def run_installer(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scripts/install.py'),
                               '--target', str(self.project), '--runtime', 'both', *args],
                              capture_output=True, text=True)

    def snapshot(self):
        return {str(p.relative_to(self.project)): p.read_bytes()
                for p in self.project.rglob('*') if p.is_file()}

    def test_preview_writes_nothing(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), {})
        self.assertIn('PREVIEW', result.stdout)

    def test_both_preserve_instructions_and_are_idempotent(self):
        existing = '# Project requirements\nPreserve this.\n'
        (self.project / 'AGENTS.md').write_text(existing)
        result = self.run_installer('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.project / 'AGENTS.md').read_text().startswith(existing))
        self.assertEqual(len(list((self.project / '.codex/agents').glob('*.toml'))), 7)
        self.assertEqual(len(list((self.project / '.claude/agents').glob('*.md'))), 7)
        receipt = json.loads((self.project / '.mas1-system/install-receipt.json').read_text())
        self.assertEqual(receipt['runtimes'], ['claude', 'codex'])
        self.assertEqual(len(receipt['backups']), 1)
        self.assertEqual((self.project / receipt['backups'][0]).read_text(), existing)
        before = self.snapshot()
        result = self.run_installer('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_conflict_fails_before_instruction_or_payload_writes(self):
        dest = self.project / '.claude/agents/mas1-portable-worker.md'
        dest.parent.mkdir(parents=True)
        dest.write_text('user-owned file')
        before = self.snapshot()
        result = self.run_installer('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Conflicting managed file', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_instruction_symlink_rejected_without_touching_referent(self):
        external = Path(self.temp.name) / 'private-instructions'
        external.write_text('do not modify')
        (self.project / 'AGENTS.md').symlink_to(external)
        result = self.run_installer('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(external.read_text(), 'do not modify')
        self.assertFalse((self.project / '.mas1-system').exists())

    def test_payload_parent_symlink_rejected(self):
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (self.project / '.mas1-system').symlink_to(outside, target_is_directory=True)
        result = self.run_installer('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_edited_instruction_block_rejected(self):
        (self.project / 'AGENTS.md').write_text(installer.BLOCK.replace('fully', 'partly'))
        before = self.snapshot()
        result = self.run_installer('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Conflicting or malformed', result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_sequential_runtime_installs_merge_receipt(self):
        self.assertEqual(installer.main(['--target', str(self.project), '--runtime', 'codex', '--apply']), 0)
        self.assertFalse((self.project / 'CLAUDE.md').exists())
        self.assertEqual(installer.main(['--target', str(self.project), '--runtime', 'claude', '--apply']), 0)
        receipt = json.loads((self.project / '.mas1-system/install-receipt.json').read_text())
        self.assertEqual(receipt['runtimes'], ['claude', 'codex'])
        self.assertIn('.codex/agents/mas1_portable_worker.toml', receipt['files'])
        self.assertIn('.claude/agents/mas1-portable-worker.md', receipt['files'])

    def test_existing_nonmanaged_instructions_may_evolve(self):
        self.assertEqual(self.run_installer('--apply').returncode, 0)
        p = self.project / 'AGENTS.md'
        p.write_text('# New user rule\n' + p.read_text())
        before = self.snapshot()
        result = self.run_installer('--apply')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_receipt_rejected_before_any_writes(self):
        receipt = self.project / '.mas1-system/install-receipt.json'
        receipt.parent.mkdir()
        receipt.write_text('{broken json')
        before = self.snapshot()
        result = self.run_installer('--apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_missing_target_rejected(self):
        with self.assertRaises(ValueError):
            installer.plan(self.project / 'missing', 'codex')


if __name__ == '__main__':
    unittest.main()
