#!/usr/bin/env python3
"""Verify integrity, canonical source boundaries, and public agent formats."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from manifest import ROOT, files


def main() -> int:
    failures: list[str] = []
    entries: dict[str, str] = {}
    for row in (ROOT / 'SHA256SUMS').read_text().splitlines():
        sha, name = row.split('  ', 1)
        p = Path(name)
        if p.is_absolute() or '..' in p.parts or name in entries:
            failures.append('Unsafe or duplicate manifest entry')
            continue
        entries[name] = sha
    actual = {p.relative_to(ROOT).as_posix() for p in files()}
    if actual != set(entries):
        failures.append(f'Manifest inventory mismatch: {sorted(actual.symmetric_difference(entries))}')
    for name, sha in entries.items():
        path = ROOT / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            failures.append(f'Checksum mismatch: {name}')
    version = json.loads((ROOT / 'VERSION.json').read_text())
    if version['canonical_prompt_sha256'] != 'e8944e86049bb21196604a7a77470a7fe47a084cb8ddfed01964e2ef22a4b08f':
        failures.append('Unexpected canonical prompt identity')
    unchanged = [name for name in version['source_sha256'] if name.startswith(('prompts/', 'profiles/'))
                 or name.endswith(('schema.json', 'fixtures.json'))]
    for name in unchanged:
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != version['source_sha256'][name]:
            failures.append(f'Preserved source changed: {name}')
    for path in ROOT.rglob('*.py'):
        if '.venv' not in path.parts and '__pycache__' not in path.parts:
            ast.parse(path.read_text(), filename=str(path))
    for path in (ROOT / 'adapters/codex/agents').glob('*.toml'):
        profile = tomllib.loads(path.read_text())
        if not all(profile.get(k) for k in ('name', 'description', 'developer_instructions')):
            failures.append(f'Incomplete profile: {path.name}')
        if 'model' in profile or 'model_reasoning_effort' in profile:
            failures.append(f'Portable default should inherit model and effort: {path.name}')
        expected = 'workspace-write' if profile['name'].endswith('_worker') else 'read-only'
        if profile.get('sandbox_mode') != expected:
            failures.append(f'Unexpected sandbox request: {path.name}')
    for path in (ROOT / 'adapters/claude/agents').glob('*.md'):
        text = path.read_text()
        header = text.split('---', 2)[1]
        if not all(re.search(rf'^{field}: .+', header, re.M) for field in ('name', 'description', 'tools', 'model')):
            failures.append(f'Incomplete Claude profile: {path.name}')
        if 'model: inherit' not in header:
            failures.append(f'Unexpected portable model default: {path.name}')
        if not path.stem.endswith('-worker') and 'tools: Read, Glob, Grep\n' not in header:
            failures.append(f'Unexpected read-only tool surface: {path.name}')
    secrets = re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{30,}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----)')
    for path in files():
        if path.name == '.env' or 'witness' in path.relative_to(ROOT).parts:
            failures.append(f'Forbidden publication file: {path.relative_to(ROOT)}')
        if secrets.search(path.read_text(errors='replace')):
            failures.append(f'Potential credential in {path.relative_to(ROOT)} (value withheld)')
    if failures:
        print('\n'.join('FAIL: ' + f for f in failures))
        return 1
    print(f'PASS: {len(entries)} checksums; preserved sources; Python syntax; adapter formats; heuristic credential scan')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
