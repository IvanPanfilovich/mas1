#!/usr/bin/env python3
"""Install MAS1 portable into an existing project. Preview by default."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
MARKER_START = '<!-- MAS1-PORTABLE:BEGIN -->'
MARKER_END = '<!-- MAS1-PORTABLE:END -->'
BLOCK = f'''{MARKER_START}
## MAS1 portable

When explicitly asked to use **MAS1 portable**, read `.mas1-system/MAS1-portable.md`
fully and apply protocol `MAS1-portable/1`. Delegate bounded work when useful and
permitted by the runtime. Use the installed portable roles when available.
This is a separate adaptation, not canonical MAS1 v6.1 compliance. Do not replace
an existing canonical MAS1 trigger or claim unavailable model/review/test evidence.
{MARKER_END}
'''


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def no_symlinks(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(f'Symlink destination is not supported: {component}')


def plan(target: Path, runtime: str) -> tuple[list[tuple[Path, bytes, str]], dict[str, str]]:
    no_symlinks(target)
    if not target.is_dir():
        raise ValueError('Target must be an existing project directory')
    payload: dict[Path, bytes] = {}
    for source in [ROOT / 'prompts/MAS1-portable.md', ROOT / 'docs/compatibility.md',
                   *sorted((ROOT / 'templates').glob('*.md'))]:
        relative = Path('templates') / source.name if source.parent.name == 'templates' else Path(source.name)
        payload[target / '.mas1-system' / relative] = source.read_bytes()
    changes: list[tuple[Path, bytes, str]] = []
    managed: dict[str, str] = {}
    for client in ('codex', 'claude'):
        if runtime not in (client, 'both'):
            continue
        for source in sorted((ROOT / 'adapters' / client / 'agents').iterdir()):
            payload[target / f'.{client}' / 'agents' / source.name] = source.read_bytes()
        instruction = target / ('AGENTS.md' if client == 'codex' else 'CLAUDE.md')
        no_symlinks(instruction)
        if instruction.exists() and not instruction.is_file():
            raise ValueError(f'Instruction destination is not a file: {instruction}')
        original = instruction.read_text(encoding='utf-8') if instruction.exists() else ''
        if MARKER_START in original or MARKER_END in original:
            if original.count(MARKER_START) != 1 or original.count(MARKER_END) != 1 or BLOCK not in original:
                raise ValueError(f'Conflicting or malformed managed instruction block: {instruction}')
        else:
            updated = original + ('\n\n' if original and not original.endswith('\n\n') else '') + BLOCK
            changes.append((instruction, updated.encode(), 'append-instructions'))
    for destination, data in sorted(payload.items()):
        no_symlinks(destination)
        managed[str(destination.relative_to(target))] = digest(data)
        if destination.exists():
            if not destination.is_file() or destination.read_bytes() != data:
                raise ValueError(f'Conflicting managed file; inspect it manually: {destination}')
        else:
            changes.append((destination, data, 'create'))
    receipt = target / '.mas1-system/install-receipt.json'
    no_symlinks(receipt)
    if receipt.exists():
        if not receipt.is_file():
            raise ValueError('Installation receipt is not a regular file')
        previous = json.loads(receipt.read_text())
        if (not isinstance(previous, dict) or previous.get('protocol') != 'MAS1-portable/1'
                or previous.get('target') != str(target)
                or not isinstance(previous.get('files'), dict)
                or not isinstance(previous.get('backups'), list)
                or not isinstance(previous.get('runtimes'), list)
                or any(value not in ('codex', 'claude') for value in previous['runtimes'])):
            raise ValueError('Invalid or mismatched installation receipt')
    return changes, managed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--runtime', required=True, choices=['codex', 'claude', 'both'])
    parser.add_argument('--apply', action='store_true', help='write the previewed installation')
    args = parser.parse_args(argv)
    target = args.target.expanduser().absolute()
    try:
        changes, managed = plan(target, args.runtime)
        print('APPLY' if args.apply else 'PREVIEW — no files will be written')
        for path, _, action in changes:
            print(f'  {action}: {path.relative_to(target)}')
        if not changes:
            print('Already installed; no changes needed.')
            return 0
        if not args.apply:
            print('Repeat with --apply after inspecting the plan.')
            return 0
        backups: list[str] = []
        for path, data, action in changes:
            path.parent.mkdir(parents=True, exist_ok=True)
            if action == 'append-instructions' and path.exists():
                backup = target / '.mas1-system/backups' / f'{path.name}.{uuid.uuid4().hex}.bak'
                no_symlinks(backup)
                backup.parent.mkdir(parents=True, exist_ok=True)
                with backup.open('xb') as handle:
                    handle.write(path.read_bytes())
                backups.append(str(backup.relative_to(target)))
                path.write_bytes(data)
            else:
                with path.open('xb') as handle:
                    handle.write(data)
        receipt_path = target / '.mas1-system/install-receipt.json'
        previous = json.loads(receipt_path.read_text()) if receipt_path.is_file() else {}
        files = previous.get('files', {})
        files.update(managed)
        files.update({str(path.relative_to(target)): digest(data) for path, data, _ in changes})
        receipt = {'protocol': 'MAS1-portable/1', 'target': str(target),
                   'runtimes': sorted(set(previous.get('runtimes', [])) | ({'codex', 'claude'} if args.runtime == 'both' else {args.runtime})),
                   'files': files, 'backups': previous.get('backups', []) + backups}
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        print('Installed. Open a fresh session and verify available roles before use.')
        return 0
    except (ValueError, OSError, UnicodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
