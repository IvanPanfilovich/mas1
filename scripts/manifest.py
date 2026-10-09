#!/usr/bin/env python3
"""Generate SHA256SUMS for public distribution files."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_DIRS = {'.git', '__pycache__', '.venv', 'venv', '.pytest_cache', 'dist', '.mas1'}
EXCLUDED_NAMES = {'SHA256SUMS', '.DS_Store', '.coverage'}


def files() -> list[Path]:
    return [p for p in sorted(ROOT.rglob('*')) if p.is_file()
            and not EXCLUDED_DIRS.intersection(p.relative_to(ROOT).parts)
            and p.name not in EXCLUDED_NAMES and p.suffix not in {'.pyc', '.pyo'}]


if __name__ == '__main__':
    rows = [f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT).as_posix()}' for p in files()]
    (ROOT / 'SHA256SUMS').write_text('\n'.join(rows) + '\n')
    print(f'Wrote checksums for {len(rows)} files')
