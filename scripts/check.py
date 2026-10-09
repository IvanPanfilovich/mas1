#!/usr/bin/env python3
"""Run deterministic public distribution checks without global configuration writes."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
commands = [
    ['scripts/verify.py'],
    ['-m', 'unittest', 'discover', '-s', 'tests', '-v'],
    ['tools/validate-mas1-ledger-fixtures.py'],
    ['scripts/run_public_regressions.py'],
]
if __name__ == '__main__':
    if sys.version_info < (3, 11):
        print('MAS1 public checks require Python 3.11+. Select a supported interpreter.', file=sys.stderr)
        raise SystemExit(2)
    for command in commands:
        print('+', sys.executable, *command, flush=True)
        result = subprocess.run([sys.executable, *command], cwd=ROOT)
        if result.returncode:
            raise SystemExit(result.returncode)
    print('All public distribution checks passed. Private historical exclusions and live-runtime limits still apply.')
