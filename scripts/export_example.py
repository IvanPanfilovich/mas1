#!/usr/bin/env python3
"""Export a SYNTHETIC regression fixture, never real execution evidence."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads((ROOT / 'tools/mas1-ledger-fixtures.json').read_text())['base_ledgers']['no_roots']
    with args.output.open('x') as handle:
        handle.write(json.dumps(fixture, indent=2) + '\n')
    print('SYNTHETIC fixture exported. Dates/models/tokens are test inputs, not execution evidence.')
