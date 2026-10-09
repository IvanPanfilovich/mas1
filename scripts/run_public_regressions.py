#!/usr/bin/env python3
"""Run original public ledger regressions; explicitly skip private witnesses."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_CLASSES = {'LegacyV60AuditMigrationTests', 'PostMigrationRepresentabilityTests'}
EXCLUDED_METHODS = {
    'test_r004_compatibility_table_001_through_013_and_dom_golden',
    'test_lower_bound_phase5q_production_entry_rejects_complete_evidence_tampering',
}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main() -> int:
    sys.path.insert(0, str(ROOT / 'tools'))
    import test_mas1_ledger_core as source
    suite = unittest.defaultTestLoader.loadTestsFromModule(source)
    selected = []
    excluded = []
    for case in flatten(suite):
        if case.__class__.__name__ in EXCLUDED_CLASSES or case._testMethodName in EXCLUDED_METHODS:
            # A standard unittest skip preserves exclusion counts in its result.
            excluded.append(case.id())
            case = unittest.FunctionTestCase(lambda: None, description=case.id())
            def skip():
                raise unittest.SkipTest('Requires private source-machine witness data; not publicly verified')
            case._testFunc = skip
        selected.append(case)
    print(f'Public original regression suite: {len(selected)} tests; {len(excluded)} explicit private-evidence skips', flush=True)
    for name in sorted(EXCLUDED_CLASSES | EXCLUDED_METHODS):
        print(f'  excluded: {name}', flush=True)
    result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(selected))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
