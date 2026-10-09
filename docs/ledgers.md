# Ledger tooling

Requires Python 3.11+, POSIX (macOS/Linux or WSL), and `jsonschema`. The core imports `fcntl` for filesystem locking; native Windows is not supported for these tools.

`mas1_ledger_core.validate_ledger` remains the sole production validator and derived-facts entry point. The analyzer and fixture runner consume its results. The JSON Schema alone is not sufficient for causal and chronological checks.

```bash
python3 tools/validate-mas1-ledger-fixtures.py
python3 tools/analyze-mas1-ledgers.py --help
```

To inspect a fully synthetic fixture without treating it as execution evidence:

```bash
python3 scripts/export_example.py --output /tmp/mas1-synthetic-example.json
```

The exported file is a regression fixture, not a real task record. Its historical dates and model fields are test inputs. Never submit it as actual adoption, runtime identity, usage, or closure evidence.

To use the core from Python, add `tools/` to your module path and supply the schema:

```python
import json
import sys
from pathlib import Path

repo = Path('/absolute/path/to/mas1')
sys.path.insert(0, str(repo / 'tools'))
from mas1_ledger_core import validate_ledger

schema = json.loads((repo / 'tools/mas1-finding-ledger-v1.schema.json').read_text())
ledger = json.loads(Path('/absolute/path/to/finding-ledger.v1.json').read_text())
result = validate_ledger(ledger, schema)
print(result.valid, result.reasons)
```

A basic structural/procedural pass does not by itself establish live filesystem bindings, marker integrity, a complete rollout population, or truthful runtime evidence. Use the analyzer's documented inputs and original protocol for those claims. With `--cutover`, a dispatched frozen population is mandatory; without it, scope is unbounded and cross-task completeness is not claimed.

Portable prose ledgers use `templates/finding-ledger.md`. The original core is intentionally not modified to accept portable model substitutions or portable closure claims.
