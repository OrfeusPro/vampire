"""Discover direct callers of the source-bound logging owner factory."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_factory_calls', HERE / 'build-nid-user-info-callers.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def build():
    base.TARGETS = {0x14450f420: 'Common log owner factory'}
    result = base.build()
    result['caller_indexer_sha256'] = result.pop('tool_sha256')
    result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


if __name__ == '__main__':
    report = build()
    target = base.native.ROOT / 'code-clues/nid-user-info-factory-callers.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         calls=report['calls'], failed=report['failed_roots'])))
