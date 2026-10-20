"""Reuse verified E8 caller discovery for the actual zeroing UserInfo constructor."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nid_construct_calls', HERE / 'build-nid-user-info-callers.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def build():
    base.TARGETS = {0x14450e830: 'UserInfo zeroing constructor', 0x1455fb2a0: 'UserInfo copy',
                    0x14450f5d0: 'UserInfo owner constructor'}
    report = base.build()
    report['caller_indexer_sha256'] = report.pop('tool_sha256')
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['limitations'].append('Constructor/copy caller identity alone does not prove later field population.')
    return report


if __name__ == '__main__':
    report = build()
    path = base.native.ROOT / 'code-clues/nid-user-info-construct-callers.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         calls=len(report['calls']), roots=sorted({r['root'] for r in report['calls']}),
                         failed=report['failed_roots'])))
