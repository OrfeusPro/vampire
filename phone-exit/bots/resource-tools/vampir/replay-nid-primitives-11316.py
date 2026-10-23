"""Execute actual current numeric/channel helpers and OnResult caller, offline."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def replay(root=None):
    spec=importlib.util.spec_from_file_location('nid_primitives_caller',HERE/'replay-nid-result-11316.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    report=module.replay(root=root,native_primitives=True)
    report['dependencies'][Path(__file__).name]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return report


if __name__=='__main__':
    report=replay()
    spec=importlib.util.spec_from_file_location('nid_primitives_save',HERE/'audit-client-release.py')
    audit=importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
    path=audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/nid-primitives-11316'),report)
    print(json.dumps(dict(report=str(path),caller_cases=len(report['cases']),
        numeric=len(report['primitive_cases']['numeric']),channels=len(report['primitive_cases']['channels']))))
