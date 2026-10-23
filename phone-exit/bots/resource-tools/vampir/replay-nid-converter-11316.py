"""Whole current webViewType converter and its NID extension caller, offline."""
from pathlib import Path
import importlib.util
import json

HERE = Path(__file__).resolve().parent


def replay(root=None):
    spec = importlib.util.spec_from_file_location('nid_converter_extensions', HERE/'replay-nid-extensions-11316.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    report = module.replay(root=root, native_converter=True)
    import hashlib
    report['dependencies'][Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return report


if __name__ == '__main__':
    report = replay()
    spec = importlib.util.spec_from_file_location('nid_converter_save', HERE/'audit-client-release.py')
    audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
    path = audit.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/nid-converter-11316'), report)
    print(json.dumps(dict(report=str(path), converter_cases=len(report['converter_cases']), caller_cases=len(report['cases']))))
