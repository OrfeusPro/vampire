"""Bounded native preset completion, including deferred-queue selection."""
import importlib.util
import json
from pathlib import Path


def run():
    path = Path(__file__).with_name('replay-release-preset-initializer.py')
    spec = importlib.util.spec_from_file_location('preset_completion_initializer', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.run(completion=True)


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['postconstruct_cases']))))
