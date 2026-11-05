"""Изолированное исполнение одной явной группы unittest после ownership handshake."""
import argparse
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import unittest


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('utf-8')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def ids(suite):
    result = []
    for test in suite:
        result.extend(ids(test) if isinstance(test, unittest.TestSuite) else [test.id()])
    return result


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.subtest_failures = []
        self.subtest_errors = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def addSubTest(self, test, subtest, error):
        if error is not None:
            row = dict(id=subtest.id(), parent=test.id(), traceback=self._exc_info_to_string(error, test))
            target = self.subtest_failures if issubclass(error[0], test.failureException) else self.subtest_errors
            target.append(row)
        super().addSubTest(test, subtest, error)


def execute(workspace, definition):
    workspace = Path(workspace)
    sys.path.insert(0, str(workspace / 'phone-exit/bots'))
    sys.path.insert(0, str(workspace / 'phone-exit/.tools/vampir-analysis'))
    runtime = definition.get('runtime', {})
    for name in runtime.get('distributions', {}):
        spec = importlib.util.find_spec(name)
        if (spec is None or spec.origin is None
                or str(Path(spec.origin).resolve()) not in runtime.get('files', {})):
            raise ValueError('Isolated worker runtime origin differs: ' + name)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in definition['group']['test_modules']:
        spec = importlib.util.find_spec(name)
        source = (workspace / 'phone-exit/bots' / (name + '.py')).resolve()
        if spec is None or spec.origin is None or Path(spec.origin).resolve() != source:
            raise ValueError('Worker test import origin differs from its pinned source: ' + name)
        suite.addTests(loader.loadTestsFromModule(importlib.import_module(name)))
    test_ids = ids(suite)
    started = time.monotonic()
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=Result).run(suite)
    def traced(rows):
        return [dict(id=test.id(), traceback=trace) for test, trace in rows]
    return dict(schema=1, producer='tooling-group-worker-v1',
                group_id=definition['group']['id'], definition_sha256=fingerprint(definition),
                state='passed' if result.wasSuccessful() else 'failed',
                test_ids=test_ids, started_ids=result.started_ids, tests_run=result.testsRun,
                skipped=[dict(id=test.id(), reason=reason) for test, reason in result.skipped],
                failures=traced(result.failures), errors=traced(result.errors),
                expected_failures=traced(result.expectedFailures),
                unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
                subtest_failures=result.subtest_failures, subtest_errors=result.subtest_errors,
                duration_seconds=time.monotonic() - started)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--definition', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--fixture-root', required=True, type=Path)
    args = parser.parse_args()
    # Parent assigns this waiting process to its Job before allowing any imports.
    if sys.stdin.buffer.readline() != b'GO\n':
        raise ValueError('Tooling worker did not receive its ownership handshake')
    definition = json.loads(args.definition.read_bytes())
    root = args.fixture_root.resolve()
    if not root.is_dir():
        raise ValueError('Parent-owned fixture directory is missing')
    os.environ['PHONEEXIT_VAMPIR_RESOURCES'] = str(root / 'vampir')
    os.environ['PHONEEXIT_RF_RESOURCES'] = str(root / 'rf')
    result = execute(args.workspace, definition)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as stream:
        stream.write(canonical(result))
    raise SystemExit(0 if result['state'] == 'passed' else 1)


if __name__ == '__main__':
    main()
