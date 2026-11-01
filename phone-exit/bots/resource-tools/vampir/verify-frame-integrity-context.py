"""Verify current leaf integrity and ten native backend/writer deliveries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def differences(actual, expected, path='$', limit=16):
    result = []
    def visit(left, right, location):
        if len(result) >= limit:
            return
        if type(left) is not type(right):
            result.append(dict(path=location, actual=left, expected=right))
        elif isinstance(left, dict):
            for key in sorted(set(left) | set(right)):
                child = location + '.' + key
                if key not in left or key not in right:
                    result.append(dict(path=child, actual=left.get(key, '<missing>'),
                                       expected=right.get(key, '<missing>')))
                else:
                    visit(left[key], right[key], child)
                if len(result) >= limit:
                    break
        elif isinstance(left, list):
            if len(left) != len(right):
                result.append(dict(path=location + '.length', actual=len(left), expected=len(right)))
            for index, (a, b) in enumerate(zip(left, right)):
                visit(a, b, location + '[' + str(index) + ']')
                if len(result) >= limit:
                    break
        elif left != right:
            result.append(dict(path=location, actual=left, expected=right))
    visit(actual, expected, path)
    return result[:limit]


def failure_payload(context, contract, spec, actual, wanted, error, *, state='actual_row_mismatch'):
    return dict(schema=1, family=contract.FAMILY, scope=contract.SCOPE,
        method='bounded_native_failure_diagnostic', state=state, accepted=False,
        source_sha256=context['source_sha256'], transfer_proof=context['transfer_proof'],
        context_canonical_sha256=hashlib.sha256(contract.canonical(context).encode('utf-8')).hexdigest(),
        tools=contract.tools(), spec=spec, actual=actual, expected=wanted, error=str(error),
        actual_row_available=actual is not None,
        differences=differences(actual, wanted) if actual is not None else [],
        network_used=False, runtime_activated=False, profile_activated=False)


def dependencies(context, root, core):
    """Check exact parent links; source admission is also enforced by the harness."""
    root = Path(root)
    backend = core.checked(root, context['backend_context'], 'generated-native-contexts')
    wire = core.checked(root, context['wire_context'], 'generated-native-contexts')
    proof = core.checked(root, context['transfer_proof'], 'native-frame-integrity-proofs')
    backend_proof = core.checked(root, backend['transfer_proof'], 'native-login-backend-wire-proofs')
    deps, parents = proof['dependencies'], backend_proof['dependencies']
    if (deps['backend'] != context['backend_context'] or deps['wire'] != context['wire_context']
            or deps['wire'] != backend['wire_context']
            or deps['prepare_check'] != parents['prepare_check']
            or deps['wire_check'] != parents['wire_check']):
        raise ValueError('Frame integrity proof dependency links differ')
    backend_report = core.checked(root, deps['backend_check'], 'native-adapter-checks')
    prepare_report = core.checked(root, deps['prepare_check'], 'native-adapter-checks')
    wire_report = core.checked(root, deps['wire_check'], 'native-adapter-checks')
    # The previous verifier performs only pure dependency/semantic validation;
    # neither its old native harness nor its 1807-case suite is invoked here.
    prepare, parent_wire, parent_prepare_report = load('verify-login-backend-wire-context').dependencies(
        backend, root, core)
    if (parent_wire != wire or parent_prepare_report != prepare_report
            or backend_report.get('context_sha256') != context['backend_context']['sha256']
            or backend_report.get('proof') != backend['transfer_proof']):
        raise ValueError('Frame integrity accepted backend report binding differs')
    source = context['source_sha256']
    if (any(item.get('source_sha256') != source for item in (
            backend, wire, prepare, backend_report, prepare_report, wire_report))
            or proof.get('target', {}).get('source_sha256') != source
            or backend_proof.get('target', {}).get('source_sha256') != source):
        raise ValueError('Frame integrity dependency source differs')
    load('login-backend-wire-native-contracts').validate_report(backend_report, backend, prepare_report)
    load('frame-integrity-oracle').prepared_rows(prepare_report, backend_report)
    return wire, prepare_report, backend_report


def verify(context, root):
    core = load('portable-native-family')
    contract = load('frame-integrity-case-contracts')
    wire, prepare_report, backend_report = dependencies(context, root, core)
    oracle = load('frame-integrity-oracle')
    prepared = oracle.prepared_rows(prepare_report, backend_report)
    harness = load('frame-integrity-harness')
    h = harness.make_harness(context, root=root)
    h.uc = harness.MemoryPolicy(h.uc)
    run = load('frame-integrity-runtime').install(h, context, wire, contract, prepared)
    rows = []
    for spec in contract.scenarios():
        try:
            actual = run(spec)
        except Exception as error:
            payload = failure_payload(context, contract, spec, None, None, error,
                                      state='native_execution_failure')
            target = load('research-workflow').snapshot(Path(root), 'native-frame-integrity-failures', payload)
            raise ValueError('Frame integrity execution failed; diagnostic ' + str(target)) from error
        try:
            oracle.validate_case(actual, spec, prepared)
        except ValueError as error:
            payload = failure_payload(context, contract, spec, actual,
                oracle.expected_case(spec, prepared), error)
            target = load('research-workflow').snapshot(Path(root), 'native-frame-integrity-failures', payload)
            raise ValueError('Frame integrity actual row differs; diagnostic ' + str(target)) from error
        rows.append(actual)
    report = dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native',
        scope=contract.SCOPE, cases=rows, matrix_sha256=contract.matrix_sha256(),
        summary=contract.observed_summary(rows), evidence=h.evidence,
        runtime=harness.runtime_inputs(), metadata_fields=prepare_report['metadata_fields'],
        **contract.EXTENTS, **dict.fromkeys(contract.TRUE_FLAGS, True),
        **dict.fromkeys(contract.FALSE_FLAGS, False), limits=[
            'Three exact source leaves execute as separate explicit primitive entries, including raw CRC continuation, width/signed-length behavior, empty, unaligned and in-place inputs.',
            'Ten direct source backend entries execute the real Login writer, archive routines, CRC initializer/update and XOR without manual helper calls inside a backend entry.',
            'Synthetic packet fields and UTF-16 storage come from four immutable, separately proved parent prepared inputs; preparation, SDK, metadata, publisher, service assignment and session key acquisition are not executed.',
            'The final two entries reuse the same backend/packet; the second observes the native sequence left by the first and only its explicit key field is changed before delivery.',
            'Allocation/initial capacity, state/debug providers, CRT/import effects and transport capture remain bounded fixtures. Actual native ciphertext is captured before archive cleanup; no socket delivery or asynchronous transport ownership is proved.',
            'Exact same-buffer and disjoint XOR are covered; partial overlap, arbitrary buffer sizes, reallocation/aligned/OOM/SEH, receive integrity validation, online admission and Android parity remain outside this scope.'])
    contract.validate_report(report, context, prepare_report, backend_report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-frame-integrity-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
