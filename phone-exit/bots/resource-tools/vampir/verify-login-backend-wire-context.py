"""Actual publisher/prepare/backend/native-wire composition with bounded effects."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def differences(actual, expected, path='$', limit=16):
    """Retain a bounded diagnostic of the completed actual row."""
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
        source_sha256=context['source_sha256'], context_canonical_sha256=hashlib.sha256(
            contract.canonical(context).encode('utf-8')).hexdigest(),
        transfer_proof=context['transfer_proof'], tools=contract.tools(),
        spec=spec, actual=actual, expected=wanted, error=str(error),
        actual_row_available=actual is not None,
        differences=differences(actual, wanted) if actual is not None else [], network_used=False,
        runtime_activated=False, profile_activated=False)


def dependencies(context, root, core):
    """Resolve exact declared parents; no old suite or adaptive source fallback."""
    root = Path(root)
    handoff = core.checked(root, context['handoff_context'], 'generated-native-contexts')
    wire = core.checked(root, context['wire_context'], 'generated-native-contexts')
    prepare = core.checked(root, handoff['prepare_context'], 'generated-native-contexts')
    proof = core.checked(root, context['transfer_proof'], 'native-login-backend-wire-proofs')
    parent_proof = core.checked(root, handoff['transfer_proof'], 'native-login-send-handoff-proofs')
    deps = proof['dependencies']
    if (deps['handoff'] != context['handoff_context'] or deps['wire'] != context['wire_context']
            or deps['prepare_check'] != parent_proof['dependencies']['prepare_check']):
        raise ValueError('Backend native proof dependency links differ')
    prepared_report = core.checked(root, deps['prepare_check'], 'native-adapter-checks')
    handoff_report = core.checked(root, deps['handoff_check'], 'native-adapter-checks')
    wire_report = core.checked(root, deps['wire_check'], 'native-adapter-checks')
    if (any(value.get('source_sha256') != context['source_sha256'] for value in (
            handoff, wire, prepare, prepared_report, handoff_report, wire_report))
            or any(value.get('target', {}).get('source_sha256') != context['source_sha256']
                   for value in (proof, parent_proof))):
        raise ValueError('Backend native dependency source differs')
    load('login-send-handoff-case-contracts').validate_report(handoff_report, handoff, prepared_report)
    load('login-backend-wire-oracle').validate_schema(wire['packets']['game-login'])
    return prepare, wire, prepared_report


def verify(context, root):
    core = load('portable-native-family')
    contract = load('login-backend-wire-native-contracts')
    prepare, wire, parent_report = dependencies(context, root, core)
    oracle = load('login-backend-wire-native-oracle')
    prepared = oracle.prepared_rows(parent_report)
    harness = load('verify-login-backend-wire-harness')
    h = harness.make_harness(context, context['exports'],
        {int(at, 16) for at in context['functions'].values()},
        leaves={int(at, 16): raw for at, raw in context['leaves'].items()},
        tails={int(at, 16): raw for at, raw in context['tails'].items()}, root=root)
    h.uc = harness.MemoryPolicy(h.uc)
    run = load('login-backend-wire-runtime').install(h, prepare, context, wire, contract)
    rows = []
    for spec in contract.scenarios():
        try:
            actual = run(spec)
        except Exception as error:
            # A fixture/native guard can fail before a complete observation row
            # exists. Preserve that concrete failure without manufacturing one.
            payload = failure_payload(context, contract, spec, None, None, error,
                                      state='native_execution_failure')
            target = load('research-workflow').snapshot(Path(root), 'native-login-backend-wire-failures', payload)
            raise ValueError('Login backend wire execution failed; diagnostic ' + str(target)) from error
        try:
            oracle.validate_case(actual, spec, prepared)
        except ValueError as error:
            wanted = oracle.expected_case(spec, prepared)
            payload = failure_payload(context, contract, spec, actual, wanted, error)
            target = load('research-workflow').snapshot(Path(root), 'native-login-backend-wire-failures', payload)
            raise ValueError('Login backend wire actual row differs; diagnostic ' + str(target)) from error
        rows.append(actual)
    report = dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native',
        scope=contract.SCOPE, cases=rows, evidence=h.evidence, runtime=harness.runtime_inputs(),
        metadata_fields=parent_report['metadata_fields'], matrix_sha256=contract.matrix_sha256(),
        summary=contract.observed_summary(rows), **contract.EXTENTS,
        **dict.fromkeys(contract.TRUE_FLAGS, True), **dict.fromkeys(contract.FALSE_FLAGS, False),
        limits=[
            'Whole publisher setup and one preparation delivery execute admitted source instructions, including the service table/thunk, backend, packet ID, Login/string/UTF-8 writers, archive append and cleanup.',
            'Publisher zeroes service+0x10; the later ambient backend binding remains an explicit provider, without a native backend assignment or concurrent publication/lifetime claim.',
            'Pending insert/delegate, SDK/provider/map/variant/string storage, initial 1024-byte growth, allocator/destructor, notifications and security/import effects remain bounded fixtures.',
            'The archive-flags global aliases the preparation enum provider: the same current seeded value (0 or 0xffffffff) feeds packet+0x120 and both constructor arguments. The immutable source-initial value 1 remains a source anchor, not a per-case argument claim.',
            'Checksum returns the declared fixture constant after checking the actual inner bytes. Transform checks the exact key/in-place span and performs identity; neither real integrity nor encryption is proved.',
            'Transport captures the actual native frame before both native archive cleanups and prepare destruction; its return AL is a fixture effect, not network or server acceptance.',
            'No reallocation/aligned/OOM/SEH, asynchronous ownership, native checksum/cipher/transport, Version send, responses, clock/heartbeat/world, profile/runtime activation or online session admission.'])
    contract.validate_report(report, context, parent_report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    report = verify(json.loads(args.context.read_text('utf-8')), args.root)
    report['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = load('research-workflow').snapshot(args.root, 'native-login-backend-wire-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
