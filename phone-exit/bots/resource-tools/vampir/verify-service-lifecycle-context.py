"""Новый bounded native lifecycle; родительские replay suites не вызываются."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import traceback

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
            for i, (a, b) in enumerate(zip(left, right)):
                visit(a, b, location + '[' + str(i) + ']')
                if len(result) >= limit:
                    break
        elif left != right:
            result.append(dict(path=location, actual=left, expected=right))
    visit(actual, expected, path)
    return result[:limit]


def failure_payload(context, contract, spec, actual, expected, error, *, state):
    return dict(schema=1, family=contract.FAMILY, scope=contract.SCOPE,
        method='bounded_native_failure_diagnostic', state=state, accepted=False,
        source_sha256=context['source_sha256'], transfer_proof=context['transfer_proof'],
        context_canonical_sha256=hashlib.sha256(contract.canonical(context).encode('utf-8')).hexdigest(),
        tools=contract.tools(), spec=spec, actual=actual, expected=expected, error=str(error),
        error_type=type(error).__name__,
        traceback=''.join(traceback.format_exception(type(error), error, error.__traceback__)),
        actual_row_available=actual is not None,
        differences=differences(actual, expected) if actual is not None else [],
        network_used=False, runtime_activated=False, profile_activated=False)


def dependencies(context, root, core):
    """Точные принятые parent pointers; только чистая проверка готового report."""
    parent = core.checked(Path(root), context['backend_context'], 'generated-native-contexts')
    report = core.checked(Path(root), context['backend_check'], 'native-adapter-checks')
    proof = core.checked(Path(root), context['transfer_proof'], 'native-service-lifecycle-proofs')
    if (parent.get('family') != 'login-backend-wire'
            or parent.get('source_sha256') != context['source_sha256']
            or report.get('source_sha256') != context['source_sha256']
            or proof.get('target', {}).get('source_sha256') != context['source_sha256']
            or proof.get('dependencies') != dict(backend=context['backend_context'],
                                                backend_check=context['backend_check'])):
        raise ValueError('Service lifecycle dependency source/family/links differ')
    # report_valid reads the accepted preparation report and checks its rows;
    # it does not call verify(), native harnesses or any parent scenario runner.
    api = load('update-native-login-backend-wire').select('login-backend-wire')
    api.report_valid(report, parent, context['backend_context']['sha256'])
    return parent


def verify(context, root):
    core = load('portable-native-family')
    contract = load('service-lifecycle-case-contracts')
    dependencies(context, root, core)
    oracle = load('service-lifecycle-oracle')
    harness = load('service-lifecycle-harness')
    h = harness.make_harness(context, root=root)
    run = load('service-lifecycle-runtime').install(h, context, contract)
    rows = []
    for spec in contract.scenarios():
        try:
            actual = run(spec)
        except Exception as error:
            payload = failure_payload(context, contract, spec, None, None, error,
                                      state='native_execution_failure')
            path = load('research-workflow').snapshot(Path(root), 'native-service-lifecycle-failures', payload)
            raise ValueError('Service lifecycle native execution failed; diagnostic ' + str(path)) from error
        try:
            oracle.validate_case(actual, spec)
        except ValueError as error:
            payload = failure_payload(context, contract, spec, actual, oracle.expected_case(spec), error,
                                      state='actual_row_mismatch')
            path = load('research-workflow').snapshot(Path(root), 'native-service-lifecycle-failures', payload)
            raise ValueError('Service lifecycle actual row differs; diagnostic ' + str(path)) from error
        rows.append(actual)
    report = dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native',
        scope=contract.SCOPE, cases=rows, matrix_sha256=contract.matrix_sha256(),
        summary=contract.observed_summary(rows), evidence=h.evidence, runtime=harness.runtime_inputs(),
        backend_context=context['backend_context'], backend_check=context['backend_check'],
        **contract.EXTENTS, **dict.fromkeys(contract.TRUE_FLAGS, True),
        **dict.fromkeys(contract.FALSE_FLAGS, False), limits=[
            'Twelve whole roots and one 21-byte source control-disposal dispatch capsule execute in 42 cases, each repeated with two independently seeded allocator/stack poison patterns.',
            'Source publisher, assignment, constructors, atomic strong/weak transitions and native virtual deletion/reset/string-ring paths use the same objects throughout each declared lifetime.',
            'Service/backend/control extents are 240/800/24 bytes. The old 784-byte backend proof is only a separately accepted parent; its suite and buffer/frame suites are never replayed here.',
            'Callback storage 48 bytes, token, callback destruction/resize, vector helpers, engine members, iterator find/reserve/remove and external registration context are explicit bounded fixtures.',
            'Native callback construction preserves the uninitialized allocator qword at +8 and copies actual stack poison at +0x2c; no zero-initialization of either is claimed.',
            'Destructor leaves service backend/control slots dangling. Snapshots are captured while readable, and no reconstruction/repeated-destruction or safe backlink reuse is claimed.',
            'The shared old backend remains under an explicit external strong owner through service deletion, then a declared native move/release disposes it; no fixture decrements native-owned counts.',
            'Retained external strong/weak owners and destructed storage without bit0 free are explicit final observations, not leaks silently balanced by synthetic native cleanup.',
            'Local insertion always reserves after the native base constructor. Global spare storage is an explicit input before entry; no mid-native mutation invents a local spare-capacity branch.',
            'Every case explicitly fixes cleanup_find=end for opaque destructor/reset lookup. Iterator remove is an unmodelled trap; native unregistration and successful engine cleanup of registered observers are not claimed.',
            'Single-thread fixtures exclude actual allocator/OS/engine/callback/container behavior, scheduling, OOM/SEH, races, process init/shutdown owner, sockets/drain and online admission.'])
    contract.validate_report(report, context)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result['context_sha256'] = hashlib.sha256(args.context.read_bytes()).hexdigest()
    result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    path = load('research-workflow').snapshot(args.root, 'native-service-lifecycle-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), rounds=result['summary']['rounds'])))
