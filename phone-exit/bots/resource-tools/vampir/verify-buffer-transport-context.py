"""Verify new buffer helpers and ordinary queue handoff; never replay parents."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

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
        actual_row_available=actual is not None,
        differences=differences(actual, expected) if actual is not None else [],
        network_used=False, runtime_activated=False, profile_activated=False)


def dependencies(context, root, core):
    """Read and validate the exact accepted wire proof, without its native suite."""
    wire = core.checked(Path(root), context['wire_context'], 'generated-native-contexts')
    report = core.checked(Path(root), context['wire_check'], 'native-adapter-checks')
    proof = core.checked(Path(root), context['transfer_proof'], 'native-buffer-transport-proofs')
    if (wire.get('family') != 'archive-wire'
            or wire.get('source_sha256') != context['source_sha256']
            or report.get('source_sha256') != context['source_sha256']
            or proof.get('target', {}).get('source_sha256') != context['source_sha256']
            or proof.get('dependencies') != dict(wire=context['wire_context'], wire_check=context['wire_check'])):
        raise ValueError('Buffer transport wire dependency source/family differs')
    load('update-native-archive-wire').report_valid(report, wire, context['wire_context']['sha256'])
    contract = load('buffer-transport-case-contracts')
    layout = contract.source_layout(context)
    table = context['source_inputs']['archive_table']
    try:
        leaf_address = wire['archive_helpers']['set_count_leaf']
        leaf = wire['archive_leaves'][leaf_address]
        table_bytes = bytes.fromhex(table['bytes'])
        raw_slot = wire['layout']['archive_slots']['raw']
        if (wire['layout']['archive_bytes'] != contract.EXTENTS['archive_bytes']
                or raw_slot != layout['archive_raw_slot']
                or table['address'] != wire['archive']['table']
                or hashlib.sha256(table_bytes).hexdigest() != wire['archive_table_sha256']
                or struct.unpack_from('<Q', table_bytes, raw_slot)[0] != int(wire['archive']['raw'], 16)
                or wire['archive']['raw'] != context['functions']['archive.raw']
                or wire['archive']['growth'] != context['functions']['vector.resize']
                or layout['set_count_leaf'] != dict(address=leaf_address, bytes=leaf['bytes'])
                or leaf['bytes'] != '895108c3' or leaf['size'] != 4
                or leaf['sha256'] != hashlib.sha256(bytes.fromhex(leaf['bytes'])).hexdigest()):
            raise ValueError('Buffer transport source layout differs from accepted wire profile')
    except (KeyError, TypeError, ValueError, struct.error) as error:
        raise ValueError('Buffer transport source layout differs from accepted wire profile') from error
    return wire


def verify(context, root):
    core = load('portable-native-family')
    contract = load('buffer-transport-case-contracts')
    dependencies(context, root, core)
    oracle = load('buffer-transport-oracle')
    harness = load('buffer-transport-harness')
    h = harness.make_harness(context, root=root)
    run = load('buffer-transport-runtime').install(h, context, contract)
    rows = []
    for spec in contract.scenarios():
        try:
            actual = run(spec)
        except Exception as error:
            payload = failure_payload(context, contract, spec, None, None, error,
                                      state='native_execution_failure')
            target = load('research-workflow').snapshot(Path(root), 'native-buffer-transport-failures', payload)
            raise ValueError('Buffer transport native execution failed; diagnostic ' + str(target)) from error
        try:
            oracle.validate_case(actual, spec)
        except ValueError as error:
            payload = failure_payload(context, contract, spec, actual, oracle.expected_case(spec), error,
                                      state='actual_row_mismatch')
            target = load('research-workflow').snapshot(Path(root), 'native-buffer-transport-failures', payload)
            raise ValueError('Buffer transport actual row differs; diagnostic ' + str(target)) from error
        rows.append(actual)
    report = dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native',
        scope=contract.SCOPE, cases=rows, matrix_sha256=contract.matrix_sha256(),
        summary=contract.observed_summary(rows), evidence=h.evidence,
        runtime=harness.runtime_inputs(), source_layout=contract.source_layout(context),
        wire_context=context['wire_context'], wire_check=context['wire_check'],
        **contract.EXTENTS, **dict.fromkeys(contract.TRUE_FLAGS, True),
        **dict.fromkeys(contract.FALSE_FLAGS, False), limits=[
            'Five whole source roots and one set-count leaf execute in 65 declared cases; cumulative steps reuse the same owned object and storage.',
            'Resize, allocation growth, append, archive raw and ordinary transport return AL1 are native; allocator, sized-free, CRT memory effects and synthetic wake table are explicit bounded fixtures.',
            'Archive state is an ambient 64-byte provider seeded from the accepted source constructor contract; its constructor, packet writer, CRC, transform and cleanup do not execute.',
            'Transport always appends; only state1/busy0 invokes the synthetic wake callback, with checked source receiver and argument. No callback result, delivery, failure/reset or socket claim is made.',
            'Small/aligned growth, byte preservation/zeroing, raw NUL, source immutability, exact helper order, ownership/retirement, guards and Win64 ABI are bounded to the declared matrix.',
            'Negative or overflowing append lengths, malformed descriptors, huge allocation arithmetic, OOM, SEH, queue drain, real wake scheduling, backend lifetime and online admission remain outside this scope.'])
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
    path = load('research-workflow').snapshot(args.root, 'native-buffer-transport-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
