"""Source-bound Login preparation and native sender handoff; no wire emission."""
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


def differences(actual, wanted, path='$', limit=16):
    """Bounded structural diagnostics, independent of native execution."""
    found = []
    def visit(left, right, location):
        if len(found) >= limit:
            return
        if type(left) is not type(right):
            found.append(dict(path=location, actual=left, expected=right))
        elif isinstance(left, dict):
            for key in sorted(set(left) | set(right)):
                if key not in left or key not in right:
                    found.append(dict(path=location + '.' + key,
                        actual=left.get(key, '<missing>'), expected=right.get(key, '<missing>')))
                else:
                    visit(left[key], right[key], location + '.' + key)
                if len(found) >= limit:
                    break
        elif isinstance(left, list):
            if len(left) != len(right):
                found.append(dict(path=location + '.length', actual=len(left), expected=len(right)))
            for i, (a, b) in enumerate(zip(left, right)):
                visit(a, b, location + '[' + str(i) + ']')
                if len(found) >= limit:
                    break
        elif left != right:
            found.append(dict(path=location, actual=left, expected=right))
    visit(actual, wanted, path)
    return found[:limit]


def failure_payload(context, contract, spec, actual, wanted, error):
    return dict(schema=1, family=contract.FAMILY, scope=contract.SCOPE,
        method='bounded_native_failure_diagnostic', state='actual_row_mismatch', accepted=False,
        source_sha256=context['source_sha256'], context_canonical_sha256=hashlib.sha256(
            contract.canonical(context).encode('utf-8')).hexdigest(),
        transfer_proof=context['transfer_proof'], tools=contract.tools(),
        spec=spec, actual=actual, expected=wanted, error=str(error),
        differences=differences(actual, wanted), native_wire_used=False, network_used=False,
        runtime_activated=False, profile_activated=False)


def verify(context, root):
    core = load('portable-native-family')
    contract = load('login-send-handoff-case-contracts')
    prepare = core.checked(Path(root), context['prepare_context'], 'generated-native-contexts')
    functions = {int(at, 16) for at in context['functions'].values()}
    leaves = {int(at, 16): value for at, value in context['leaves'].items()}
    harness = load('verify-login-send-handoff-harness')
    h = harness.make_harness(context, context['exports'], functions, leaves=leaves, root=root)
    proof = core.checked(Path(root), context['transfer_proof'], 'native-login-send-handoff-proofs')
    parent_report = core.checked(Path(root), proof['dependencies']['prepare_check'], 'native-adapter-checks')
    oracle = load('login-send-handoff-oracle')
    prepared_rows = oracle.prepared_rows(parent_report)
    h.uc = harness.MemoryPolicy(h.uc)
    run = load('login-send-handoff-runtime').install(h, prepare, context, contract)
    cases = []
    for spec in contract.scenarios():
        row = run(spec)
        try:
            oracle.validate_case(row, spec, prepared_rows)
        except ValueError as error:
            wanted = oracle.expected_case(spec, prepared_rows)
            payload = failure_payload(context, contract, spec, row, wanted, error)
            target = load('research-workflow').snapshot(Path(root), 'native-login-send-handoff-failures', payload)
            raise ValueError('Login send handoff actual row differs; diagnostic ' + str(target)) from error
        cases.append(row)
    report = dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native',
        scope=contract.SCOPE, cases=cases, evidence=h.evidence, runtime=harness.runtime_inputs(),
        metadata_fields=parent_report['metadata_fields'], packet_bytes=320, session_bytes=160,
        **{flag: True for flag in contract.TRUE_FLAGS},
        **{flag: False for flag in contract.FALSE_FLAGS},
        limits=[
            'Whole preparation/constructor, three SDK getters, six metadata roots and sender execute native source instructions; seven returning leaves include the service getter.',
            'The sender duplicate gate, default-timeout fallback and virtual service call execute natively over synthetic pending state.',
            'Pending insert, delegate/add and the synthetic service vtable sink are explicit fixtures. The service vtable is not claimed to come from native source.',
            'The sink observes the same prepared packet and UTF-16 strings; it serializes or emits no bytes. Parent wire evidence is a separate schema/reference dependency.',
            'SDK/backend/provider, map/variant/string-storage, allocation/destructor, notifications and import/security effects remain bounded fixtures.',
            'No native wire, framing/integrity, transport, server acceptance, Version send, responses, clock/heartbeat/world, authorization, profile activation or online session proof.'])
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
    target = load('research-workflow').snapshot(args.root, 'native-login-send-handoff-checks', report)
    print(json.dumps(dict(report=str(target), cases=len(report['cases']))))
