"""Whole current handler for four pre-gate error codes with explicit services.

Does not execute result gate, successful-login branch, UI callbacks or backend
services. Every unexpected native target remains rejected by the shared harness.
"""
import argparse
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


def admit(context, root):
    # A family name or self-declared layout cannot grant native execution.
    from types import SimpleNamespace
    if (context.get('family') != 'login-handler-early' or not context.get('transfer_proof')
            or any(key in context for key in ('function_budget', 'budget_scope', 'native_admission', 'native_handler'))):
        raise ValueError('Portable Login handler admission scope differs')
    index = load('knowledge-index').api()
    args = SimpleNamespace(root=Path(root), knowledge=HERE / 'knowledge')
    args.source_store = load('update-bindings').SourceStore(index, args.root)
    adapter = load('update-native-login-handler').select('login-handler-early')
    if len(adapter.roots(context)) != 1:
        raise ValueError('Portable Login handler root count differs')
    adapter.validate(index, args, context)
    args.source_store.validate()


def verify(context, root):
    admit(context, root)
    handler = int(context['functions']['handler'], 16)
    fixtures = {name: int(at, 16) for name, at in context['fixtures'].items()}
    h = load('update-native-harness').make_harness(
        context, context['exports'], {handler}, root=Path(root))
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    body = bindings.rows(native, h.image, handler)
    calls = {r['direct_target'] for r in body if r['call']}
    if set(fixtures.values()) - calls or len(set(fixtures.values())) != len(fixtures):
        raise ValueError('Pre-gate service declarations differ')
    call_sites = {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands'] for r in body if r['call']}
    if context['call_sites']['handler'] != call_sites:
        raise ValueError('Pre-gate complete call sites differ')
    if handler in fixtures.values():
        raise ValueError('Pre-gate fixture overlaps handler')
    packet, optional, localizer = [h.scratch + off for off in (0x1000, 0x4000, 0x5000)]
    state, events = {}, []

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def empty_string(at):
        require(h.scratch <= at <= h.scratch + 0x38000 - 16, 'Pre-gate string fixture bounds')
        h.uc.mem_write(at, bytes(16))

    def fixture(name):
        def execute(machine):
            a, b, c, d = [reg(n) for n in ('RCX', 'RDX', 'R8', 'R9')]
            value = 0
            if name == 'string_init':
                empty_string(a)
            elif name == 'log':
                require(b & 0xffffffff == 0x309, 'Pre-gate log selector differs')
            elif name == 'free':
                raise ValueError('Empty string fixture unexpectedly freed')
            elif name == 'localizer':
                value = localizer
            elif name == 'localized':
                require(a == localizer, 'Pre-gate localizer receiver differs')
                empty_string(b)
            elif name == 'popup54':
                require(state['code'] == 54, 'Pre-gate popup code differs')
                require(h.scratch <= a < h.scratch + 0x38000 and h.scratch <= b < h.scratch + 0x38000,
                        'Pre-gate popup fixture bounds')
                require(d == 0, 'Pre-gate popup final argument differs')
            elif name in ('optional_9818', 'optional_90021'):
                value = optional if state['present'] else 0
            elif name == 'optional_prepare':
                require(a == optional and state['present'], 'Pre-gate optional prepare receiver differs')
            elif name == 'error_9818':
                require(a == optional and b & 0xffffffff == state['code'] and state['code'] in (9818, 9819),
                        'Pre-gate optional error arguments differ')
            elif name == 'error_90021':
                require(a == optional and state['present'] and state['code'] == 90021,
                        'Pre-gate dedicated error receiver differs')
            elif name == 'error_finish':
                require(a == 0, 'Pre-gate error finish argument differs')
            else:
                raise ValueError('Undeclared pre-gate fixture')
            call_at = int.from_bytes(h.uc.mem_read(reg('RSP'), 8), 'little') - 5
            require(call_sites.get(hex(call_at)) == hex(fixtures[name]), 'Pre-gate captured caller/target differs')
            events.append(dict(action=name, call_offset=call_at-handler, arguments_checked=True))
            h.finish(value)
        return execute

    for name, at in fixtures.items():
        h.add_fixture(at, fixture(name))
    abi = {name: 0x1122334400000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i): 0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
    cases = []
    for poison in (0x55, 0xaa):
        for code, present in [(54, False)] + [(code, present) for code in (9818, 9819, 90021) for present in (False, True)]:
            state.clear()
            state.update(code=code, present=present)
            events.clear()
            payload = bytearray([poison] * 0x160)
            struct.pack_into('<I', payload, 0x10, code)
            guarded = b'\xa5' * 16 + payload + b'\xa6' * 16
            h.uc.mem_write(packet - 16, bytes(guarded))
            h.uc.mem_write(optional - 16, b'\xa5' * 16 + bytes([poison]) * 0x100 + b'\xa6' * 16)
            optional_before = bytes(h.uc.mem_read(optional - 16, 0x120))
            for name, value in abi.items():
                h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
            h.uc.reg_write(h.x.UC_X86_REG_RDX, 0x12345678)
            h.uc.reg_write(h.x.UC_X86_REG_R8, packet)
            h.call(handler, h.scratch + 0x6000)
            actions = [e['action'] for e in events]
            expected = ['string_init', 'log']
            if code == 54:
                expected += ['string_init', 'localizer', 'localized', 'popup54']
            elif code in (9818, 9819):
                expected += ['optional_9818'] + (['optional_prepare', 'error_9818'] if present else []) + ['error_finish']
            else:
                expected += ['optional_90021'] + (['error_90021'] if present else []) + ['error_finish']
            require(actions == expected, 'Pre-gate action order differs')
            require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                    'Pre-gate handler ABI differs')
            require(bytes(h.uc.mem_read(packet - 16, len(guarded))) == bytes(guarded), 'Pre-gate packet/canaries changed')
            require(bytes(h.uc.mem_read(optional - 16, 0x120)) == optional_before, 'Pre-gate optional/canaries changed')
            cases.append(dict(code=code, optional_present=present, poison=poison,
                              events=list(events), guards=True, abi=True))
    return dict(schema=1, method='bounded_native', source_sha256=context['source_sha256'], handler=hex(handler), cases=cases,
                exports=context['exports'], runtime=load('update-native-harness').runtime_inputs(),
                network_used=False, profile_activated=False, runtime_activated=False,
                gate_executed=False, successful_login_executed=False,
                limits=['Whole handler executes only pre-gate error paths 54, 9818, 9819, 90021.',
                        'Empty string/localization, logging, popup, optional lookup/actions and finalization are explicit fixtures.',
                        'Popup callbacks, native result gate, successful-login branch, nested decoder and real services/session are not proven.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--context', type=Path, required=True)
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    path = load('research-workflow').snapshot(args.root, 'portable-login-handler-early', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
