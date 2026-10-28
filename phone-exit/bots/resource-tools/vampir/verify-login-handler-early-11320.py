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
ROOT = Path('F:/PhoneExit Resources/Vampir')
SOURCE = '544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
HANDLER = 0x14679e2d0
EXPORT_RUN = 'run-cc90e4f503ac'
EXPORT_SHA = '2573e9f84adce9d0123cc47079b60ea1c48d476da4cb5142430a12e296acdc04'
FIXTURES = {
    'string_init': 0x141426b90,
    'log': 0x141403bd0,
    'free': 0x1414830e0,
    'localizer': 0x1445cd4e0,
    'localized': 0x1445cf040,
    'popup54': 0x144a516e0,
    'optional_9818': 0x146673500,
    'optional_prepare': 0x144a5bf20,
    'error_9818': 0x1466816d0,
    'optional_90021': 0x145e30870,
    'error_90021': 0x145e3b720,
    'error_finish': 0x144a779a0,
}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def context(root=ROOT):
    return dict(source_sha256=SOURCE,
                source=str(Path(root) / 'client-code-snapshots' / SOURCE / 'ProjectRED-Win64-Shipping.exe'),
                helpers=dict(memcpy='0x1487f8c59'), verify_whole_exports=True)


def verify(root=ROOT):
    h = load('update-native-harness').make_harness(
        context(root), {EXPORT_RUN: EXPORT_SHA}, {HANDLER}, root=Path(root))
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    body = bindings.rows(native, h.image, HANDLER)
    calls = {r['direct_target'] for r in body if r['call']}
    if set(FIXTURES.values()) - calls or len(set(FIXTURES.values())) != len(FIXTURES):
        raise ValueError('Pre-gate service declarations differ')
    if HANDLER in FIXTURES.values():
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
            events.append(dict(action=name, args=[a, b, c, d]))
            h.finish(value)
        return execute

    for name, at in FIXTURES.items():
        h.add_fixture(at, fixture(name))
    abi = {name: 0x1122334400000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
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
            h.call(HANDLER, h.scratch + 0x6000)
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
    return dict(schema=1, source_sha256=SOURCE, handler=hex(HANDLER), cases=cases,
                exports={EXPORT_RUN: EXPORT_SHA}, runtime=load('update-native-harness').runtime_inputs(),
                network_used=False, profile_activated=False, runtime_activated=False,
                gate_executed=False, successful_login_executed=False,
                limits=['Whole handler executes only pre-gate error paths 54, 9818, 9819, 90021.',
                        'Empty string/localization, logging, popup, optional lookup/actions and finalization are explicit fixtures.',
                        'Popup callbacks, native result gate, successful-login branch, nested decoder and real services/session are not proven.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    result = verify(args.root)
    path = load('research-workflow').snapshot(args.root, 'login-handler-early-11320', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
