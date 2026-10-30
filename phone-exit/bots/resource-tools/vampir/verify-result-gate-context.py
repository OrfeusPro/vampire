"""Proof-bound result gate; whole returns and bounded indexed dispatch only.

State/error services are fixtures. Indexed cases stop at a selected instruction
before that branch executes; they make no claim about a returned ABI or service.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CODES = (0, 1, 42, 58, 708, 1304, 0xffffffff, 0x1197)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def admit(context, root):
    if (context.get('family') != 'result-gate' or not context.get('transfer_proof')
            or any(key in context for key in ('function_budget', 'budget_scope', 'native_admission', 'native_handler'))):
        raise ValueError('Portable result gate admission scope differs')
    index = load('knowledge-index').api()
    args = SimpleNamespace(root=Path(root), knowledge=HERE / 'knowledge')
    args.source_store = load('update-bindings').SourceStore(index, args.root)
    adapter = load('update-native-response').select('result-gate')
    if adapter.roots(context) != {int(context['function'], 16)}:
        raise ValueError('Portable result gate needs exactly one checked root')
    adapter.validate(index, args, context)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    image = args.source_store.image(native, context['source_sha256'])
    rules = load('result-gate-transfer-rules')
    rules.rows(native, image, context)
    rules.export_coverage(args.root, context, native, bindings, image)
    args.source_store.validate()


def verify(context, root):
    admit(context, root)
    function = int(context['function'], 16)
    # The inline table is not code. Its exact separation and full 251-instruction
    # coverage are checked by the proof rule, not the ordinary unwind normalizer.
    view = dict(context, verify_whole_exports=False)
    h = load('update-native-harness').make_harness(view, context['exports'], {function}, root=Path(root))
    rules, native, bindings = load('result-gate-transfer-rules'), load('build-native-entry-code'), load('update-bindings')
    rows = rules.rows(native, h.image, context)
    rules.export_coverage(Path(root), context, native, bindings, h.image)
    if len(rows) != 251:
        raise ValueError('Portable result gate instruction coverage differs')
    switch = context['switch']
    targets = [h.image.pe.base + value for value in struct.unpack('<4I', bytes.fromhex(switch['table_bytes']))]
    index_bytes = bytes.fromhex(switch['index_bytes'])
    fixtures = {name: int(at, 16) for name, at in context['fixtures'].items()}
    state, temporary = h.scratch + 0x1000, h.scratch + 0x2000
    current, events, selected = {}, [], {}

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def fixture(name):
        def execute(machine):
            return_address = int.from_bytes(h.uc.mem_read(reg('RSP'), 8), 'little')
            call_at = return_address - 5
            require(context['call_sites'].get(hex(call_at)) == hex(fixtures[name]), 'Gate fixture caller/target differs')
            value = 0
            if name == 'gate_state':
                value = state
            elif name == 'gate_error':
                require((reg('RCX') & 0xffffffff) == current['code'] and reg('RDX') == 0,
                        'Gate error arguments differ')
            else:
                raise ValueError('Unreviewed gate service fixture')
            events.append(dict(action=name, call_offset=call_at-function, arguments_checked=True))
            h.finish(value)
        return execute

    for name, at in fixtures.items():
        h.add_fixture(at, fixture(name))

    import unicorn
    def branch_selected(machine, at, size, unused):
        if selected.get('enabled') and at in targets:
            selected['target'] = at
            h.uc.emu_stop()
    h.uc.hook_add(unicorn.UC_HOOK_CODE, branch_selected)
    abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM'+str(i): 0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})

    def seed(code, flag):
        current.update(code=code); events.clear()
        state_bytes = bytearray(b'\x5a' * 16); state_bytes[8] = flag
        h.uc.mem_write(state - 16, b'\xa5' * 16 + state_bytes + b'\xa6' * 16)
        h.uc.mem_write(temporary - 16, b'\xa5' * 16 + bytes(24) + b'\xa6' * 16)
        return bytes(h.uc.mem_read(state - 16, 48)), bytes(h.uc.mem_read(temporary - 16, 56))

    def guards(before):
        require(bytes(h.uc.mem_read(state - 16, 48)) == before[0], 'Gate state/guards changed')
        require(bytes(h.uc.mem_read(temporary - 16, 56)) == before[1], 'Gate temporary/guards changed')

    cases = []
    for code in CODES:
        for flag in (0, 1):
            before = seed(code, flag); selected.clear()
            for name, value in abi.items():
                h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
            h.uc.reg_write(h.x.UC_X86_REG_RDX, 2)
            h.uc.reg_write(h.x.UC_X86_REG_R8, temporary)
            h.uc.reg_write(h.x.UC_X86_REG_R9, 0)
            returned = h.call(function, code) & 255
            require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                    'Whole gate ABI differs')
            guards(before)
            cases.append(dict(code=code, state_flag=flag, returned=returned, events=list(events),
                              guards=True, abi=True, state_guards=True, temporary_guards=True))

    switch_cases = []
    for number, slot in enumerate(index_bytes):
        code = switch['input_first'] + number
        before = seed(code, 0); selected.clear(); selected['enabled'] = True
        for name, value in dict(RSP=h.scratch+0x38000, RCX=code, RDX=2, R8=temporary, R9=0).items():
            h.uc.reg_write(getattr(h.x, 'UC_X86_REG_'+name), value)
        h.uc.mem_write(h.scratch + 0x38000, struct.pack('<Q', h.scratch + 0x3f000))
        h.uc.emu_start(function, 0, count=2000)
        require(selected.get('target') == targets[slot] and reg('RIP') == targets[slot], 'Native gate selected wrong target')
        guards(before)
        switch_cases.append(dict(code=code, index=slot, target=hex(selected['target']), events=list(events),
            stopped_before_target=True, abi_return_checked=False, external_branch_services_executed=False,
            state_guards=True, temporary_guards=True, guards=True))
    selected['enabled'] = False
    return dict(schema=1, method='bounded_native', source_sha256=context['source_sha256'], function=context['function'],
        cases=cases, switch_cases=switch_cases, runtime=load('update-native-harness').runtime_inputs(),
        code_instructions=251, exports=context['exports'], network_used=False, profile_activated=False, runtime_activated=False,
        handler_executed=False, login_handoff_executed=False, session_executed=False,
        limits=['One native gate with two explicit state/error fixtures; only 16 declared full-return cases have ABI checks.',
                '227 indexed cases stop before the selected branch instruction; branch services and return ABI are unproved.',
                'No result handler, registration, Login handoff, real service effects or live session.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    path = load('research-workflow').snapshot(args.root, 'native-result-gate-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), switch_cases=len(result['switch_cases']))))
