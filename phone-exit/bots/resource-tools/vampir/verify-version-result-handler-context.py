"""Current VersionResult registration window, handler, gate and captured Login handoff."""
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


def verify(context, root):
    functions = {name: int(at, 16) for name, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(functions.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    rows = {name: bindings.rows(native, h.image, at) for name, at in functions.items()}
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in items if r['call']} for name, items in rows.items()}
    if calls != context['call_sites']:
        raise ValueError('VersionResult handler/gate call sites differ')

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    window = context['registration_window']
    at, code = int(window['address'], 16), bytes.fromhex(window['bytes'])
    require(len(code) <= 128 and data(at, len(code)) == code
            and hashlib.sha256(code).hexdigest() == window['sha256'], 'VersionResult registration window differs')
    require(h.image.pe.base + h.image.roots[h.image.containing(at)][0] == int(window['owner'], 16),
            'VersionResult registration owner differs')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, at))
    require(sum(r.size for r in instructions) == len(code), 'VersionResult registration instruction gap')
    require([(hex(r.address), r.mnemonic, r.op_str) for r in instructions] == [tuple(r) for r in window['instructions']],
            'VersionResult registration arguments differ')
    table = int(context['handler_table'], 16)
    lea = next(r for r in instructions if r.mnemonic == 'lea' and r.operands[1].type == native.X86_OP_MEM
               and r.operands[1].mem.base == native.X86_REG_RIP)
    require(lea.address + lea.size + lea.operands[1].mem.disp == table
            and struct.unpack('<Q', data(table + 0x10, 8))[0] == functions['handler'],
            'VersionResult handler registration link differs')
    packet_table = int(context['packet_table'], 16)
    require(struct.unpack('<Q', data(packet_table + 0x28, 8))[0] == int(context['id_getter'], 16),
            'VersionResult handler ID link differs')
    require(any(r['mnemonic'] == 'jmp' and r['direct_target'] == int(context['login_prepare'], 16)
                for r in rows['handler']), 'VersionResult Login tail handoff differs')
    constructor = int(context['packet_constructor'], 16)
    require(any(r.mnemonic == 'call' and r.operands[0].imm == constructor for r in instructions),
            'VersionResult registered constructor differs')
    constructor_rows = list(decoder.disasm(bytes.fromhex(context['leaves'][hex(constructor)]), constructor))
    first = constructor_rows[0]
    require(first.mnemonic == 'lea' and first.address + first.size + first.operands[1].mem.disp == packet_table,
            'VersionResult constructor table differs')

    uc, x = h.uc, h.x
    packet, state, peer = [h.scratch + n for n in (0x1000, 0x2000, 0x3000)]
    current, events = {}, []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def fixture(machine, name):
        value = 0
        if name == 'string_init':
            require(h.scratch + 0x30000 <= reg('RCX') < h.scratch + 0x38000, 'Handler string destination differs')
            put(reg('RCX'), 'QII', 0, 0, 0)
        elif name == 'log':
            pass
        elif name == 'free':
            require(reg('RCX') == 0, 'Unexpected allocated string in handler fixture')
        elif name == 'gate_state':
            value = state
        elif name == 'gate_error':
            require(reg('RCX') & 0xffffffff == current['code'] and reg('RDX') == 0, 'Gate error arguments differ')
            events.append('error')
        elif name == 'peer':
            events.append('peer'); value = peer
        elif name == 'login_prepare':
            require(reg('RCX') == peer and reg('RSP') == h.scratch + 0x38000, 'Login tail receiver/stack differs')
            events.append('login_prepare')
        else:
            raise ValueError('Unsupported VersionResult fixture')
        h.finish(value)

    protected = set(functions.values()) | {int(at, 16) for at in context['leaves']}
    for name, at in context['fixtures'].items():
        require(int(at, 16) not in protected, 'VersionResult fixture overlaps native root')
        h.add_fixture(int(at, 16), lambda machine, name=name: fixture(machine, name))
    # Table page is read-only source data; the handler invokes the actual ID leaf.
    page = packet_table & ~4095
    if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
        uc.mem_map(page, 4096); uc.mem_write(page, data(page, 4096))
    import unicorn
    def entered(machine, at, size, unused):
        if at == functions['gate']:
            require((reg('RCX') & 0xffffffff, reg('RDX'), reg('R9')) == (current['code'], 2, 0),
                    'VersionResult native gate arguments differ')
            require(bytes(uc.mem_read(reg('R8'), 24)) == bytes(24), 'VersionResult gate temporary not empty')
            events.append('gate')
    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    cases = []
    for code in (0, 1, 42, 58, 708, 1304, 0xffffffff):
        for flag in (0, 1):
            current.update(code=code); events.clear()
            uc.mem_write(packet - 16, b'\xa5' * 16 + bytes(0x28) + b'\xa6' * 16)
            h.call(constructor, packet)
            put(packet + 0x10, 'I', code); put(state + 8, 'B', flag)
            before = bytes(uc.mem_read(packet - 16, 0x48))
            abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
            for name, value in abi.items():
                uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
            uc.reg_write(x.UC_X86_REG_R8, packet)
            h.call(functions['handler'], h.scratch + 0x4000)
            expected = ['gate', 'peer', 'login_prepare'] if code == 0 else (
                ['gate', 'error'] if flag == 0 and code != 42 else ['gate'])
            require(events == expected, 'VersionResult handler success/error route differs')
            require(bytes(uc.mem_read(packet - 16, 0x48)) == before, 'VersionResult handler changed packet')
            require(all(reg(name) == value for name, value in abi.items())
                    and reg('RSP') == h.scratch + 0x38008, 'VersionResult handler ABI differs')
            cases.append(dict(code=code, state_flag=flag, events=events.copy()))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
                evidence=h.evidence, network_used=False, profile_activated=False,
                limits=['Synthetic packet, gate-state getter, strings/log/error services and peer are fixtures.',
                        'Registration is a static bounded window; dispatcher is not executed.',
                        'Native handler/gate execute for declared codes; Login prepare is captured at entry.',
                        'No live Login, character request/creation, profile promotion or active baseline change.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-version-result-handler-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
