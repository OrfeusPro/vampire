"""Port the established post-Login reset contract to an explicit source context."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
LEVELS = (0xf0, 0x140, 0x190, 0x210, 0x260, 0x2b0, 0x300)
VALUES = LEVELS + (0x1a0, 0x1b0, 0x220, 0x240, 0x244, 0x248, 0x24c, 0x270, 0x290, 0x294,
                    0x298, 0x29c, 0x2c0, 0x2e0, 0x2e4, 0x2e8, 0x2ec, 0x338, 0x33c)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def verify(context, root):
    functions = {name: int(at, 16) for name, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(functions.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    rows = load('update-bindings').rows
    native = load('build-native-entry-code')
    decoded = {name: rows(native, h.image, at) for name, at in functions.items()}
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in rr if r['call']} for name, rr in decoded.items()}
    if calls != context['call_sites']:
        raise ValueError('Continuation call sites differ')
    for spec in context['anchors']:
        off = h.image.offset(int(spec['address'], 16) - h.image.pe.base)
        data = bytes.fromhex(spec['bytes'])
        if h.raw[off:off + len(data)] != data:
            raise ValueError('Continuation anchor differs')
    table = int(context['table'], 16)
    off = h.image.offset(table - h.image.pe.base)
    if struct.unpack_from('<Q', h.raw, off + 0x28)[0] != functions['reset']:
        raise ValueError('Continuation final slot differs')
    singleton, flag = (int(context[key], 16) for key in ('singleton', 'flag'))
    getter = int(context['getter'], 16)
    code = bytes.fromhex(context['leaves'][hex(getter)])
    if code[:3] != b'\x48\x8b\x05' or code[7:] != b'\xc3' or getter + 7 + struct.unpack_from('<i', code, 3)[0] != singleton:
        raise ValueError('Continuation getter link differs')
    helpers = {int(at, 16) for at in context['helpers_captured']}
    direct = {int(target, 16) for sites in calls.values() for target in sites.values() if target.startswith('0x')}
    if direct - set(functions.values()) - helpers or helpers & set(functions.values()):
        raise ValueError('Continuation helper closure differs')
    obj = h.scratch + 0x1000
    events, writes = [], []
    phase = ['constructor']
    import unicorn

    def reg(name):
        return h.uc.reg_read(getattr(h.x, 'UC_X86_REG_' + name))

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def capture(machine, at):
        a, b = reg('RCX'), reg('RDX')
        events.append(dict(address=hex(at), offset=hex(a - obj) if obj <= a < obj + 0x400 else None, second=b & 0xffffffff))
        h.finish(0)
    for at in helpers:
        h.add_fixture(at, lambda machine, at=at: capture(machine, at))

    def memory(machine, access, at, size, value, unused):
        if obj <= at < obj + 0x400:
            writes.append(dict(phase=phase[0], offset=hex(at - obj), size=size,
                               value=value & ((1 << (size * 8)) - 1), instruction=hex(reg('RIP'))))
    h.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory)
    cases = []
    for level in (0, 1, 2, 5):
        for capacity in (128, 256):
            events.clear(); writes.clear(); phase[0] = 'constructor'
            h.uc.mem_write(obj - 16, b'\xa5' * 16 + b'\x5a' * 0x400 + b'\xa6' * 16)
            require(h.call(functions['constructor'], obj) == obj, 'Continuation constructor return differs')
            require(h.call(getter) == obj and int.from_bytes(h.uc.mem_read(obj, 8), 'little') == table,
                    'Continuation actual singleton/table differs')
            ctor_writes = [w for w in writes if w['offset'] == '0x0']
            require([w['value'] for w in ctor_writes] == [int(context['base_table'], 16), table],
                    'Continuation base/final table sequence differs')
            for at in LEVELS:
                h.uc.mem_write(obj + at, struct.pack('<I', level))
            for at in (0x244, 0x294, 0x2e4):
                h.uc.mem_write(obj + at, struct.pack('<I', capacity))
            h.uc.mem_write(obj + 0x308, b'\xff\xff'); h.uc.mem_write(flag, b'\x01')
            initial = bytes(h.uc.mem_read(obj, 0x400))
            events.clear(); writes.clear(); phase[0] = 'reset'
            abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
            for name, value in abi.items():
                h.uc.reg_write(getattr(h.x, 'UC_X86_REG_' + name), value)
            actual_table = int.from_bytes(h.uc.mem_read(h.call(getter), 8), 'little')
            actual_method = int.from_bytes(h.uc.mem_read(actual_table + 0x28, 8), 'little')
            h.call(actual_method, obj)
            require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                    'Continuation reset ABI differs')
            require(bytes(h.uc.mem_read(obj - 16, 16)) == b'\xa5' * 16 and bytes(h.uc.mem_read(obj + 0x400, 16)) == b'\xa6' * 16,
                    'Continuation object guards differ')
            after = bytes(h.uc.mem_read(obj, 0x400))
            allowed = {i for w in writes for i in range(int(w['offset'], 16), int(w['offset'], 16) + w['size'])}
            require(all(a == b for i, (a, b) in enumerate(zip(initial, after)) if i not in allowed), 'Continuation unattributed store')
            cases.append(dict(level=level, capacity=capacity, ctor_vptrs=[w['value'] for w in ctor_writes],
                              values={hex(o): int.from_bytes(h.uc.mem_read(obj + o, 4), 'little') for o in VALUES},
                              field308=int.from_bytes(h.uc.mem_read(obj + 0x308, 2), 'little'),
                              flag=int.from_bytes(h.uc.mem_read(flag, 1), 'little'), events=list(events), writes=list(writes), guards=True))
    return dict(schema=1, source_sha256=context['source_sha256'], cases=cases, evidence=h.evidence,
                runtime=load('update-native-harness').runtime_inputs(), network_used=False, profile_activated=False,
                limits=['Constructor/getter/final virtual reset execute; container init/clear/shrink and cleanup helpers return fixture zero.',
                        'Factory is static export evidence only; no handler integration, real containers or CharacterListRead send proof.',
                        'Seeds cover historical 8 reset scenarios; nonempty destructor loops and helper side effects remain unproved.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-login-continuation-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
