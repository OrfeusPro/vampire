"""Current ID 27 handler -> native policy -> ID 101 request, with explicit services."""
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
        raise ValueError('WaitingEnd call sites differ')

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    for block in context['blocks']:
        at, payload = int(block['address'], 16), bytes.fromhex(block['bytes'])
        require(len(payload) <= 512 and data(at, len(payload)) == payload
                and hashlib.sha256(payload).hexdigest() == block['sha256'], 'WaitingEnd source block differs')
    b = {name: int(at, 16) for name, at in context['bindings'].items()}
    require(struct.unpack('<Q', data(b['handler_table'] + 0x10, 8))[0] == functions['handler'], 'WaitingEnd handler slot differs')
    for prefix, code in (('notify', 27), ('request', 101)):
        require(struct.unpack('<Q', data(b[prefix + '_table'] + 0x28, 8))[0] == b[prefix + '_id']
                and h.call(b[prefix + '_id']) == code, 'WaitingEnd packet ID differs')
    require(any(r['mnemonic'] == 'jmp' and r['direct_target'] == functions['request'] for r in rows['handler']),
            'WaitingEnd request tail differs')
    window = context['registration']
    at, code = int(window['address'], 16), bytes.fromhex(window['bytes'])
    require(data(at, len(code)) == code and len(code) <= 128, 'WaitingEnd registration window differs')
    require(h.image.pe.base + h.image.roots[h.image.containing(at)][0] == int(window['owner'], 16),
            'WaitingEnd registration owner differs')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    ins = list(decoder.disasm(code, at))
    require([(hex(r.address), r.mnemonic, r.op_str) for r in ins] == [tuple(r) for r in window['instructions']]
            and sum(r.size for r in ins) == len(code), 'WaitingEnd registration shape differs')
    require(any(r.mnemonic == 'call' and r.operands[0].imm == b['notify_constructor'] for r in ins),
            'WaitingEnd registered constructor differs')
    lea = next(r for r in ins if r.mnemonic == 'lea' and r.operands[1].type == native.X86_OP_MEM
               and r.operands[1].mem.base == native.X86_REG_RIP)
    require(lea.address + lea.size + lea.operands[1].mem.disp == b['handler_table']
            and [(r.mnemonic, r.op_str) for r in ins[-4:]] == [
                ('mov', 'r8, rdi'), ('mov', 'rdx, rax'), ('mov', 'rcx, rsi'),
                ('call', '0x1467cbb90' if context['source_sha256'] ==
                 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c' else '0x1467cb6c0')],
            'WaitingEnd registration handler/arguments differ')
    uc, x = h.uc, h.x
    packet, peer, inner, policy, metadata, lookup, selected = [h.scratch + n for n in (0x1000, 0x2000, 0x3000, 0x4000, 0x6000, 0x8000, 0x9000)]
    callbacks = dict(policy=h.scratch + 0xc000, send=h.scratch + 0xc010,
                     select=h.scratch + 0xc020, next=h.scratch + 0xc030)
    events, current = [], {}

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def map_source(at):
        page = at & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096); uc.mem_write(page, data(page, 4096))

    for at in b.values():
        if at >= h.image.pe.base:
            map_source(at)

    def fixture(machine, name):
        value = 0
        if name == 'state_toggle':
            require(reg('RDX') == 0, 'WaitingEnd state toggle differs')
        elif name in ('ui_service', 'ui_class', 'exit_service'):
            value = peer
        elif name == 'ui_lookup':
            value = 0  # Explicit absent UI; visible UI branch is outside this replay.
        elif name == 'lookup':
            require(reg('RCX') == 0, 'WaitingEnd policy lookup argument differs')
            value = policy if current['policy_object'] else 0
        elif name == 'type':
            value = metadata
        elif name == 'selected':
            value = selected
        elif name == 'string_init':
            require(h.scratch + 0x30000 <= reg('RCX') <= h.scratch + 0x38000 - 16, 'WaitingEnd string destination differs')
            put(reg('RCX'), 'QII', 0, 0, 0)
        elif name == 'free':
            require(reg('RCX') == 0, 'WaitingEnd unexpected free')
        elif name == 'log':
            pass
        else:
            raise ValueError('Unsupported WaitingEnd fixture')
        h.finish(value)
    protected = set(functions.values()) | {int(at, 16) for at in context['leaves']}
    for name, at in context['fixtures'].items():
        require(int(at, 16) not in protected, 'WaitingEnd fixture overlaps native code')
        h.add_fixture(int(at, 16), lambda machine, name=name: fixture(machine, name))

    def callback(machine, name):
        if name == 'policy':
            require(reg('RCX') == policy, 'WaitingEnd virtual policy receiver differs')
            events.append(dict(action='policy', value=current['policy_value'])); h.finish(current['policy_value']); return
        require(reg('RCX') == peer, 'WaitingEnd virtual receiver differs')
        if name == 'send':
            at = reg('RDX')
            require(int.from_bytes(uc.mem_read(at, 8), 'little') == b['request_table']
                    and bytes(uc.mem_read(at + 0xa, 1)) == b'\0', 'WaitingEnd request packet differs')
            events.append(dict(action='send', packet_id=101))
        elif name == 'select':
            events.append(dict(action='select', raw64=reg('RDX'), raw32=reg('R8') & 0xffffffff))
        elif name == 'next':
            events.append(dict(action='next'))
        h.finish()
    for name, at in callbacks.items():
        h.add_fixture(at, lambda machine, name=name: callback(machine, name))
    import unicorn
    def trace(machine, at, size, unused):
        if at == functions['predicate']:
            events.append(dict(action='predicate'))
    uc.hook_add(unicorn.UC_HOOK_CODE, trace)

    sentinel = int.from_bytes(data(b['sentinel'], 8), 'little')
    raw32 = int.from_bytes(data(b['selection_argument'], 4), 'little')
    notify_value, selected_value = 0x0102030405060708, 0xfedcba9876543210

    def run(flag=1, value=1, chosen=True, **settings):
        current.clear(); current.update(policy_object=True, policy_value=value, disabled=False, type_match=True, type_short=False)
        current.update(settings); events.clear()
        uc.mem_write(peer, bytes(0x400)); uc.mem_write(policy, bytes(0x100)); uc.mem_write(metadata, bytes(0x100))
        put(peer, 'Q', peer + 0x100); put(peer + 0x10, 'Q', inner); put(inner + 0x2a6, 'B', flag)
        for slot, name in ((0x38, 'send'), (0x40, 'next'), (0x50, 'select')):
            put(peer + 0x100 + slot, 'Q', callbacks[name])
        put(policy, 'Q', policy + 0x100); put(policy + 0x100 + 0xa18, 'Q', callbacks['policy'])
        put(policy + 0x10, 'Q', lookup); put(lookup + 0x30, 'Q', lookup + 0x100)
        put(lookup + 0x38, 'i', 0 if current['type_short'] else 1)
        put(metadata + 0x38, 'i', 1)
        put(lookup + 0x108, 'Q', metadata + (0x30 if current['type_match'] else 0x40))
        put(b['peer_global'], 'Q', peer); put(b['disabled'], 'B', current['disabled'])
        put(selected + 0x28, 'Q', selected_value if chosen else sentinel)
        uc.mem_write(packet - 16, b'\xa5' * 16 + bytes(0x18) + b'\xa6' * 16)
        require(h.call(b['notify_constructor'], packet) == packet, 'WaitingEnd notify constructor return differs')
        require(int.from_bytes(uc.mem_read(packet, 8), 'little') == b['notify_table'], 'WaitingEnd notify table differs')
        put(packet + 0x10, 'Q', notify_value); before = bytes(uc.mem_read(packet - 16, 0x38))
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, val in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), val)
        uc.reg_write(x.UC_X86_REG_R8, packet); h.call(functions['handler'], h.scratch + 0xa000)
        require(all(reg(name) == val for name, val in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'WaitingEnd ABI differs')
        require(bytes(uc.mem_read(packet - 16, 0x38)) == before, 'WaitingEnd handler changed notify')
        effective = value if current['policy_object'] and not current['disabled'] and current['type_match'] and not current['type_short'] else 4
        actions = [e['action'] for e in events if e['action'] != 'policy']
        if flag:
            expected = ['predicate', 'send'] if effective == 1 else ['predicate', 'predicate', 'next' if effective == 0 else 'select']
        else:
            expected = ['predicate'] + ([] if effective else ['select' if chosen else 'next'])
        require(actions == expected, 'WaitingEnd branch/action order differs')
        if actions[-1] == 'select':
            require(events[-1] == dict(action='select', raw64=notify_value if flag else selected_value, raw32=raw32),
                    'WaitingEnd selection source differs')
        return dict(peer_flag=flag, policy_value=value, selected=chosen, settings=settings, events=events.copy())
    cases = [run(flag, value, chosen) for flag in (0, 1) for value in (0, 1, 2, 4) for chosen in (False, True)]
    fallback = [run(flag, 1, **settings) for flag in (0, 1) for settings in (
        dict(disabled=True), dict(policy_object=False), dict(type_match=False), dict(type_short=True))]
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases, fallback=fallback,
                evidence=h.evidence, network_used=False, profile_activated=False,
                limits=['Notify raw64, UI-absent lookup, policy/type objects and virtual policy result are fixtures.',
                        'Registration is static; native notify reader, dispatch, send transport and server timing are not executed.',
                        'Actual handler, predicate, request, quick-select thunk, constructors/getters/destructor execute.',
                        'Virtual send/selection/next, UI/state/string/log services are captures; no live list or character creation.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-waiting-end-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']), fallback=len(result['fallback']))))
