"""Current ID 102 registration and native handler/gate/policy with synthetic services."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    f = {key: int(at, 16) for key, at in context['functions'].items()}
    h = load('update-native-harness').make_harness(context, context['exports'], set(f.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    switch = context.get('switch_gate')
    if switch:
        if switch != 'version-gate-11318':
            raise ValueError('Unreviewed CharacterList gate switch')
        gate_module = load('version-gate-switch-11318')
        gate_module.validate(native, h)
        shapes = load('audit-launcher-shape-11318')
        for function in h.fragments:
            if int(function['address'], 16) != f['gate']:
                shapes.normalize_function(native, h.image, function)
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in (gate_module.rows(native, h.image, h.sha) if switch and name == 'gate'
                             else bindings.rows(native, h.image, at)) if r['call']} for name, at in f.items()}
    if calls != context['call_sites']:
        raise ValueError('List handler/gate/policy call sites differ')

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = h.image.offset(at - h.image.pe.base)
        return h.raw[off:off + size]

    uc, x = h.uc, h.x
    for block in context['blocks']:
        at, payload = int(block['address'], 16), bytes.fromhex(block['bytes'])
        require(data(at, len(payload)) == payload and hashlib.sha256(payload).hexdigest() == block['sha256'], 'List handler source block differs')
        for page in range(at & ~4095, (at + len(payload) + 4095) & ~4095, 4096):
            if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
                uc.mem_map(page, 4096); uc.mem_write(page, data(page, 4096))
    b = {key: int(at, 16) for key, at in context['bindings'].items()}
    require(struct.unpack('<Q', data(b['request_table'] + 0x10, 8))[0] == b['request_writer']
            and struct.unpack('<Q', data(b['request_table'] + 0x28, 8))[0] == b['request_id']
            and h.call(b['request_id']) == 101, 'List empty request table/ID differs')
    request, request_archive = h.scratch + 0x22000, h.scratch + 0x23000
    uc.mem_write(request, bytes(0x20)); uc.mem_write(request_archive, b'\x5a' * 0x40)
    h.call(b['request_constructor'], request)
    request_before, archive_before = bytes(uc.mem_read(request, 0x20)), bytes(uc.mem_read(request_archive, 0x40))
    uc.reg_write(x.UC_X86_REG_RDX, request_archive)
    require(h.call(b['request_writer'], request) & 255 == 1
            and bytes(uc.mem_read(request, 0x20)) == request_before
            and bytes(uc.mem_read(request_archive, 0x40)) == archive_before
            and int.from_bytes(request_before[:8], 'little') == b['request_table'] and request_before[0xa] == 0,
            'List empty request writer changed packet/archive')
    require(struct.unpack('<Q', data(b['handler_table'] + 0x10, 8))[0] == f['handler']
            and struct.unpack('<Q', data(b['packet_table'] + 0x28, 8))[0] == b['id_getter']
            and h.call(b['id_getter']) == 102, 'List handler registration table/ID differs')
    window = context['registration']
    start, code = int(window['address'], 16), bytes.fromhex(window['bytes'])
    require(len(code) == 75 and data(start, len(code)) == code, 'List registration window differs')
    require(h.image.pe.base + h.image.roots[h.image.containing(start)][0] == int(window['owner'], 16), 'List registration owner differs')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    instructions = list(decoder.disasm(code, start))
    require([(hex(r.address), r.mnemonic, r.op_str) for r in instructions] == [tuple(r) for r in window['instructions']], 'List registration shape differs')
    lea = next(r for r in instructions if r.mnemonic == 'lea')
    register = ('0x1467cbb90' if h.sha == 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
                else '0x1467cb6c0')
    require(lea.address + lea.size + lea.operands[1].mem.disp == b['handler_table']
            and any(r.mnemonic == 'call' and r.operands[0].imm == b['packet_constructor'] for r in instructions)
            and [(r.mnemonic, r.op_str) for r in instructions[-4:]] == [
                ('mov', 'r8, rdi'), ('mov', 'rdx, rax'), ('mov', 'rcx, rsi'), ('call', register)],
            'List registration constructor/arguments differ')
    packet, rows, state, controller, service, peer, inner, options, policy, metadata, lookup = [h.scratch + n for n in
        (0x1000, 0x4000, 0x8000, 0xa000, 0xb000, 0xc000, 0xc400, 0xd000, 0xe000, 0x13000, 0x14000)]
    policy_table, type_array, owner = h.scratch + 0xf000, h.scratch + 0x15000, h.scratch + 0x17000
    callbacks = dict(exit=h.scratch + 0x16000, policy=h.scratch + 0x16010, owner=h.scratch + 0x16020)
    current, events = {}, []

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def number(at, size):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def fixture(machine, name):
        a, d, c = reg('RCX'), reg('RDX'), reg('R8'); result = 0
        if name in ('string_init', 'string_format', 'prefix_init'):
            require(h.scratch + 0x30000 <= a <= h.scratch + 0x38000 - 16, 'List handler string destination differs')
            put(a, 'QII', 0, 0, 0)
        elif name == 'log':
            pass
        elif name == 'free':
            require(a == 0, 'Unexpected owned string in list handler fixture')
        elif name == 'gate_state':
            result = options
        elif name == 'gate_error':
            require((a & 0xffffffff, d) == (current['code'], 0), 'List gate error arguments differ'); events.append('gate_error')
        elif name == 'service':
            result = service
        elif name == 'policy_lookup':
            require(a == 0, 'List policy lookup argument differs'); result = policy if current['policy_present'] else 0
        elif name == 'policy_type':
            result = metadata
        elif name == 'state':
            result = state
        elif name == 'clear':
            require(d == 0, 'List handler initial state count differs')
        elif name == 'reserve':
            require(a == state + 0x70 and d <= 4, 'List handler reserve receiver/count differs')
            put(a, 'Q', h.scratch + 0x20000); put(a + 12, 'I', d)
        elif name == 'copy':
            require(a == h.scratch + 0x20000 and d == rows and c == len(current['ids']) <= 4, 'List handler copy arguments differ')
            uc.mem_write(a, bytes(uc.mem_read(d, c * 0x170))); events.append('publish_copy')
        elif name == 'tail_store':
            require(a == state and d == current['tail40'], 'List handler tail store differs'); events.append('tail_store')
        elif name == 'sdk_service':
            result = service
        elif name == 'sdk_log':
            events.append('sdk_log')
        elif name == 'controller':
            result = controller if current['controller_present'] else 0
        elif name == 'controller_reset':
            require(a == controller, 'List controller receiver differs'); events.append('controller_reset')
        elif name == 'ui_lookup':
            require(a == 0, 'List UI lookup argument differs'); result = 0
        elif name == 'ui_class':
            raise ValueError('Visible UI branch outside list handler fixtures')
        elif name == 'optional_owner':
            result = owner if current['owner_present'] else 0
        elif name == 'transition_effect':
            events.append('effect')
        elif name == 'flow_mode':
            require(a == service and d & 255 == 6, 'List flow mode differs'); events.append('mode6')
        else:
            raise ValueError('Unknown list handler fixture ' + name)
        h.finish(result)
    protected = set(f.values()) | {int(at, 16) for at in context['leaves']}
    for name, at in context['fixtures'].items():
        require(int(at, 16) not in protected, 'List handler fixture overlaps native code')
        h.add_fixture(int(at, 16), lambda machine, name=name: fixture(machine, name))
    def capture(machine, name):
        if name == 'policy':
            require(reg('RCX') == policy, 'List policy virtual receiver differs'); h.finish(current['policy']); return
        require(reg('RCX') == (service if name == 'exit' else owner), 'List handler virtual receiver differs')
        if name == 'exit':
            require(reg('RDX') == 0, 'List error exit argument differs')
        events.append(name); h.finish()
    for name, at in callbacks.items():
        h.add_fixture(at, lambda machine, name=name: capture(machine, name))
    import unicorn
    def entered(machine, at, size, unused):
        if at == f['gate']:
            require((reg('RCX') & 0xffffffff, reg('RDX'), reg('R9')) == (current['code'], 102, 0), 'List gate arguments differ')
            require(bytes(uc.mem_read(reg('R8'), 24)) == bytes(24), 'List gate temporary differs')
            events.append('gate')
        elif at == f['predicate']:
            events.append('predicate')
        elif at == b['peer_reset']:
            require(reg('RCX') == peer and reg('RDX') == 0, 'List peer-reset arguments differ'); events.append('peer_reset')
    uc.hook_add(unicorn.UC_HOOK_CODE, entered)
    sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
    from vampir_core.character_list import decode_character_list, preferred_character_index
    make_record = load('verify-character-record-context').body_for
    sentinel = struct.unpack('<Q', data(b['sentinel'], 8))[0]
    require(sentinel == 0, 'List preferred-index sentinel differs')

    def run(ids=(), preferred=0, code=0, gate_state=0, policy_value=1, raw28=7, **settings):
        require(len(ids) <= 4, 'List handler fixture count budget')
        current.clear(); current.update(ids=ids, code=code, policy=policy_value, policy_present=True, controller_present=True,
                                        owner_present=False, disabled=False, tail40=0xfedcba9876543210)
        current.update(settings); events.clear()
        uc.mem_write(packet - 16, b'\xa5' * 16 + bytes(0x48) + b'\xa6' * 16); h.call(b['packet_constructor'], packet)
        uc.mem_write(rows, bytes(4 * 0x170))
        for i, key in enumerate(ids):
            put(rows + i * 0x170, 'Q', b['record_table']); put(rows + i * 0x170 + 8, 'Q', key)
        put(packet + 0x10, 'IIQII', code, 207, rows if ids else 0, len(ids), len(ids))
        put(packet + 0x28, 'QI', raw28, 0x80000017); put(packet + 0x38, 'QQ', preferred, current['tail40'])
        uc.mem_write(state - 16, b'\xa7' * 16 + bytes(0x100) + b'\xa8' * 16)
        put(state + 0x80, 'II', 0x11111111, 0x22222222)
        uc.mem_write(controller - 16, b'\xa9' * 16 + bytes(0x410) + b'\xaa' * 16); put(controller + 0x3f8, 'i', -9)
        put(service, 'Q', service + 0x100); put(service + 0x138, 'Q', callbacks['exit'])
        put(owner, 'Q', owner + 0x100); put(owner + 0xb00, 'Q', callbacks['owner'])
        put(peer + 0x10, 'Q', inner); put(inner + 0x2a6, 'B', 1); put(b['peer_global'], 'Q', peer)
        put(options + 8, 'B', gate_state); put(b['disabled'], 'B', current['disabled'])
        put(policy, 'Q', policy_table); put(policy + 0x10, 'Q', lookup); put(policy_table + 0xa18, 'Q', callbacks['policy'])
        put(lookup + 0x30, 'Q', type_array); put(lookup + 0x38, 'i', 1); put(metadata + 0x38, 'i', 1); put(type_array + 8, 'Q', metadata + 0x30)
        before = bytes(uc.mem_read(packet - 16, 0x68))
        abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_R8, packet); h.call(f['handler'], h.scratch + 0x18000, budget=250000)
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008, 'List handler ABI differs')
        require(bytes(uc.mem_read(packet - 16, 0x68)) == before, 'List handler changed packet')
        for address, size, left, right in ((state, 0x100, b'\xa7', b'\xa8'), (controller, 0x410, b'\xa9', b'\xaa')):
            require(bytes(uc.mem_read(address - 16, 16)) == left * 16 and bytes(uc.mem_read(address + size, 16)) == right * 16,
                    'List handler state/controller guards changed')
        accepted = code == 0 and policy_value == 1 and current['policy_present'] and not current['disabled']
        count, pointer = number(state + 0x78, 4), number(state + 0x70, 8)
        selected = struct.unpack('<i', bytes(uc.mem_read(controller + 0x3f8, 4)))[0]
        if accepted:
            require(count == len(ids) and [number(pointer + i * 0x170 + 8, 8) for i in range(count)] == list(ids), 'List handler publication differs')
            require((number(state + 0x80, 4), number(state + 0x84, 4)) == (0x80000017, raw28 & 0xffffffff), 'List handler state fields differ')
            wire = struct.pack('<IIH', 0, 207, len(ids)) + b''.join(make_record(seed=key) for key in ids) + struct.pack('<QIQQ', raw28, 0x80000017, preferred, current['tail40'])
            decoded = decode_character_list(wire, max_payload_size=4096, max_characters=4, max_extension_items=0)
            expected = preferred_character_index(decoded)
            require(selected == ((expected if expected is not None else 0) if current['controller_present'] else -9), 'List native preferred index differs')
            require(events[-2:] == ['mode6', 'peer_reset'] and 'exit' not in events and number(inner + 0x2a6, 1) == 0,
                    'List success transition/reset differs')
        else:
            require(count == 0 and selected == -9 and number(inner + 0x2a6, 1) == 1
                    and (number(state + 0x80, 4), number(state + 0x84, 4)) == (0x11111111, 0x22222222)
                    and not any(name in events for name in ('publish_copy', 'tail_store', 'mode6', 'peer_reset')),
                    'Rejected list reached publication/transition')
            require(('exit' in events) == (code != 0), 'List error/policy exit route differs')
        require(('sdk_log' in events) == (accepted and raw28 >= 1 << 63), 'List signed tail28 diagnostic branch differs')
        return dict(code=code, gate_state=gate_state, policy=policy_value, ids=list(ids), preferred=preferred, settings=settings,
                    published=accepted, stored_count=count, selected_index=selected, events=events.copy())

    cases = [run(ids, 22, code, flag, policy_value) for code in (0, 1, 42, 58, 0xffffffff) for flag in (0, 1)
             for policy_value in (0, 1, 2, 4) for ids in ((), (11, 22, 33))]
    cases.extend(run((11, 22), 22, code) for code in (14, 22, 37, 54, 9400, 9818, 9819, 90021))
    cases.extend(run(ids, preferred) for ids, preferred in (((), 0), ((11, 22, 33), 0), ((11, 22, 33), 11),
        ((11, 22, 33), 33), ((11, 22, 33), 99), ((11, 22, 22, 33), 22), ((11, 0, 22), 0), ((1 << 63, 0xffffffffffffffff), 0xffffffffffffffff)))
    cases.extend((run((11, 22), 22, controller_present=False), run((11, 22), 22, owner_present=True),
                  run((11, 22), 22, policy_present=False), run((11, 22), 22, disabled=True), run((11, 22), 22, raw28=0x8000000000000001)))
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases, sentinel=sentinel,
                empty_request=dict(packet_id=101, writer_returned=True, packet_archive_unchanged=True),
                evidence=h.evidence, network_used=False, profile_activated=False,
                limits=['Static registration window and native handler/gate/policy/getter/peer-reset leaf; packets/rows/type metadata are synthetic.',
                        'State copy/reserve/cleanup, getters, strings/logs/SDK/controller/UI/flow/effect/exit/owner are fixtures/captures.',
                        'Visible UI branch is absent; native empty list stores index 0, while portable preferred helper returns None.',
                        'Mode 6 is a common captured transition, not proof of a character-create request; no shared reader/handler or live session.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-character-list-handler-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
