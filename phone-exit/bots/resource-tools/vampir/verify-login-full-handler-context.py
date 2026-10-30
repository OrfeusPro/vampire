"""Proof-bound whole LoginResult handler/gate with current synthetic 352-byte packet."""
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


def read_popup_selector(image, handler, rows):
    """Read the UI selector loaded into EBX, independently of the result code."""
    at = handler + 289
    found = [row for row in rows if row['address'] == at]
    if len(found) != 1:
        raise ValueError('Handler popup selector instruction is missing or ambiguous')
    row = found[0]; code = bytes.fromhex(row['bytes'])
    if len(code) != 6 or code[:2] != b'\x8b\x1d' or row['mnemonic'] != 'mov':
        raise ValueError('Handler popup selector load shape differs')
    target = at + 6 + struct.unpack_from('<i', code, 2)[0]
    if row['rip_references'] != [target]:
        raise ValueError('Handler popup selector RIP target differs')
    offset = image.offset(at-image.pe.base)
    if image.data[offset:offset+6] != code:
        raise ValueError('Handler popup selector instruction bytes changed')
    offset = image.offset(target-image.pe.base)
    value = image.data[offset:offset+4]
    if len(value) != 4:
        raise ValueError('Handler popup selector data bounds differ')
    return struct.unpack('<I', value)[0]


def admit(context, root):
    from types import SimpleNamespace
    if (context.get('family') != 'login-full-handler' or not context.get('transfer_proof')
            or any(k in context for k in ('function_budget', 'budget_scope', 'native_admission', 'native_input', 'native_result'))):
        raise ValueError('Portable full Login handler admission scope differs')
    index = load('knowledge-index').api()
    args = SimpleNamespace(root=Path(root), knowledge=HERE / 'knowledge')
    args.source_store = load('update-bindings').SourceStore(index, args.root)
    adapter = load('update-native-login-full').select('login-full-handler')
    roots = {int(at, 16) for at in context['functions'].values()}
    if len(roots) != 2 or adapter.roots(context) != roots:
        raise ValueError('Portable full Login handler needs exactly two checked roots')
    adapter.validate(index, args, context)
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    image = args.source_store.image(native, context['source_sha256'])
    adapter.export_coverage(args.root, context, native, bindings, image)
    args.source_store.validate()


def verify(context, root):
    admit(context, root)
    roots = {name: int(at, 16) for name, at in context['functions'].items()}
    gate_context = load('portable-native-family').checked(Path(root), context['gate_context'], 'generated-native-contexts')
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    gate_module = load('result-gate-transfer-rules')
    exports = dict(context['exports'])
    for run, sha in gate_context['exports'].items():
        if run in exports and exports[run] != sha:
            raise ValueError('Full Login handler conflicting gate exports')
        exports[run] = sha
    view_context = dict(context, verify_whole_exports=False)
    h = load('update-native-harness').make_harness(view_context, exports, set(roots.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    gate_module.rows(native, h.image, gate_context)
    gate_module.export_coverage(Path(root), gate_context, native, bindings, h.image)
    shapes = load('audit-launcher-shape-11318')
    for function in h.fragments:
        if int(function['address'], 16) == roots['handler']:
            shapes.normalize_function(native, h.image, function)
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in (gate_module.rows(native, h.image, gate_context) if name == 'gate'
                             else bindings.rows(native, h.image, at)) if r['call']} for name, at in roots.items()}
    if calls != context['call_sites']:
        raise ValueError('Handler/gate call sites differ')
    popup_selector = read_popup_selector(h.image, roots['handler'], bindings.rows(native, h.image, roots['handler']))
    labels = {int(at, 16): name for name, at in context['fixtures'].items()}
    protected = set(roots.values()) | {int(at, 16) for at in context['leaves']}
    if len(labels) != len(context['fixtures']) or set(labels) & protected:
        raise ValueError('Handler fixture overlaps native code')
    direct = {int(at, 16) for sites in calls.values() for at in sites.values() if at.startswith('0x')}
    if direct - set(roots.values()) - set(labels):
        raise ValueError('Handler/gate undeclared fixture')
    table = int(context['packet_table'], 16)
    packet, state, controller, manager = [h.scratch + off for off in (0x1000, 0xa000, 0xb000, 0xc000)]
    service, view, options = [h.scratch + off for off in (0xd000, 0xe000, 0xf000)]
    callback = dict(exit=h.scratch + 0xf800, view=h.scratch + 0xf810, sdk=h.scratch + 0xf820)
    current, events, writes = {}, [], []
    x, uc = h.x, h.uc
    import unicorn

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, fmt, *values):
        uc.mem_write(at, struct.pack('<' + fmt, *values))

    def qword(at):
        return int.from_bytes(uc.mem_read(at, 8), 'little')

    def map_source(at):
        page = at & ~4095
        if not any(lo <= page <= hi for lo, hi, _ in uc.mem_regions()):
            uc.mem_map(page, 4096)
            off = h.image.offset(page - h.image.pe.base)
            uc.mem_write(page, h.raw[off:off + 4096])

    map_source(table)
    require(qword(table + 0x28) == int(context['id_getter'], 16), 'Handler packet ID table differs')
    globals_ = {name: int(at, 16) for name, at in context['globals'].items()}
    references = {at for r in bindings.rows(native, h.image, roots['handler']) for at in r['rip_references']}
    require(set(globals_.values()) <= references, 'Handler globals are not source references')
    for at in globals_.values():
        map_source(at)

    def allocate(data, owner):
        pointer = current['heap'] + 16
        require(current['heap'] + len(data) + 32 < h.scratch + 0x30000, 'Handler string fixture heap bound')
        uc.mem_write(pointer - 16, b'\xa5' * 16 + data + b'\xa6' * 16)
        current['heap'] += (len(data) + 63) & ~15
        current['allocations'][pointer] = dict(size=len(data), owner=owner, data=data)
        return pointer

    def text(at, value, owner='fixture'):
        require(h.scratch <= at <= h.scratch + 0x38000 - 16, 'Handler string descriptor bound')
        data = value.encode('utf-16le') + b'\0\0' if value else b''
        pointer = allocate(data, owner) if data else 0
        put(at, 'QII', pointer, len(data) // 2, len(data) // 2)

    def read_text(at):
        pointer, size, cap = struct.unpack('<QII', bytes(uc.mem_read(at, 16)))
        require(0 <= size <= cap <= 512, 'Handler string fixture descriptor differs')
        return bytes(uc.mem_read(pointer, size * 2))[:-2].decode('utf-16le') if size else ''

    def fixture(machine, name):
        a, b, c, d = (reg(r) for r in ('RCX', 'RDX', 'R8', 'R9'))
        return_at = qword(reg('RSP'))
        call_at = return_at - 5
        owner = 'gate' if roots['gate'] <= call_at < int(gate_context['switch']['code_end'], 16) else 'handler'
        require(calls[owner].get(hex(call_at)) == hex(int(context['fixtures'][name], 16)), 'Handler fixture concrete call site differs')
        event = dict(action=name, owner=owner, call_offset=call_at-roots[owner], arguments_checked=True)
        value = 0
        if name in ('string_init', 'string_format'):
            require(h.scratch + 0x30000 <= a < h.scratch + 0x38000, 'Handler stack string receiver differs')
            text(a, '')
        elif name == 'string_copy':
            require(owner == 'handler' and call_at == roots['handler'] + 515 and b == packet + 0x18,
                    'Handler string copy source/caller differs')
            text(a, read_text(b)); value = a
        elif name == 'string_assign':
            require(a == state + 0x28 and h.scratch + 0x30000 <= b < h.scratch + 0x38000,
                    'Handler state string assignment receiver/source differs')
            text(a, read_text(b)); value = a
        elif name == 'localized':
            require(a == h.scratch + 0xf500 and h.scratch + 0x30000 <= b < h.scratch + 0x38000,
                    'Handler localization receiver/destination differs')
            text(b, 'localized-fixture')
        elif name == 'sdk_text':
            require(a == h.scratch + 0xf380 and current['auth_present'] and h.scratch + 0x30000 <= b < h.scratch + 0x38000,
                    'Handler SDK text receiver/destination differs')
            text(b, 'sdk-fixture'); value = b
        elif name == 'free':
            require(a in current['allocations'] and a not in current['freed'], 'Handler free ownership/repetition differs')
            require(current['allocations'][a]['owner'] != 'packet', 'Handler attempted to free packet input string')
            current['freed'].add(a)
            if call_at == roots['handler'] + 869:
                require(a == current.get('trailing_allocation') and not current['trailing_predicate'], 'Handler trailing free identity differs')
                current['trailing_freed'] = True
                events.append(dict(event, action='trailing_free'))
        elif name == 'log':
            require(b & 0xffffffff == 0x309, 'Handler log selector differs')
        elif name == 'state':
            value = state
        elif name == 'controller':
            value = controller
        elif name == 'gate_state':
            value = options
        elif name == 'peer_flag':
            value = current['peer_flag']
        elif name == 'selected_server':
            value = current['selected_server']
        elif name == 'sdk_manager':
            value = manager if current['manager_present'] else 0
        elif name == 'exit_service':
            value = service
        elif name == 'view_service':
            value = view
        elif name in ('optional_positive', 'optional_9818', 'optional_90021'):
            value = h.scratch + 0xf400 if current['optional_object'] else 0
        elif name == 'post_predicate':
            value = int(current['post_predicate'])
        elif name == 'trailing_predicate':
            require((a, b, c & 0xffffffff, d & 0xffffffff) ==
                    (packet + 0x140, qword(packet + 0x58), current['field150'], current['field154']),
                    'Handler trailing predicate arguments differ')
            value = int(current['trailing_predicate'])
            events.append(dict(event, text=read_text(a), time=b, field150=c & 0xffffffff, field154=d & 0xffffffff, returned=value))
        elif name == 'trailing_apply':
            if current['trailing_predicate']:
                require(a == packet + 0x140 and call_at == roots['handler'] + 836, 'Handler trailing input apply branch differs')
                applied = read_text(a)
                require(applied == current['trailing_text'], 'Handler trailing input text differs')
                source = 'packet'
            else:
                require(call_at == roots['handler'] + 855 and h.scratch + 0x30000 <= a < h.scratch + 0x38000,
                        'Handler empty temporary apply branch differs')
                require(bytes(uc.mem_read(a, 16)) == bytes(16), 'Handler empty temporary not initialized')
                applied, source = '', 'empty_temporary'
                if current['temp_allocated']:
                    pointer = allocate(b'\0\0', 'trailing_temporary')
                    put(a, 'QII', pointer, 1, 1)
                    current['trailing_allocation'] = pointer
            events.append(dict(event, source=source, text=applied, temporary_allocated=bool(current.get('trailing_allocation'))))
        elif name in ('peer', 'clock_service', 'time_service', 'localizer', 'post_service', 'other_service', 'sdk_service', 'predicate_service'):
            value = h.scratch + 0xf500
        elif name == 'clock':
            value = 0
        elif name in ('early', 'time_pair', 'toggle', 'positive', 'post_state', 'server_store', 'predicate_action',
                      'other_action', 'flag138', 'error_9818', 'error_90021', 'error_finish', 'popup54', 'popup',
                      'dedicated_error', 'error9400', 'disconnect', 'sdk_final', 'sdk_a0', 'gate_error', 'optional_prepare'):
            if name == 'time_pair':
                require(a == h.scratch + 0xf500 and b == qword(packet + 0x58) and c & 0xffff == current['raw16'], 'Handler time pair arguments differ')
            elif name == 'gate_error':
                require(a & 0xffffffff == current['code'] and b == 0, 'Handler gate error arguments differ')
            elif name in ('error_9818', 'error_90021', 'optional_prepare'):
                require(a == h.scratch + 0xf400 and current['optional_object'], 'Handler optional service receiver differs')
                if name == 'error_9818': require(b & 0xffffffff == current['code'], 'Handler optional error code differs')
            elif name == 'early':
                require(a == controller and current['peer_flag'] and 0 < current['field48'] < 32768, 'Handler early service receiver/condition differs')
            elif name == 'positive':
                require(a == h.scratch + 0xf400 and current['optional_object'] and b & 0xffffffff == current['field48'],
                        'Handler positive service arguments differ')
            elif name == 'error_finish': require(a == 0, 'Handler error finish argument differs')
            elif name == 'dedicated_error': require(a == h.scratch + 0xf600 and b & 0xffffffff == current['code'], 'Handler dedicated error arguments differ')
            elif name == 'error9400': require(a == state and (b, c, d) == (packet+0xc8, packet+0xb8, packet+0xa8), 'Handler9400 nested arguments differ')
            elif name == 'disconnect': require(a == h.scratch + 0xf500 and b == 0, 'Handler disconnect receiver/argument differs')
            elif name == 'popup54': require(current['code'] == 54 and d == 0, 'Handler54 popup arguments differ')
            elif name == 'popup':
                require(h.scratch + 0x30000 <= a < h.scratch + 0x38000
                        and h.scratch + 0x30000 <= b < h.scratch + 0x38000
                        and (a, b) == (reg('RSP') + 0x48, reg('RSP') + 0x78)
                        and c & 0xffffffff == popup_selector, 'Handler error popup UI selector/receivers differ')
            elif name == 'server_store': require(a == h.scratch + 0xf500 and b & 0xffffffff == current['selected_server'], 'Handler server store arguments differ')
            elif name == 'flag138': require(a == 1 and current['flag138'] == 1, 'Handler flag138 argument differs')
            elif name == 'predicate_action': require(a == h.scratch + 0xf500 and b == 0, 'Handler predicate action arguments differ')
            elif name == 'other_action': require(a == h.scratch + 0xf500, 'Handler alternate action receiver differs')
            elif name == 'sdk_a0': require(a == h.scratch + 0xf300 and current['sdk_callbacks'], 'Handler SDK a0 receiver differs')
            elif name == 'sdk_final': require(a == h.scratch + 0xf500 and h.scratch + 0x30000 <= b < h.scratch + 0x38000, 'Handler SDK final receiver/text differs')
            elif name == 'toggle': require(b & 255 == int(call_at == roots['handler']+953), 'Handler toggle argument differs')
            events.append(event)
        else:
            raise ValueError('Unsupported handler fixture ' + name)
        h.finish(value)

    for at, name in labels.items():
        h.add_fixture(at, lambda machine, name=name: fixture(machine, name))
    for name, at in callback.items():
        def capture(machine, name=name):
            return_at = qword(reg('RSP'))
            # All three virtual captures are handler-owned CALL instructions.
            site = return_at - (4 if name == 'exit' else 3)
            expected_offset = dict(exit=490, view=974, sdk=711)[name]
            require(site == roots['handler'] + expected_offset, 'Handler virtual caller differs')
            receiver = dict(exit=service, view=view, sdk=h.scratch+0xf100)[name]
            require(reg('RCX') == receiver, 'Handler virtual receiver differs')
            events.append(dict(action='virtual_' + name, owner='handler', call_offset=expected_offset, arguments_checked=True)); h.finish()
        h.add_fixture(at, capture)

    def memory(machine, access, at, size, value, unused):
        region = ('state', at - state) if state <= at < state + 0x100 else (
                 ('controller', at - controller) if controller <= at < controller + 0x320 else (
                 ('global', next(name for name in ('special22', 'derived') if globals_[name] == at)) if at in (globals_['special22'], globals_['derived']) else None))
        if region:
            writes.append(dict(region=region[0], offset=region[1] if region[0] == 'global' else hex(region[1]), size=size,
                               value=value & ((1 << (size * 8)) - 1), instruction_offset=reg('RIP')-roots['handler']))
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory)
    gate_return = next(int(site, 16) + 5 for site, target in calls['handler'].items() if target == hex(roots['gate']))

    def trace(machine, at, size, unused):
        if at == roots['gate']:
            require((reg('RCX') & 0xffffffff, reg('RDX') & 0xffff, reg('R9')) == (current['code'], 4, 0),
                    'Handler native gate arguments differ')
            require(h.scratch + 0x30000 <= reg('R8') <= h.scratch + 0x38000 - 24
                    and bytes(uc.mem_read(reg('R8'), 24)) == bytes(24), 'Handler gate temporary is not empty')
            events.append(dict(action='native_gate', code=reg('RCX') & 0xffffffff, packet_id=reg('RDX') & 0xffff))
        elif at == gate_return:
            events.append(dict(action='native_gate_return', value=reg('RAX') & 255))
    uc.hook_add(unicorn.UC_HOOK_CODE, trace)

    def run(code=0, field48=0, raw16=0x8000, **settings):
        current.clear()
        current.update(heap=h.scratch + 0x28000, peer_flag=0, selected_server=42, previous_server=7,
                       gate_state=0, optional_object=True, sdk_enabled=False, manager_present=True,
                       sdk_callbacks=False, auth_present=False, post_predicate=False, flag138=1, message='',
                       trailing_predicate=False, temp_allocated=False, trailing_text='', field150=0, field154=0,
                       poison=0, allocations={}, freed=set(), trailing_freed=False, raw16=raw16, code=code, field48=field48)
        current.update(settings)
        events.clear(); writes.clear()
        uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        for at, size in ((packet, 0x160), (state, 0x100), (controller, 0x320)):
            uc.mem_write(at - 16, b'\xa5' * 16 + bytes([current['poison']]) * size + b'\xa6' * 16)
        # State/controller fields outside the tracked projections are controlled
        # fixture storage; seed zero independently from packet poison.
        uc.mem_write(state, bytes(0x100)); uc.mem_write(controller, bytes(0x320))
        put(packet, 'Q', table); put(packet + 0x10, 'I', code)
        for off in (0x18, 0x28, 0x38, 0x70, 0x90, 0xb8, 0xc8, 0x140):
            text(packet + off, current['trailing_text'] if off == 0x140 else current['message'] if off == 0x38 else 'fixture' if off == 0x18 else '', owner='packet')
        put(packet + 0x150, 'II', current['field150'], current['field154'])
        put(packet + 0x48, 'H', field48); put(packet + 0x60, 'H', raw16)
        for i, off in enumerate((0x58, 0x68, 0x80, 0xb0, 0xf0, 0x100, 0x110, 0x120)):
            put(packet + off, 'Q', 0x1234000000000000 + i)
        for off in (0x88, 0xa0, 0xe0, 0x128):
            put(packet + off, 'B', 1)
        put(packet + 0x138, 'B', current['flag138'])
        text(state + 0x28, 'before'); put(state + 0x38, 'Q', 0xabcdef)
        put(controller + 0x308, 'II', current['previous_server'], current['previous_server'])
        put(options + 8, 'B', current['gate_state'])
        for at, slot, target in ((service, 0x38, callback['exit']), (view, 0x28, callback['view']),
                                 (h.scratch + 0xf100, 0x20, callback['sdk'])):
            put(at, 'Q', at + 0x100); put(at + 0x100 + slot, 'Q', target)
        put(manager + 0x88, 'Q', h.scratch + 0xf100 if current['sdk_callbacks'] else 0)
        put(manager + 0xa0, 'Q', h.scratch + 0xf300 if current['sdk_callbacks'] else 0)
        put(manager + 0x38, 'Q', h.scratch + 0xf380 if current['auth_present'] else 0)
        put(globals_['sdk_enabled'], 'B', int(current['sdk_enabled']))
        put(globals_['special22'], 'B', 0); put(globals_['derived'], 'q', 0xabcdef)
        before = bytes(uc.mem_read(packet, 0x160))
        abi = {name: 0x1122334400000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        abi.update({'XMM'+str(i): 0x123456789abcdef0fedcba9876543210+i for i in range(6,16)})
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, 0x12345678); uc.reg_write(x.UC_X86_REG_R8, packet)
        current['handler_phase'] = True
        h.call(roots['handler'], h.scratch + 0xf600, budget=250000)
        current['handler_phase'] = False
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'Handler ABI differs')
        require(bytes(uc.mem_read(packet, 0x160)) == before, 'Handler modified packet fixture')
        for pointer, info in current['allocations'].items():
            require(bytes(uc.mem_read(pointer-16, 16)) == b'\xa5'*16 and bytes(uc.mem_read(pointer+info['size'], 16)) == b'\xa6'*16,
                    'Handler string allocation guards changed')
            if info['owner'] == 'packet':
                require(bytes(uc.mem_read(pointer, info['size'])) == info['data'], 'Handler modified source string buffer')
        for at, size in ((packet, 0x160), (state, 0x100), (controller, 0x320)):
            require(bytes(uc.mem_read(at - 16, 16)) == b'\xa5' * 16 and bytes(uc.mem_read(at + size, 16)) == b'\xa6' * 16,
                    'Handler guards changed')
        return dict(code=code, field48=field48, raw16=raw16, settings=settings, handler_invoked=True, events=list(events), writes=list(writes),
                    state=dict(text=read_text(state + 0x28), qwords={hex(o): qword(state + o) for o in (0x38, 0x88, 0xb0, 0xc0, 0xd0, 0xe0)},
                               flags={hex(o): bytes(uc.mem_read(state + o, 1))[0] for o in (0xa0, 0xe8)}),
                    controller_server=list(struct.unpack('<II', bytes(uc.mem_read(controller + 0x308, 8)))),
                    special22=bytes(uc.mem_read(globals_['special22'], 1))[0],
                    derived=struct.unpack('<q', bytes(uc.mem_read(globals_['derived'], 8)))[0], guards=True, abi=True,
                    packet_guards=True, string_guards=True,
                    trailing_temporary_allocated=bool(current.get('trailing_allocation')), trailing_temporary_freed=current['trailing_freed'])

    cases = [run(**scenario) for scenario in load('login-full-handler-case-contracts').scenarios()]
    return dict(schema=1, source_sha256=context['source_sha256'], method='bounded_native', cases=cases,
                runtime=load('update-native-harness').runtime_inputs(), evidence=h.evidence,
                network_used=False, profile_activated=False, runtime_activated=False,
                same_packet_reader_used=False, native_handler_used=True, native_gate_used=True,
                native_post_state_used=False, native_continuation_used=False, session_executed=False,
                packet_bytes=352, limits=[
                    'Synthetic current352-byte packet; two native roots and the native packet ID leaf execute.',
                    'Services, strings/storage, SDK/UI/clock/persistence/disconnect, trailing predicate/apply and post-state are bounded fixtures.',
                    'No same-packet reader, dispatch/session, real service effects or online-entry claim.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'native-login-handler-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
