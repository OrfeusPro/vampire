"""Execute explicit current LoginResult handler/gate with synthetic packet and services."""
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


def verify(context, root, shared=None):
    roots = {name: int(at, 16) for name, at in context['functions'].items()}
    h = shared['h'] if shared else load('update-native-harness').make_harness(
        context, context['exports'], set(roots.values()),
        leaves={int(at, 16): code for at, code in context['leaves'].items()}, root=root)
    if h.sha != context['source_sha256']:
        raise ValueError('Handler shared source differs')
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    switch = context.get('switch_gate')
    if switch:
        if switch != 'version-gate-11318':
            raise ValueError('Unreviewed Login gate switch')
        gate_module = load('version-gate-switch-11318')
        gate_module.validate(native, h)
        shapes = load('audit-launcher-shape-11318')
        for function in h.fragments:
            if int(function['address'], 16) != roots['gate']:
                shapes.normalize_function(native, h.image, function)
    calls = {name: {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                   for r in (gate_module.rows(native, h.image, h.sha) if switch and name == 'gate'
                             else bindings.rows(native, h.image, at)) if r['call']} for name, at in roots.items()}
    if calls != context['call_sites']:
        raise ValueError('Handler/gate call sites differ')
    labels = {int(at, 16): name for name, at in context['fixtures'].items()}
    protected = set(roots.values()) | {int(at, 16) for at in context['leaves']}
    if shared:
        protected.update(int(f['address'], 16) for f in h.fragments)
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

    def text(at, value):
        require(h.scratch <= at <= h.scratch + 0x38000 - 16, 'Handler string descriptor bound')
        data = value.encode('utf-16le') + b'\0\0' if value else b''
        pointer = current['heap'] if data else 0
        if data:
            require(current['heap'] + len(data) < h.scratch + 0x30000, 'Handler string fixture heap bound')
            uc.mem_write(pointer, data)
            current['heap'] += (len(data) + 15) & ~15
        put(at, 'QII', pointer, len(data) // 2, len(data) // 2)

    def read_text(at):
        pointer, size, cap = struct.unpack('<QII', bytes(uc.mem_read(at, 16)))
        require(0 <= size <= cap <= 512, 'Handler string fixture descriptor differs')
        return bytes(uc.mem_read(pointer, size * 2))[:-2].decode('utf-16le') if size else ''

    def fixture(machine, name):
        a, b, c, d = (reg(r) for r in ('RCX', 'RDX', 'R8', 'R9'))
        value = 0
        if name in ('string_init', 'string_format'):
            text(a, '')
        elif name == 'string_copy':
            text(a, read_text(b)); value = a
        elif name == 'string_assign':
            text(a, read_text(b)); value = a
        elif name == 'localized':
            text(b, 'localized-fixture')
        elif name == 'sdk_text':
            text(b, 'sdk-fixture'); value = b
        elif name in ('free', 'log'):
            pass
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
        elif name in ('peer', 'clock_service', 'time_service', 'localizer', 'post_service', 'other_service', 'sdk_service', 'predicate_service'):
            value = h.scratch + 0xf500
        elif name == 'clock':
            value = 0
        elif name in ('early', 'time_pair', 'toggle', 'positive', 'post_state', 'server_store', 'predicate_action',
                      'other_action', 'flag138', 'error_9818', 'error_90021', 'error_finish', 'popup54', 'popup',
                      'dedicated_error', 'error9400', 'disconnect', 'sdk_final', 'sdk_a0', 'gate_error', 'optional_prepare'):
            events.append(dict(action=name, args=[a, b, c, d]))
        else:
            raise ValueError('Unsupported handler fixture ' + name)
        h.finish(value)

    for at, name in labels.items():
        previous = h.fixtures.get(at)
        def dispatch(machine, name=name, previous=previous):
            if previous and not current.get('handler_phase'):
                previous(machine)
            else:
                fixture(machine, name)
        h.add_fixture(at, dispatch)
    for name, at in callback.items():
        def capture(machine, name=name):
            events.append(dict(action='virtual_' + name)); h.finish()
        h.add_fixture(at, capture)

    def memory(machine, access, at, size, value, unused):
        region = ('state', at - state) if state <= at < state + 0x100 else (
                 ('controller', at - controller) if controller <= at < controller + 0x320 else (
                 ('global', at) if at in (globals_['special22'], globals_['derived']) else None))
        if region:
            writes.append(dict(region=region[0], offset=hex(region[1]), size=size,
                               value=value & ((1 << (size * 8)) - 1), instruction=hex(reg('RIP'))))
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, memory)
    gate_return = next(int(site, 16) + 5 for site, target in calls['handler'].items() if target == hex(roots['gate']))

    def trace(machine, at, size, unused):
        if at == roots['gate']:
            events.append(dict(action='native_gate', code=reg('RCX') & 0xffffffff, packet_id=reg('RDX') & 0xffff))
        elif at == gate_return:
            events.append(dict(action='native_gate_return', value=reg('RAX') & 255))
    uc.hook_add(unicorn.UC_HOOK_CODE, trace)

    def run(code=0, field48=0, raw16=0x8000, **settings):
        current.clear()
        current.update(heap=h.scratch + 0x28000, peer_flag=0, selected_server=42, previous_server=7,
                       gate_state=0, optional_object=True, sdk_enabled=False, manager_present=True,
                       sdk_callbacks=False, auth_present=False, post_predicate=False, flag138=1, message='')
        current.update(settings)
        events.clear(); writes.clear()
        uc.mem_write(h.scratch + 0x30000, bytes(0x8000))
        decoded = shared['read_packet'](code, field48, raw16, current) if shared else None
        if shared and decoded['returned'] != 1:
            require(not events and not writes, 'Incomplete packet reached handler services')
            return dict(decoded=decoded, handler_invoked=False, events=[], writes=[], settings=settings)
        for at, size in (((state, 0x100), (controller, 0x320)) if shared else ((packet, 0x140), (state, 0x100), (controller, 0x320))):
            uc.mem_write(at - 16, b'\xa5' * 16 + bytes(size) + b'\xa6' * 16)
        if not shared:
            put(packet, 'Q', table); put(packet + 0x10, 'I', code)
            for off in (0x18, 0x28, 0x38, 0x70, 0x90, 0xb8, 0xc8):
                text(packet + off, current['message'] if off == 0x38 else 'fixture' if off == 0x18 else '')
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
        before = bytes(uc.mem_read(packet, 0x140))
        abi = {name: 0x1122334400000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
        for name, value in abi.items():
            uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
        uc.reg_write(x.UC_X86_REG_RDX, 0x12345678); uc.reg_write(x.UC_X86_REG_R8, packet)
        current['handler_phase'] = True
        h.call(roots['handler'], h.scratch + 0xf600, budget=250000)
        current['handler_phase'] = False
        if shared:
            shared['check_after']()
        require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008,
                'Handler ABI differs')
        require(bytes(uc.mem_read(packet, 0x140)) == before, 'Handler modified packet fixture')
        for at, size in ((packet, 0x140), (state, 0x100), (controller, 0x320)):
            require(bytes(uc.mem_read(at - 16, 16)) == b'\xa5' * 16 and bytes(uc.mem_read(at + size, 16)) == b'\xa6' * 16,
                    'Handler guards changed')
        return dict(code=code, field48=field48, raw16=raw16, settings=settings, decoded=decoded,
                    handler_invoked=True, events=list(events), writes=list(writes),
                    state=dict(text=read_text(state + 0x28), qwords={hex(o): qword(state + o) for o in (0x38, 0x88, 0xb0, 0xc0, 0xd0, 0xe0)},
                               flags={hex(o): bytes(uc.mem_read(state + o, 1))[0] for o in (0xa0, 0xe8)}),
                    controller_server=list(struct.unpack('<II', bytes(uc.mem_read(controller + 0x308, 8)))),
                    special22=bytes(uc.mem_read(globals_['special22'], 1))[0],
                    derived=struct.unpack('<q', bytes(uc.mem_read(globals_['derived'], 8)))[0], guards=True)

    cases = [run(field48=field, peer_flag=peer) for field in (0, 1, 32767, 32768, 65535) for peer in (0, 1)]
    cases += [run(code=code) for code in (1, 14, 22, 37, 54, 9400, 9818, 9819, 90021, 0xffffffff)]
    cases += [run(**settings) for settings in (dict(gate_state=1), dict(previous_server=42), dict(post_predicate=True),
              dict(sdk_enabled=True, manager_present=False), dict(sdk_enabled=True),
              dict(sdk_enabled=True, sdk_callbacks=True, auth_present=True), dict(sdk_enabled=True, sdk_callbacks=True),
              dict(sdk_enabled=True, auth_present=True))]
    cases += [run(code=code, optional_object=False, message='error') for code in (1, 9818, 9819, 90021)]
    cases += [run(code=1, gate_state=1), run(field48=1, optional_object=False), run(flag138=0)]
    cases += [run(raw16=value) for value in (0, 1, 65535)]
    if switch:
        cases += [run(code=0x1197, gate_state=flag) for flag in (0, 1)]
    if shared:
        cases += [run(**settings) for settings in shared.get('additional_settings', [])]
    rejected = [run(**settings) for settings in shared['rejected_settings']] if shared else []
    return dict(schema=1, source_sha256=context['source_sha256'], cases=cases, rejected=rejected, evidence=h.evidence,
                runtime=load('update-native-harness').runtime_inputs(), network_used=False, profile_activated=False,
                same_packet_reader_used=bool(shared),
                limits=['Synthetic packet only without shared reader; services/getters/storage and UI/SDK/clock/persistence/disconnect/post-state fixtures in both modes.',
                        'Handler and covered result-gate instructions execute; reader integration only when same_packet_reader_used. No dispatch/session proof.',
                        'Post-state and continuation remain fixture captures here; their separate checks do not prove real backend delivery.'])


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
