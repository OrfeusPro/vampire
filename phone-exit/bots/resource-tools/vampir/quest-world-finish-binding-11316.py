"""Native ID206 receiver through real completion; bounded missing-actor engine mode."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

EXPORTS = {'run-7650bee00bb6': '9c583d5995e73bb8b2f8891c8c965781f1f5b44a68f445e8fe0dc73c615ddefe'}


def run_cases(h, environment, services, listeners, context, state, events, with_handler=False):
    uc, x, b = h.uc, h.x, h.scratch
    packet, player, control, holder, other, table = [b + off for off in
        (0x10000, 0x12000, 0x15000, 0x16000, 0x17000, 0x18000)]

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def put(at, value, size=8):
        uc.mem_write(at, int(value).to_bytes(size, 'little'))

    def get(at, size=8):
        return int.from_bytes(uc.mem_read(at, size), 'little')

    def exact(at, encoded):
        off = h.image.offset(at - h.image.pe.base)
        if h.raw[off:off + len(bytes.fromhex(encoded))] != bytes.fromhex(encoded):
            raise ValueError('World finish static binding differs at ' + hex(at))

    registration = '488d056bfd6003488907eb03488bfbb920010000e8993015004885c0740a488bc8e8ec6f09ffeb03488bc34c8bc7488bd0488bcee8e95d0100'
    exact(0x1467b589e, registration)
    for table_at, expected_slots in ((0x149dc5610, (0x1414096c0, 0x14153b9d0, 0x1467ca450)),):
        off = h.image.offset(table_at - h.image.pe.base)
        if struct.unpack_from('<3Q', h.raw, off) != expected_slots:
            raise ValueError('World finish handler table differs')
    exact(0x14584c8bc, '488d051ded1104488901')
    off = h.image.offset(0x14996b5e0 + 0x28 - h.image.pe.base)
    if struct.unpack_from('<Q', h.raw, off)[0] != 0x145757ea0:
        raise ValueError('World finish packet ID slot differs')
    exact(0x145757ea0, 'b8ce000000c3')
    exact(0x1467ca5d0, 'e82b245eff')
    # The full source-bound handler is inspected statically, not dispatched.
    source = h.root / 'ghidra/request-exports' / h.sha / 'run-7650bee00bb6/details.json'
    payload = source.read_bytes()
    if hashlib.sha256(payload).hexdigest() != EXPORTS['run-7650bee00bb6']:
        raise ValueError('World finish handler export changed')
    handler = next(f for f in json.loads(payload)['functions'] if f['address'] == '0x1467ca450')
    if not handler.get('block_coverage_complete') or handler.get('direct_flow_coverage_complete') is not True:
        raise ValueError('World finish handler static coverage incomplete')
    for row in handler['instructions']:
        exact(int(row['address'], 16), row['bytes'])

    def noop(machine):
        h.finish()

    # This receiver first dereferences the real derived table before calling
    # +A0/+78. Map its source page explicitly; never synthesize these slots.
    source_page = 0x149a3d000
    uc.mem_map(source_page, 4096)
    source_offset = h.image.offset(source_page - h.image.pe.base)
    uc.mem_write(source_page, h.raw[source_offset:source_offset + 4096])
    if get(0x149a3dac0 + 0xa0) != 0x145da4d50 or get(0x149a3dac0 + 0x78) != 0x145da88d0:
        raise ValueError('Finish derived dispatch table differs')

    def lookup(machine):
        if reg('RDX') & 0xffffffff != 10012:
            raise ValueError('Finish world record lookup key differs')
        uc.mem_write(reg('RCX'), struct.pack('<QQ', 10012, 0))
        h.finish(reg('RCX'))

    def handle_get(machine):
        h.finish(get(reg('RCX') + 8))

    def world_notice(machine):
        if reg('RCX') != other or reg('RDX') & 255 != state['kind'] or reg('R8') & 0xffffffff != 10012:
            raise ValueError('Finish other-service world arguments differ')
        events.append('world-notice')
        h.finish()

    def model_apply(machine):
        if reg('RCX') != player or reg('RDX') != packet + 0xb8:
            raise ValueError('Finish player-array boundary differs')
        h.finish()

    def actor_create(machine):
        if get(reg('RCX')) != player or get(reg('RCX') + 8) != control:
            raise ValueError('Finish actor-create shared player differs')
        if bytes(uc.mem_read(reg('RDX'), 24)) != bytes(uc.mem_read(packet + 0x30, 24)):
            raise ValueError('Finish actor-create vector differs')
        events.append('actor-create-missing')
        h.finish(0)

    def heading(machine):
        if reg('RCX') != packet + 0x58:
            raise ValueError('Finish heading boundary differs')
        uc.mem_write(reg('RDX'), bytes(24))
        h.finish(reg('RDX'))

    fixtures = {
        0x145c79950: lookup, 0x141488490: handle_get,
        0x145691660: noop, 0x14560ad60: lambda machine: h.finish(other),
        table + 0x200: world_notice, table + 0x210: noop,
        0x145594e00: lambda machine: h.finish(holder),
        0x145d8b8d0: model_apply, 0x145d71df0: noop,
        0x14568ebf0: lambda machine: h.finish(1),
        0x145515dc0: lambda machine: h.finish(context),
        0x145513740: lambda machine: h.finish(0),
        0x14150b060: heading, 0x14567d4f0: actor_create,
        0x14230ae00: noop, 0x145691820: noop,
        # Exact derived +A0 is outside this composition; its boolean is explicit.
        0x145da4d50: lambda machine: h.finish(0),
    }
    for at, fn in fixtures.items():
        h.add_fixture(at, fn)
    uc.mem_write(other, struct.pack('<Q', table))
    put(table + 0x58, table + 0x200)
    put(table + 0x68, table + 0x210)
    tls = 0x30000000
    uc.mem_map(tls, 0x110000)
    uc.reg_write(x.UC_X86_REG_GS_BASE, tls)
    put(tls + 0x58, tls + 0x100)
    put(tls + 0x100, tls + 0x200)
    put(0x14b6a4c20, 0, 4)
    put(0x14b5f1d44, 0, 4)
    rows = []
    for old_quest in (0, 110120):
        for new_quest in (0, 110120):
            for old_flag in (False, True):
                for kind in (0, 2, 255):
                    state.update(before=3, kind=kind)
                    events.clear()
                    uc.mem_write(environment, bytes(0x1b0))
                    uc.mem_write(packet, bytes(0x120))
                    uc.mem_write(player, bytes(0x300))
                    uc.mem_write(holder, bytes(0x80))
                    uc.mem_write(control, bytes(0x20))
                    uc.mem_write(listeners, bytes(0x40))
                    put(environment, 0x149a3dac0)
                    put(environment + 0x30, 3, 1)
                    put(environment + 0x40, 200, 4)
                    put(environment + 0x44, 10012, 4)
                    put(environment + 0x50, old_quest)
                    put(environment + 0x79, int(old_flag), 1)
                    put(environment + 0x5b, 1, 1)
                    put(environment + 0xf0, 0x6420, 2)
                    put(holder + 0x38, player)
                    put(holder + 0x40, control)
                    put(player + 8, 123456789)
                    put(control + 8, 2, 4)
                    put(control + 0xc, 1, 4)
                    put(packet + 0x18, 0xfedcba9876543210)
                    put(packet + 0x20, 10012, 4)
                    put(packet + 0x24, 77, 4)
                    put(packet + 0x29, kind, 1)
                    uc.mem_write(packet + 0x30, struct.pack('<ddd', 1.25, -2.5, 3.75))
                    put(packet + 0x110, new_quest)
                    put(packet + 0x118, 1, 1)
                    put(packet + 0x119, 1, 1)
                    uc.reg_write(x.UC_X86_REG_RDX, packet)
                    try:
                        h.call(0x145daca00, environment, budget=100000)
                    except Exception as error:
                        raise RuntimeError('World finish stopped at ' + hex(reg('RIP'))) from error
                    expected_flag = old_quest == 0 and new_quest == 0
                    expected = {0x30: (6, 1), 0x38: (0xfedcba9876543210, 8),
                        0x40: (10012, 4), 0x44: (0, 4), 0x48: (77, 4),
                        0x50: (new_quest, 8), 0x58: (kind, 1), 0x5a: (1, 1),
                        0x79: (int(expected_flag), 1), 0xf1: (1, 1)}
                    if any(get(environment + at, size) != value for at, (value, size) in expected.items()):
                        raise ValueError('World finish native state projection differs')
                    if get(player + 0x1f8, 4) != 10012 or get(control + 8, 4) != 2:
                        raise ValueError('World finish player/refcount differs')
                    if events != ['world-notice', 'actor-create-missing', 'phase-format', 'phase-notify', 'event-clear', 'ui-reset']:
                        raise ValueError('World finish completion order differs')
                    rows.append(dict(old_quest=old_quest, new_quest=new_quest, old_flag=old_flag,
                        kind=kind, after=6, computed_flag79=expected_flag, refcount=2, events=events.copy()))
    handler_cases = []
    if with_handler:
        # Complete the previously pinned executable gate prefix. Inline data
        # after RET is not treated as more code, and no unknown target is allowed.
        spec = importlib.util.spec_from_file_location(
            'finish_gate_native', Path(__file__).with_name('build-native-entry-code.py'))
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        part = h.image.containing(0x1467cd7b0)
        actual = {r['address']: r['bytes'] for f in native.decode_ranges(h.image, {h.image.roots[part]})
            for r in f['instructions'] if r['address'] < 0x1467cdbc7}
        gate = next(f for f in h.fragments if f['address'] == '0x1467cd7b0')
        supplied = {int(r['address'], 16): r['bytes'] for r in gate['instructions']}
        supplied[0x1467cdab2] = '488b4d47'
        if supplied != actual or len(actual) != 251 or actual.get(0x1467cdbc6) != 'c3':
            raise ValueError('World finish gate executable prefix differs')
        setting, post, post_table = b + 0x1b000, b + 0x1c000, b + 0x1d000
        old_format, old_notify = h.fixtures[0x141433340], h.fixtures[0x145639100]

        def handler_format(machine):
            if reg('RDX') != 0x149dc5630:
                return old_format(machine)
            if reg('R8') & 0xffffffff != state['code'] or reg('R9') & 0xffffffff != 10012:
                raise ValueError('World finish handler diagnostic fields differ')
            uc.mem_write(reg('RCX'), bytes(16))
            state['handler_diagnostic'] = True
            events.append('handler-format')
            h.finish(reg('RCX'))

        def handler_notify(machine):
            if not state.get('handler_diagnostic'):
                return old_notify(machine)
            state['handler_diagnostic'] = False
            if reg('RCX') != context or get(reg('RDX')):
                raise ValueError('World finish handler diagnostic context differs')
            events.append('handler-notify')
            h.finish()

        def error(machine):
            if reg('RCX') & 0xffffffff != state['code'] or reg('RDX') & 0xffffffff:
                raise ValueError('World finish error presentation differs')
            events.append('error')
            h.finish()

        def prepare_finish(machine):
            if reg('RCX') != environment:
                raise ValueError('World finish preparation context differs')
            events.append('prepare')
            h.finish()

        def rejected(machine):
            events.append('rejected')
            h.finish()

        def post_effect(machine):
            if reg('RCX') != 0 or reg('RDX') != packet + 0xc8:
                raise ValueError('World finish post-receiver array arguments differ')
            events.append('post-effects')
            h.finish()

        callbacks = {0x141433340: handler_format, 0x145639100: handler_notify,
            0x145594db0: lambda machine: h.finish(setting), 0x145fd3ee0: error,
            0x146750120: rejected, 0x144a778e0: noop, 0x145d9c220: prepare_finish,
            0x1455e6e60: lambda machine: h.finish(post), 0x1417f8040: lambda machine: h.finish(0),
            post_table + 0x100: noop, 0x1467cecd0: post_effect,
            0x145cc6a20: lambda machine: h.finish(post), 0x1445fb7f0: noop}
        for at, callback in callbacks.items():
            h.add_fixture(at, callback)
        put(post, post_table)
        put(post_table + 0x38, post_table + 0x100)
        put(0x14b5e5ea8, environment)
        put(0x14b592033, 0, 1)
        packet_page = 0x14996b000
        uc.mem_map(packet_page, 4096)
        off = h.image.offset(packet_page - h.image.pe.base)
        uc.mem_write(packet_page, h.raw[off:off + 4096])
        baseline = bytes(uc.mem_read(environment, 0x1b0))
        for key_present in (False, True):
            for special in (False, True):
                for code in (0, 10, 0x1197, 0xffffffff):
                    events.clear()
                    state.update(before=3, kind=255, code=code, handler_diagnostic=False)
                    uc.mem_write(environment, baseline)
                    put(environment + 0x30, 3, 1)
                    put(environment + 0x40, 200, 4)
                    put(environment + 0x44, 10012, 4)
                    before = bytes(uc.mem_read(environment, 0x1b0))
                    put(player + 8, 123456789 if key_present else 0)
                    put(player + 0x1f8, 200, 4)
                    put(control + 8, 2, 4)
                    put(setting + 8, int(special), 1)
                    put(packet, 0x14996b5e0)
                    put(packet + 0x10, code, 4)
                    uc.reg_write(x.UC_X86_REG_RDX, 0)
                    uc.reg_write(x.UC_X86_REG_R8, packet)
                    try:
                        h.call(0x1467ca450, b + 0x1e000, budget=100000)
                    except Exception as exception:
                        raise RuntimeError('World finish handler stopped at ' + hex(reg('RIP'))) from exception
                    accepted = key_present and (code == 0 or code == 0x1197 and not special)
                    if get(control + 8, 4) != 2:
                        raise ValueError('World finish handler leaked player reference')
                    if accepted:
                        if get(environment + 0x30, 1) != 6 or get(environment + 0x40, 4) != 10012 or get(environment + 0x44, 4):
                            raise ValueError('Accepted world finish did not reach actual completion')
                        expected = ['handler-format', 'handler-notify', 'prepare'] + (['error'] if code == 0x1197 else []) + ['world-notice',
                            'actor-create-missing', 'phase-format', 'phase-notify', 'event-clear', 'ui-reset', 'post-effects']
                        if get(player + 0x1f8, 4) != 10012:
                            raise ValueError('Accepted world finish did not update player world')
                    else:
                        expected = [] if not key_present else ['handler-format', 'handler-notify', 'prepare'] + ([] if special else ['error']) + ['rejected']
                        if bytes(uc.mem_read(environment, 0x1b0)) != before or get(player + 0x1f8, 4) != 200:
                            raise ValueError('Early/rejected world finish changed environment/player world')
                    if events != expected or state['handler_diagnostic']:
                        raise ValueError('World finish handler/gate event ordering differs')
                    handler_cases.append(dict(key_present=key_present, special=special, code=code,
                        accepted=accepted, phase=get(environment + 0x30, 1), refcount=2, events=events.copy()))
    return dict(helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), cases=rows,
        handler_cases=handler_cases,
        receiver='0x145daca00', completion_slot='0x78',
        static_binding=dict(registration_address='0x1467b589e', registration_bytes=registration,
            handler_table='0x149dc5610', handler='0x1467ca450', receiver_call='0x1467ca5d0',
            constructor='0x14584c8b0', packet_table='0x14996b5e0', id_getter='0x145757ea0', packet_id=206),
        limits=['Receiver whole body executes with synthetic packet/player and missing record/actor boundaries.',
            'World lookup, providers, array application, heading, vector predicate, actor creation and +A0 are fixtures.',
            ('Whole ID206 handler/common gate execute; reader/active dispatcher remain outside this composition.' if with_handler
             else 'No actual ID206 reader/handler/gate dispatch in this composition; handler binding remains static navigation.'),
            'No spawned actor or active quest: phase6 alone does not admit a live quest offer.'])
