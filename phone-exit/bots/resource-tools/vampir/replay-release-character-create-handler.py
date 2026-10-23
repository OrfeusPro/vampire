"""Whole ID 104 handler with captured state/UI calls; no account or network."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('create_handler_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    addresses = (0x145d4e7b0, 0x145d5e430, 0x145c9bc00, 0x145c98110, 0x14641af90,
        0x144a29050, 0x146435b90, 0x144a27f90, 0x145d4e770, 0x145d54870,
        0x14560c530, 0x14563d790, 0x145fd5370, 0x14641af30, 0x1445d3da0,
        0x145c8df30, 0x141436fb0, 0x141483160, 0x14145f2c0, 0x141403c50)
    hooks = dict.fromkeys(addresses)
    h = archive.make_harness(extra_addresses=(0x146796690,), fixtures=hooks)
    uc, x = h.uc, h.x
    evidence = h.comparison / 'details/run-dbbbcb857839/details.json'
    expected_sha = 'e3438a98efdd8b403847bd3b68095abe4a8f7b666a24be1fc0c893e8d6432a11'
    if h.audit.sha256(evidence) != expected_sha: raise ValueError('Handler export changed')
    details = json.loads(evidence.read_text())
    if not any(f['address'] == '0x146796690' and f.get('instructions') for f in details['functions']):
        raise ValueError('Handler export missing')
    packet, manager, selection, ui, ui_type, metadata, hierarchy, vtable, feature, list_manager, ui_manager = [
        h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000, 0x14000,
            0x15000, 0x16000, 0x17000, 0x18000, 0x19000, 0x1a000)]
    calls, state = [], {}
    def text(address):
        p, count, cap = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
        if not 0 <= count <= cap <= 128: raise ValueError('Handler FString bound')
        return bytes(uc.mem_read(p, max(0, count - 1) * 2)).decode('utf-16le') if count else ''
    def put(address, value, terminated=True):
        raw = value.encode('utf-16le') + (bytes(2) if terminated else b'')
        p = state['heap']; state['heap'] += max(16, len(raw))
        if raw: uc.mem_write(p, raw)
        uc.mem_write(address, struct.pack('<QII', p if raw else 0, len(raw) // 2, len(raw) // 2))
    def fixture(machine):
        current = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = None
        if current == 0x145d4e7b0: result = manager
        elif current == 0x145d5e430:
            if a != manager: raise ValueError('Creation name-match callback input differs')
            calls.append('name_match')
        elif current == 0x145c9bc00: result = list_manager
        elif current == 0x145c98110:
            if (a, b) != (list_manager, packet + 0x18): raise ValueError('Created record insertion input differs')
            calls.append('record')
        elif current == 0x14641af90: result = selection if state['selection'] else 0
        elif current == 0x144a29050: result = ui_manager
        elif current in (0x146435b90, 0x145c8df30): result = metadata
        elif current == 0x144a27f90:
            if (a, b) != (ui_manager, metadata): raise ValueError('Handler UI lookup input differs')
            result = ui if state['ui'] != 'missing' else 0
        elif current == 0x141403c50:
            if (a, b, c) != (ui, 1, 1): raise ValueError('Handler UI refresh arguments differ')
            calls.append('ui_refresh')
        elif current == 0x145d4e770: result = manager
        elif current == 0x145d54870:
            if a != manager: raise ValueError('Handler success finalizer differs')
            calls.append('success_finalize')
        elif current == 0x14560c530: result = feature if state['feature'] != 'absent' else 0
        elif current == 0x14563d790:
            if a != 0x12345678: raise ValueError('Handler feature target differs')
            calls.append('feature')
        elif current == 0x145fd5370:
            if a & 0xffffffff != state['code'] or b != 0: raise ValueError('Handler error code differs')
            calls.append('error')
        elif current == 0x14641af30: result = ui if state['player'] else 0
        elif current == 0x1445d3da0:
            if a: raise ValueError('Handler error UI lookup argument differs')
            result = ui if state['ui'] != 'missing' else 0
        elif current == 0x141436fb0:
            if not 0 < b <= 128: raise ValueError('Handler allocation bound')
            p = state['heap']; state['heap'] += b * 2 + 16
            uc.mem_write(p, bytes(b * 2)); uc.mem_write(a, struct.pack('<QII', p, b, b)); result = a
        elif current == 0x14145f2c0:
            # The native handler's length/special-empty branches execute; exact
            # comparison of nonempty names is an explicit fixture here.
            def terminated(p):
                data = bytearray()
                for i in range(128):
                    pair = bytes(uc.mem_read(p + i * 2, 2))
                    if pair == bytes(2): return bytes(data)
                    data.extend(pair)
                raise ValueError('Handler comparator bound')
            result = int(terminated(a) != terminated(b)); calls.append('compare')
        elif current == 0x141483160: pass
        else: raise ValueError('Unknown handler fixture')
        if result is not None: uc.reg_write(x.UC_X86_REG_RAX, result)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little')); uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    for a in hooks: hooks[a] = fixture
    def setup(code, ui_case, selection_present, feature_case, player=True):
        state.update(code=code, ui=ui_case, selection=selection_present, feature=feature_case,
            player=player, heap=h.scratch + 0x22000)
        calls.clear()
        for a, size in ((packet, 0x180), (manager, 0x400), (ui, 0x600), (ui_type, 0x80),
                        (metadata, 0x80), (hierarchy, 32), (vtable, 0x600), (feature, 0xb0)):
            uc.mem_write(a, bytes(size))
        uc.mem_write(selection - 16, b'\xa5' * (0x410 + 32))
        uc.mem_write(packet + 0x10, struct.pack('<I', code))
        uc.mem_write(packet + 0x20, struct.pack('<Q', 0xfedcba9876543210))
        uc.mem_write(ui, struct.pack('<Q', vtable)); uc.mem_write(ui + 0x10, struct.pack('<Q', ui_type))
        uc.mem_write(vtable + 0x598, struct.pack('<Q', 0x141403c50))
        uc.mem_write(metadata + 0x38, struct.pack('<i', 1))
        uc.mem_write(ui_type + 0x30, struct.pack('<Qi', hierarchy, 0 if ui_case == 'range' else 2))
        uc.mem_write(hierarchy + 8, struct.pack('<Q', metadata + (0x20 if ui_case == 'mismatch' else 0x30)))
        uc.mem_write(ui + 0x378, b'\x01')
        uc.mem_write(0x14b2f314b, bytes((int(ui_case == 'disabled'),)))
        uc.mem_write(0x14b595033, bytes((int(feature_case != 'off'),)))
        uc.mem_write(feature + 0xa0, struct.pack('<Q', 0x12345678 if feature_case == 'active' else 0))
    cases = []
    names = (('Carnage', 'Carnage', True), ('Carnage', 'Otherxx', False),
        ('A', 'Longer', False), ('', '', True))
    for (expected_name, returned_name, match), selected, ui_case, feature_case in itertools.product(
            names, (False, True), ('valid', 'missing', 'mismatch', 'range'), ('off', 'absent', 'empty', 'active')):
        setup(0, ui_case, selected, feature_case)
        put(manager + 0x350, expected_name); put(packet + 0x30, returned_name)
        before = bytes(uc.mem_read(packet, 0x180)); before_selection = bytes(uc.mem_read(selection - 16, 0x410 + 32))
        h.call(0x146796690, 0, 0, packet, budget=200000)
        expected_events = (['compare'] if len(expected_name) == len(returned_name) and expected_name else [])
        if match: expected_events.append('name_match')
        expected_events += ['record'] + (['ui_refresh'] if ui_case == 'valid' else []) + ['success_finalize']
        if feature_case == 'active': expected_events.append('feature')
        if calls != expected_events: raise ValueError('Handler success event sequence differs: ' + repr((calls, expected_events)))
        expected_bytes = bytearray(before_selection)
        if selected: struct.pack_into('<Q', expected_bytes, 16 + 0x400, 0xfedcba9876543210)
        if bytes(uc.mem_read(selection - 16, len(expected_bytes))) != bytes(expected_bytes): raise ValueError('Handler selection/key write differs')
        if bytes(uc.mem_read(packet, 0x180)) != before: raise ValueError('Handler modified result packet')
        cases.append(dict(code=0, name_match=match, selection_present=selected, ui=ui_case,
            feature=feature_case, events=calls.copy(), selected_key_written=selected, packet_unchanged=True))
    errors = []
    for code, player, ui_case in itertools.product((1, 59, 0xffffffff), (False, True),
            ('valid', 'missing', 'disabled', 'mismatch', 'range')):
        setup(code, ui_case, False, 'off', player)
        fault = None
        try: h.call(0x146796690, 0, 0, packet, budget=100000)
        except h.env.unicorn.UcError as error:
            fault = str(error)
        expected_fault = player and ui_case != 'valid'
        if bool(fault) != expected_fault: raise ValueError('Handler invalid-UI fault boundary differs')
        if calls != ['error']: raise ValueError('Handler error unexpectedly used success state')
        wait = uc.mem_read(ui + 0x378, 1)[0]
        if wait != (0 if player and ui_case == 'valid' else 1): raise ValueError('Handler error wait state differs')
        errors.append(dict(code=code, player_state_present=player, ui=ui_case,
            error_forwarded=True, wait_cleared=wait == 0, null_ui_fault=bool(fault)))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, cases=cases, errors=errors,
        evidence=dict(path=str(evidence), sha256=h.audit.sha256(evidence)),
        dependencies={name: h.audit.sha256(HERE / name) for name in
            ('replay-release-archive-input.py', 'build-native-entry-code.py',
             'extract-native-enums.py', 'build-object-zero-init-code.py', 'requirements-native.txt')},
        limits=['Whole handler executes with captured manager/state/UI/feature/error calls. Name comparator, FString allocation/free and all called side effects are fixtures.',
            'Success inserts the record regardless of name-match callback; native key write and wait reset execute on guarded synthetic state.',
            'Invalid error UI after an earlier present PlayerState reaches a null+0x378 write in this build; captured emulator faults are a boundary observation, not a live crash claim.',
            'Codes 1/59/ffffffff are raw fixtures with no name-taken meaning. No automatic retry inferred.',
            'No actual account persistence, record-manager internals, game, authorization or network.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-character-create-handler', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), success_cases=len(report['cases']), error_cases=len(report['errors']))))
