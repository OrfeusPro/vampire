"""Separate Login refusals from an accepted empty list using current native code."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
LOGIN_HANDLER = 0x14679c4f0


def run():
    spec = importlib.util.spec_from_file_location('empty_character_handler', HERE / 'replay-release-character-handler.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    em = module.Emulator(extra_addresses=(LOGIN_HANDLER,), extra_leaves=(0x141453d20,))
    h, ctx = em.h, em.context
    evidence = h.comparison / 'bootstrap/run-887dcf19fe4a/export/bootstrap.json'
    if h.audit.sha256(evidence) != '7f245fa66bbeceee87fd7933b9c6376079e1b7779493d7255463b2105c3c6aed':
        raise ValueError('Current Login handler export changed')
    x, uc = h.x, h.uc
    # Independently checked packet and handler tables from current factory data.
    for table, slot, target in ((0x1499284b0, 0x28, 0x141453d20),
                                (0x149dc85d8, 0x10, LOGIN_HANDLER)):
        offset = h.image.offset(table - h.image.pe.base)
        if struct.unpack_from('<Q', h.raw, offset + slot)[0] != target:
            raise ValueError('Current Login packet / handler binding changed')
        em.map_source(table & ~4095)
    original = em.fixture

    def fixture(machine):
        address = machine.reg_read(x.UC_X86_REG_RIP)
        a, b = [machine.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX)]
        if address == 0x144ab1f70:
            if a != ctx + 0xb000 or b != 0:
                raise ValueError('Unexpected refusal transport arguments')
            em.events.append(dict(action='login_transport_capture', value=b))
            h.finish(0)
        elif address == 0x1445ce210:
            h.finish(ctx + 0xe000)
        elif address == 0x1445cfd70:
            if not h.scratch + 0x2f000 <= b <= h.scratch + 0x30000:
                raise ValueError('Refusal message output fixture bounds')
            machine.mem_write(b, bytes(16))
            h.finish(b)
        elif address == 0x144a526f0:
            em.events.append(dict(action='error_popup_capture'))
            h.finish(0)
        else:
            original(machine)

    em.fixture = fixture
    for address in (0x144ab1f70, 0x1445ce210, 0x1445cfd70, 0x144a526f0):
        em.map_source(address & ~4095)
        h.fixtures[address] = lambda machine: em.fixture(machine)
    empty_cases, refusals = [], []
    body = struct.pack('<IIHQIQQ', 0, 0, 0, 0, 0, 0, 0)
    for gate_state, ui_present, owner_present, previous in itertools.product((0, 1), (False, True), (False, True), ((), (77, 88))):
        options = dict(gate_state=gate_state, policy_disabled=False, policy_present=True, policy=1,
            ui_present=ui_present, owner_present=owner_present, previous_ids=previous)
        row = em.execute(body, options)
        if row['decoded']['count'] != 0 or row['state']['count'] != 0 or row['state']['record_raw8']:
            raise ValueError('Accepted empty list did not clear records')
        actions = [event['action'] for event in row['events']]
        if 'selection_exit_capture' in actions or actions.count('selection_event_capture') != 1:
            raise ValueError('Empty list took refusal path')
        if row['selected_index'] != (0 if ui_present else None):
            raise ValueError('Native empty UI index changed')
        empty_cases.append(row)
    packet = ctx + 0xc000
    for code, gate_state, message in itertools.product((57, 58, 59), (0, 1), (None, '', 'notice')):
        uc.mem_write(ctx, bytes(0x10000))
        uc.mem_write(packet, struct.pack('<Q', 0x1499284b0))
        uc.mem_write(packet + 0x10, struct.pack('<I', code))
        if message is not None:
            data = (message + '\0').encode('utf-16le')
            uc.mem_write(ctx + 0xd000, data)
            uc.mem_write(packet + 0x38, struct.pack('<QII', ctx + 0xd000, len(data) // 2, len(data) // 2))
        before = bytes(uc.mem_read(packet, 0x140))
        for offset, value in ((0x5000, ctx + 0x5100), (0x5138, module.EXIT)):
            uc.mem_write(ctx + offset, struct.pack('<Q', value))
        uc.mem_write(ctx + 0x6008, bytes([gate_state]))
        em.options, em.events, em.phase = {}, [], True
        stack, stop = h.scratch + 0x30000, h.scratch + 0x3f000
        uc.mem_write(stack, struct.pack('<Q', stop))
        for register, value in ((x.UC_X86_REG_RSP, stack), (x.UC_X86_REG_RCX, ctx),
                                (x.UC_X86_REG_RDX, 0), (x.UC_X86_REG_R8, packet)):
            uc.reg_write(register, value)
        uc.emu_start(LOGIN_HANDLER, stop, count=250000)
        if uc.reg_read(x.UC_X86_REG_RIP) != stop or bytes(uc.mem_read(packet, 0x140)) != before:
            raise ValueError('Refusal handler incomplete or changed packet')
        events = em.events.copy()
        gates = [event for event in events if event['action'] == 'native_gate']
        if gates != [dict(action='native_gate', code=code, packet_id=4)]:
            raise ValueError('Login refusal gate arguments differ')
        actions = [event['action'] for event in events]
        if actions.count('login_transport_capture') != 1:
            raise ValueError('Login refusal transport capture missing')
        if bool(message) != ('error_popup_capture' in actions) or bool(message) == ('selection_exit_capture' in actions):
            raise ValueError('Refusal message / exit branch differs')
        if any(action in actions for action in ('list_copy_capture', 'owner_a00_capture', 'selection_event_capture')):
            raise ValueError('Refusal unexpectedly entered list continuation')
        refusals.append(dict(code=code, gate_state=gate_state, message_fixture=message, events=events))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)),
        native_execution=True, network_used=False, empty_cases=empty_cases, refusal_cases=refusals,
        evidence_sha256=h.audit.sha256(evidence),
        limits=['Actual complete current ID102 readers/gate/predicate/handler and complete ID4 refusal handler/gate execute.',
            'Login packet native layout is a synthetic fixture, not a new live response or a native Login reader replay.',
            'Engine state, policy, guard, globals and prior records are fixtures; UI, transport, allocation and string backends are captures.',
            'Popup callbacks and owner continuation are not executed; no proof of full UI creation lifecycle.',
            'No socket, Login retry, creation request or account mutation.'])
    path = h.audit.save_snapshot(h.comparison / 'empty-character-entry-replay', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), empty_cases=len(report['empty_cases']), refusal_cases=len(report['refusal_cases']))))
