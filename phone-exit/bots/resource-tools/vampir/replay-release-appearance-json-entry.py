"""Whole appearance entry helper; definition lookup and JSON engine are captures."""
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('appearance_entry_archive', HERE / 'replay-release-archive-input.py')
    archive = importlib.util.module_from_spec(spec); spec.loader.exec_module(archive)
    hooks = (0x141426780, 0x14566c5e0, 0x145466740, 0x1414b93c0, 0x1414c3fa0,
        0x141436fb0, 0x141483160, 0x1415f2740)
    fixtures = dict.fromkeys(hooks)
    h = archive.make_harness(extra_addresses=(0x1456746c0,), fixtures=fixtures)
    uc, x = h.uc, h.x
    context, input_text, input_data, definition, key_text, key_data, text_object, text_vtable = [
        h.scratch + n for n in (0x10000, 0x11000, 0x12000, 0x13000, 0x14000, 0x15000, 0x16000, 0x17000)]
    cleanup = h.scratch + 0x18000
    # A reviewed fixture object needs only its destructor virtual slot.
    h.ranges.append((cleanup, cleanup + 1))
    uc.mem_write(cleanup, b'\xc3')
    uc.mem_write(text_vtable, struct.pack('<QQQ', 0, 0, cleanup))
    uc.mem_write(text_object, struct.pack('<Q', text_vtable))
    state, events = {}, []
    def finish(result=None):
        if result is not None: uc.reg_write(x.UC_X86_REG_RAX, result)
        sp = uc.reg_read(x.UC_X86_REG_RSP)
        uc.reg_write(x.UC_X86_REG_RIP, int.from_bytes(uc.mem_read(sp, 8), 'little'))
        uc.reg_write(x.UC_X86_REG_RSP, sp + 8)
    def string(at):
        p, units, cap = struct.unpack('<QII', bytes(uc.mem_read(at, 16)))
        if not 0 <= units <= cap <= 64: raise ValueError('Appearance entry string bound')
        return bytes(uc.mem_read(p, max(0, units - 1) * 2)).decode('utf-16le') if units else ''
    def fixture(machine):
        at = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(reg) for reg in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        if at == 0x141426780:
            if b != input_text: raise ValueError('Appearance entry input FString contract')
            machine.mem_write(a, bytes(machine.mem_read(b, 16))); finish(a)
        elif at == 0x14566c5e0:
            events.append(dict(kind='mode', value=b & 255))
            machine.mem_write(a, bytes(16)); finish(a)
        elif at == 0x145466740:
            events.append(dict(kind='lookup'))
            finish(definition if state['found'] else 0)
        elif at == 0x1414b93c0:
            events.append(dict(kind='key_id', value=b & 0xffffffff))
            machine.mem_write(a, struct.pack('<QQ', text_object, 0))
            machine.mem_write(d, bytes(16)); finish(a)
        elif at == 0x1414c3fa0:
            finish(key_text)
        elif at == 0x141436fb0:
            if b > 64: raise ValueError('Appearance entry allocation bound')
            pointer = h.scratch + 0x19000
            machine.mem_write(pointer, bytes(b * 2))
            machine.mem_write(a, struct.pack('<QII', pointer, b, b)); finish(a)
        elif at == 0x1415f2740:
            if a != context: raise ValueError('Appearance entry JSON object changed')
            value = struct.unpack('<d', machine.reg_read(x.UC_X86_REG_XMM2).to_bytes(16, 'little')[:8])[0]
            events.append(dict(kind='json_number', key=string(b), value_hex=struct.pack('<d', value).hex())); finish()
        else: finish()  # Explicit free fixture, preserving return register.
    for at in hooks: fixtures[at] = fixture
    cases = []
    for found in (False, True):
        for mode in (0, 1, 255):
            for value in (0.0, -0.0, 0.125, -2.5):
                events.clear(); state['found'] = found
                name = 'fixture_setting'
                encoded = name.encode('utf-16le') + b'\0\0'
                uc.mem_write(input_data, encoded)
                uc.mem_write(input_text, struct.pack('<QII', input_data, len(encoded) // 2, len(encoded) // 2))
                uc.mem_write(context, struct.pack('<Q', context))
                uc.mem_write(definition + 0x10, struct.pack('<I', 0x12345678))
                key = 'converted_fixture_key'; encoded = key.encode('utf-16le') + b'\0\0'
                uc.mem_write(key_data, encoded)
                uc.mem_write(key_text, struct.pack('<QII', key_data, len(encoded) // 2, len(encoded) // 2))
                f32 = struct.unpack('<f', struct.pack('<f', value))[0]
                uc.reg_write(x.UC_X86_REG_XMM2, int.from_bytes(struct.pack('<f', f32), 'little'))
                h.call(0x1456746c0, context, input_text, 0, mode, budget=20000)
                expected = [dict(kind='mode', value=mode), dict(kind='lookup')]
                if found:
                    expected += [dict(kind='key_id', value=0x12345678),
                        dict(kind='json_number', key=key, value_hex=struct.pack('<d', f32).hex())]
                if events != expected: raise ValueError('Appearance entry boundary inputs differ: ' + repr(events))
                cases.append(dict(found=found, mode=mode, input_float_hex=struct.pack('<f', f32).hex(), events=events.copy()))
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), native_execution=True,
        network_used=False, cases=cases,
        limits=['Whole entry helper 0x1456746c0 executes, including missing-definition branch and float-to-double.',
            'FString copy/storage/free, mode-name helper, definition lookup, text-key conversion and JSON setter are fixtures/captures.',
            'Definition ID and converted key synthetic; no actual definition catalogue, JSON engine output or valid appearance defaults.',
            'No network, producer or character creation.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-appearance-json-entry', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']))))
