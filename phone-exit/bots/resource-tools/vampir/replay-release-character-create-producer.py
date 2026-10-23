"""Whole ID 103 producer and writer; JSON/UI/dispatch are explicit captures."""
import importlib.util
import itertools
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def run():
    spec = importlib.util.spec_from_file_location('producer_native_writer', HERE / 'replay-release-character-create-writer.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.run(producer=True)


def run_with_writer(h, packet, output, chunks, widths):
    from vampir_core.character_create import CharacterCreatePayload, encode_character_create
    uc, x = h.uc, h.x
    owner, player, service = [h.scratch + n for n in (0x14000, 0x15000, 0x16000)]
    table = 0x149ca7190
    def at(address, count):
        off = h.image.offset(address - h.image.pe.base)
        return h.raw[off:off + count]
    if struct.unpack('<Q', at(table + 0x48, 8))[0] != 0x146449dc0 or struct.unpack('<Q', at(table + 0x90, 8))[0] != 0x14644a0c0:
        raise ValueError('Producer owner virtual bindings differ')
    page = table & ~4095
    if not any(a <= page <= b for a, b, _ in uc.mem_regions()):
        uc.mem_map(page, 4096); uc.mem_write(page, at(page, 4096))
    sentinel = struct.unpack('<I', at(0x1496726a0, 4))[0]
    dispatch_argument = struct.unpack('<Q', at(0x149672698, 8))[0]
    scalar_export = h.comparison / 'details/run-8d15dc4015fc/details.json'
    if h.audit.sha256(scalar_export) != '1e1a52528141a45e58a3d698ea9329d13ab90f8a314531f329e7e2ecd75c9b00':
        raise ValueError('Preset scalar helper export changed')
    scalar_bindings = {'HeadIndex': (0x14642dc20, 9), 'SkinColorIndex': (0x14642e0e0, 10),
        'HairIndex': (0x14642da10, 11), 'HairColorIndex': (0x14642dbd0, 12),
        'EyeColorLeftIndex': (0x14642d940, 13), 'EyeColorRightIndex': (0x14642d940, 14),
        'EyeTexIndex': (0x14642d9c0, 15), 'DecalIndex': (0x14642d880, 16),
        'DecalColorIndex': (0x14642d8f0, 17), 'VoiceType': (0x146425770, 0x28)}
    spec = importlib.util.spec_from_file_location('producer_preset_candidate', HERE / 'extract-release-creation-presets.py')
    presets = importlib.util.module_from_spec(spec); spec.loader.exec_module(presets)
    root = h.native.ROOT
    index = root / 'release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/record-indexes/f64ec55098c97fa6bfd0d620e4c397a13b26119c76dde35abb0d9f6cebd5a714/3a313dbd09096213bd92cd033a06337beb4ed38f5ca3f0ee936f7cba055c0adc/manifest.json'
    directory = root / 'resource-config-snapshots/3c1151930e190baf7fb7093c976222e4c2e053bef816c077e689c8a4b1de44a3/manifest.json'
    preset_path, preset_report = presets.extract(index, directory, root)
    female = [p for p in preset_report['packages'] if p['package'].endswith('DA_PresetDarkMage3_F')]
    if len(female) != 1: raise ValueError('Producer model candidate asset missing')
    projection = female[0]['native_default_projection']; candidate = projection['values']
    candidate_scalar = [candidate[name] for name in ('HeadIndex', 'SkinColorIndex', 'HairIndex',
        'HairColorIndex', 'EyeColorLeftIndex', 'EyeColorRightIndex', 'EyeTexIndex', 'DecalIndex', 'DecalColorIndex')]
    # Explicit JSON fixture: key conversion and native JSON output are a separate check.
    candidate_json = json.dumps({'VoiceType': candidate['VoiceType'], **{
        str(i): candidate[name] for i, name in enumerate(('Height', 'Cheat', 'Pelvis',
            'Shape', 'Waist', 'Thigh', 'Head'), 1)}}, separators=(',', ':'))
    state, calls, captures = {}, [], []
    def put_text(address, value):
        raw = value.encode('utf-16le') + b'\0\0' if value else b''
        pointer = h.allocate(len(raw)) if raw else 0
        if raw: uc.mem_write(pointer, raw)
        uc.mem_write(address, struct.pack('<QII', pointer, len(raw) // 2, len(raw) // 2))
    def get_text(address):
        pointer, count, capacity = struct.unpack('<QII', bytes(uc.mem_read(address, 16)))
        if not 0 <= count <= capacity <= 2048: raise ValueError('Producer FString capture bounds')
        if not count: return ''
        raw = bytes(uc.mem_read(pointer, count * 2))
        if raw[-2:] != bytes(2): raise ValueError('Producer FString has no terminator')
        return raw[:-2].decode('utf-16le')
    def fixture(machine):
        current = machine.reg_read(x.UC_X86_REG_RIP)
        a, b, c, d = [machine.reg_read(r) for r in
            (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        calls.append(hex(current)); result = None
        if current == 0x14644a0c0:
            if a != owner: raise ValueError('Producer class getter owner differs')
            result = state['class']
        elif current == 0x14641af30: result = player if state['present'] else 0
        elif current == 0x146447e50:
            if a != owner + 8: raise ValueError('Producer JSON owner adjustment differs')
            put_text(b, state['json']); result = b
        elif current == 0x144aaf870: result = service
        elif current == 0x144aafc50:
            if (a, c, d) != (service, 104, dispatch_argument): raise ValueError('Producer dispatch arguments differ')
            sp = machine.reg_read(x.UC_X86_REG_RSP)
            if bytes(machine.mem_read(sp + 0x28, 4)) != bytes(4): raise ValueError('Producer dispatch fifth float differs')
            if not h.scratch <= b <= h.scratch + 0x40000 - 0x70: raise ValueError('Producer packet outside fixture memory')
            payload = CharacterCreatePayload(int.from_bytes(machine.mem_read(b + 0x18, 4), 'little'),
                get_text(b + 0x20), tuple(machine.mem_read(b + 0x38, 10)), get_text(b + 0x48),
                tuple(machine.mem_read(b + 0x58, 2)), ())
            if bytes(machine.mem_read(b + 0x60, 16)) != bytes(16): raise ValueError('Producer emitted unexpected items')
            captures.append((bytes(machine.mem_read(b, 0x70)), payload)); result = 1
        elif current == 0x141436fb0:
            if not 0 < b <= 2048: raise ValueError('Producer string allocation bound')
            pointer = h.allocate(b * 2)
            machine.mem_write(a, struct.pack('<QII', pointer, b, b)); result = a
        elif current == 0x1456d9440:
            if not h.scratch <= a <= h.scratch + 0x40000 - 0x70:
                raise ValueError('Producer destruction capture bounds')
        else: raise ValueError('Unexpected producer fixture')
        h.finish(result)
    for address in (0x14644a0c0, 0x14641af30, 0x146447e50, 0x144aaf870,
                    0x144aafc50, 0x1456d9440, 0x141436fb0): h.fixtures[address] = fixture
    cases = []
    scenarios = list(itertools.product(
            (sentinel, 3, 0xffffffff), (False, True), ('', 'NightRaven', 'Ж界🙂'),
            ('', '{"VoiceType":0,"1":0.4}')))
    scenarios.append((3, True, 'CandidateCarnage', candidate_json))
    for raw_class, present, name, appearance_json in scenarios:
        h.string_heap[0] = h.scratch + 0x20000
        calls.clear(); captures.clear(); chunks.clear(); widths.clear()
        state.update({'class': raw_class, 'present': present, 'json': appearance_json})
        uc.mem_write(owner - 16, b'\xa5' * (0x90 + 32)); uc.mem_write(owner, bytes(0x90))
        uc.mem_write(owner, struct.pack('<Q', table)); uc.mem_write(owner + 8, b'\xfe')
        model_candidate = name == 'CandidateCarnage'
        scalar = candidate_scalar if model_candidate else list(range(1, 10)) if appearance_json else [0] * 9
        uc.mem_write(owner + 9, bytes(scalar))
        gender = 1 if raw_class == 3 else 255
        uc.mem_write(owner + 0x30, bytes((gender,)))
        uc.mem_write(player, bytes(0x400)); put_text(player + 0x368, name)
        before_owner = bytes(uc.mem_read(owner - 16, 0x90 + 32)); before_player = bytes(uc.mem_read(player, 0x400))
        h.call(0x146449dc0, owner, budget=200000)
        should_send = raw_class != sentinel and present
        if len(captures) != int(should_send): raise ValueError('Producer dispatch count differs')
        if bytes(uc.mem_read(owner - 16, 0x90 + 32)) != before_owner or bytes(uc.mem_read(player, 0x400)) != before_player:
            raise ValueError('Producer changed input owner/PlayerState')
        if ('0x14641af30' in calls) != (raw_class != sentinel): raise ValueError('Producer sentinel did not stop before PlayerState')
        if ('0x146447e50' in calls) != should_send: raise ValueError('Producer called JSON for blocked input')
        case = dict(raw_class=raw_class, player_state_present=present, name=name, json_fixture=appearance_json,
            dispatched=should_send, model_candidate=model_candidate, input_guards_unchanged=True, calls=calls.copy())
        if should_send:
            captured, payload = captures[0]
            expected = CharacterCreatePayload(raw_class, name,
                (gender, scalar[2], scalar[3], scalar[0], scalar[1], *scalar[4:]), appearance_json, (0, 0), ())
            if payload != expected: raise ValueError('Producer field order or constructor defaults differ')
            uc.mem_write(packet, captured); h.call(0x144aada00, output)
            if h.call(0x1456bb7d0, packet, output, budget=200000) & 255 != 1:
                raise ValueError('Producer packet writer rejected')
            body = b''.join(chunks)
            if body != encode_character_create(payload, source_sha256=h.sha):
                raise ValueError('Producer native wire differs from portable encoder')
            case.update(appearance=list(payload.appearance), raw_flags=list(payload.raw_flags),
                item_count=0, body_hex=body.hex(), expected_result_id=104)
        cases.append(case)
    evidence = h.comparison / 'details/run-33b73b3d42b9/details.json'
    if h.audit.sha256(evidence) != '977ff56c28a82d5ee388b4e464802f2675d0fbe7c2374fe99d16ccddb1e2f460':
        raise ValueError('Whole producer export changed')
    report = dict(source_sha256=h.sha, tool_sha256=h.audit.sha256(Path(__file__)), native_execution=True,
        network_used=False, sentinel=sentinel, cases=cases, producer='0x146449dc0',
        native_writer='0x1456bb7d0', evidence=dict(path=str(evidence), sha256=h.audit.sha256(evidence)),
        scalar_bindings={name: dict(helper=hex(a), owner_offset=b, method='static') for name, (a, b) in scalar_bindings.items()},
        scalar_export=dict(path=str(scalar_export), sha256=h.audit.sha256(scalar_export)),
        model_candidate=dict(preset_report=str(preset_path), asset=female[0]['package'],
            model_only=True, verified_loaded_asset=False, json_fixture=True),
        portable_encoder_sha256=h.audit.sha256(HERE.parents[1] / 'vampir-shared/vampir_core/character_create.py'),
        dependencies={name: h.audit.sha256(HERE / name) for name in ('replay-release-character-create-writer.py',
            'replay-release-fstring-input.py', 'replay-release-archive-input.py', 'build-native-entry-code.py',
            'extract-native-enums.py', 'build-object-zero-init-code.py', 'extract-release-creation-presets.py',
            'replay-release-preset-object.py', 'requirements-native.txt')},
        limits=['Whole producer, packet constructors, whole writer, scalar/UTF8 conversion execute; portable encoder compared byte-for-byte.',
            'Class getter, PlayerState, JSON helper, service lookup and dispatch are fixtures/captures. JSON text is explicitly supplied, not native JSON generation.',
            'FString storage, bounded memcpy/raw output, packet destruction/free and security are fixtures; native cleanup not covered.',
            'Synthetic boundary inputs include invalid class/gender and empty names; this is control-flow/serialization evidence, not server acceptance.',
            'Preset scalar-to-owner mapping is static evidence from exported helpers; whole UI helpers/renderer are not executed.',
            'One Carnage/F model candidate uses explicit inferred defaults and JSON fixture; it does not establish loaded-asset equivalence or server acceptance.',
            'No native JSON/key generation, whole ID 104 handler, game, authorization or network.'])
    path = h.audit.save_snapshot(h.native.ROOT / 'code-clues/release-character-create-producer', report)
    return path, report


if __name__ == '__main__':
    path, report = run()
    print(json.dumps(dict(report=str(path), cases=len(report['cases']), dispatch_captures=sum(c['dispatched'] for c in report['cases']))))
