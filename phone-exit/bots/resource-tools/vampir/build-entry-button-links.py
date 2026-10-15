"""Join title control names, native field stores and click-dispatch comparisons.

Version-bound, read-only evidence; does not produce phone input coordinates.
"""
import hashlib
import importlib.util
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('button_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
ROOT = native.ROOT


def find_binding(rows, start, expected_getter):
    """Accept only the reviewed name-construction / getter / RAX-store shape."""
    following = rows[start + 1:start + 20]
    calls = [(index, row) for index, row in enumerate(following) if row['call']]
    if len(calls) < 2 or calls[0][1]['direct_target'] != 0x1415a8e80 or calls[1][1]['direct_target'] != expected_getter:
        raise ValueError('Title button lookup sequence changed')
    index, getter = calls[1]
    if not any(row['mnemonic'] == 'mov' and row['operands'] == 'r8, r14' for row in following[:index]):
        raise ValueError('Missing callback owner argument')
    tail = following[index + 1:]
    if tail and tail[0]['mnemonic'] == 'mov' and tail[0]['operands'] == 'rcx, rsi':
        tail = tail[1:]
    if not tail:
        raise ValueError('Missing lookup result store')
    row = tail[0]
    match = re.fullmatch(r'qword ptr \[rdi \+ (0x[0-9a-f]+)\], rax', row['operands'])
    if row['mnemonic'] != 'mov' or not match:
        raise ValueError('Lookup result is not stored in reviewed field form')
    return dict(field_offset=int(match.group(1), 16), name_instruction=rows[start],
                getter_instruction=getter, store_instruction=row)


def match_comparisons(rows, owner_offset, field_offset):
    result = []
    for index, row in enumerate(rows):
        match = re.fullmatch(r'rsi, qword ptr \[rbx \+ (0x[0-9a-f]+)\]', row['operands'])
        if row['mnemonic'] != 'cmp' or not match or int(match.group(1), 16) + owner_offset != field_offset:
            continue
        if index + 1 >= len(rows):
            raise ValueError('Missing comparison branch')
        branch = rows[index + 1]
        if branch['mnemonic'] not in ('je', 'jne') or not branch['direct_target']:
            raise ValueError('Unexpected control comparison branch')
        result.append(dict(comparison=row, branch=branch,
            handler_field_offset=int(match.group(1), 16),
            matching_path='taken' if branch['mnemonic'] == 'je' else 'fallthrough'))
    return result


def main():
    entry_path = ROOT / 'ui-geometry/entry-reference.json'
    entry = json.loads(entry_path.read_text(encoding='utf-8'))
    code_path = ROOT / 'code-clues/entry-code.json'
    code = json.loads(code_path.read_text(encoding='utf-8'))
    if code['sha256'] != entry['native_entry']['sha256']:
        raise ValueError('Entry sources disagree')
    data = Path(code['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != code['sha256']:
        raise ValueError('Executable changed')
    image = native.Image(data)
    # Both addresses were found by references to exact control-name literals.
    binder_root = image.roots[image.containing(0x146428c81)]
    fragments = native.decode_ranges(image, {binder_root})
    rows = sorted((row for fragment in fragments for row in fragment['instructions']), key=lambda row: row['address'])
    instructions = {row['address']: row for row in rows}
    owner_instruction = instructions.get(0x146428c8f)
    if not owner_instruction or owner_instruction['mnemonic'] != 'lea' or owner_instruction['operands'] != 'r14, [rdi + 0xa00]':
        raise ValueError('Binding callback owner adjustment changed')
    handler_rows = sorted((row for fragment in code['fragments'] if fragment['root_begin_rva'] == 0x6417ad0
                           for row in fragment['instructions']), key=lambda row: row['address'])
    handler = {row['address']: row for row in handler_rows}
    expected = [(0x146417ae7, 'mov', 'rsi, rdx'), (0x146417aea, 'mov', 'rbx, rcx'),
                (0x146417f0e, 'lea', 'rsi, [rbx - 0xa00]')]
    for address, mnemonic, operands in expected:
        if address not in handler or (handler[address]['mnemonic'], handler[address]['operands']) != (mnemonic, operands):
            raise ValueError('Handler object/button register relation changed')
    constructor_root = image.roots[image.containing(0x14640a6eb)]
    constructor = native.decode_ranges(image, {constructor_root})
    constructor_rows = {row['address']: row for fragment in constructor for row in fragment['instructions']}
    vtable_load, vtable_store = constructor_rows[0x14640a6eb], constructor_rows[0x14640a6f2]
    if (vtable_load['mnemonic'] != 'lea' or vtable_load['operands'] != 'rax, [rip + 0x384266e]'
            or vtable_store['mnemonic'] != 'mov' or vtable_store['operands'] != 'qword ptr [rbp + 0xa00], rax'
            or len(vtable_load['rip_references']) != 1):
        raise ValueError('Callback subobject vtable assignment changed')
    vtable = vtable_load['rip_references'][0]
    vtable_offset = image.offset(vtable + 8 - image.pe.base)
    pointer = data[vtable_offset:vtable_offset + 8]
    if len(pointer) != 8 or struct.unpack('<Q', pointer)[0] != image.pe.base + 0x6417ad0:
        raise ValueError('Callback vtable slot target changed')
    layouts = [item for item in entry['layouts'] if item['name'] == 'WBP_TitlePanelUI']
    names = {control['name'] for item in layouts for control in item['controls'] if control['type'] == 'NkButton'}
    links = []
    for index, row in enumerate(rows):
        if row['mnemonic'] != 'lea':
            continue
        for address in row['rip_references']:
            offset = image.offset(address - image.pe.base)
            matches = [name for name in names if data[offset:offset + len(name) * 2 + 2] == name.encode('utf-16le') + b'\0\0']
            if not matches:
                continue
            if len(matches) != 1:
                raise ValueError('Ambiguous control name')
            name = matches[0]
            binding = find_binding(rows, index, 0x144a72480)
            comparisons = match_comparisons(handler_rows, 0xa00, binding['field_offset'])
            resources = []
            for item in layouts:
                controls = [control for control in item['controls'] if control['name'] == name and control['type'] == 'NkButton']
                if len(controls) != 1:
                    raise ValueError('Missing or ambiguous source control')
                resources.append(dict(catalog_file=item['catalog_file'], entry=item['entry'], source=item['source'],
                    asset_sha256=item['asset_sha256'], body_sha256=item['body_sha256'], control=controls[0]))
            links.append(dict(name=name, literal=dict(file_offset=offset, encoding='utf-16le', text=name),
                binding=binding, handler_comparisons=comparisons, resources=resources,
                owner_vtable_handler_verified=True, callback_dispatch_target_verified=False, used_for_bot_input=False))
    if len({row['name'] for row in links}) != len(links) or not {'ButtonStart', 'ButtonServerSelect', 'ButtonRegionSelect'} <= {row['name'] for row in links}:
        raise ValueError('Expected unique title control bindings')
    result = dict(source=code['source'], sha256=code['sha256'],
        entry_reference_sha256=hashlib.sha256(entry_path.read_bytes()).hexdigest(),
        entry_code_sha256=hashlib.sha256(code_path.read_bytes()).hexdigest(),
        binder_fragments=fragments, callback_owner_offset=0xa00, owner_instruction=owner_instruction,
        constructor_fragments=constructor,
        owner_vtable=dict(address=vtable, slot_offset=8, file_offset=vtable_offset,
            bytes=pointer.hex(), target=image.pe.base + 0x6417ad0,
            load_instruction=vtable_load, store_instruction=vtable_store),
        handler_register_evidence=[handler[address] for address, _, _ in expected],
        buttons=links, limitations=[
            'Native stores and offset-equivalent comparisons proven for this Windows build only.',
            'Owner vtable slot target proven; full listener registration and event-emission chain not reconstructed.',
            'No inference of control visibility, enabled state, absolute screen geometry or Android parity.'])
    target = ROOT / 'code-clues/entry-button-links.json'
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(buttons=len(links), with_comparisons=sum(bool(row['handler_comparisons']) for row in links),
        bindings=[dict(name=row['name'], field=hex(row['binding']['field_offset']), comparisons=len(row['handler_comparisons'])) for row in links])))


if __name__ == '__main__':
    main()
