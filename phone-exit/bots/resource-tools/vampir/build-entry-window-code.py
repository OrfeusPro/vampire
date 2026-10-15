"""Connect reviewed entry widget literals to getter fragments and direct callers."""
import hashlib
import importlib.util
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('window_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
ROOT = native.ROOT
WINDOWS = {'WBP_ServerSelectPopup', 'WBP_CharacterSelectUI', 'WBP_PatchUI', 'WBP_PatchPopup', 'WBP_TitleUI'}


def direct_call_candidates(data, raw_start, raw_size, address_of, targets):
    result = []
    for match in re.finditer(b'\xe8', data[raw_start:raw_start + raw_size]):
        offset = raw_start + match.start()
        if offset + 5 > raw_start + raw_size:
            continue
        address = address_of(offset)
        target = address + 5 + struct.unpack_from('<i', data, offset + 1)[0]
        if target in targets:
            result.append((address, target))
    return result


def checked_call(instruction, target):
    return (instruction is not None and instruction['mnemonic'] == 'call'
            and instruction['call'] and instruction['direct_target'] == target
            and len(bytes.fromhex(instruction['bytes'])) == 5
            and instruction['bytes'].startswith('e8'))


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    source_path = ROOT / 'code-clues/native-ui-links.json'
    source = json.loads(source_path.read_text(encoding='utf-8'))
    data = Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Native executable changed')
    image = native.Image(data)
    refs = [row for row in source['references'] if row['literal']['canonical_path'].rsplit('/', 1)[-1] in WINDOWS]
    roots = {image.roots[image.containing(row['instruction']['address'])] for row in refs}
    getters = native.decode_ranges(image, roots)
    getter_rows = {row['address']: row for fragment in getters for row in fragment['instructions']}
    for row in refs:
        current = getter_rows.get(row['instruction']['address'])
        if current != row['instruction']:
            raise ValueError('Indexed widget instruction changed')
    diagnostic_refs = []
    for fragment in getters:
        for instruction in fragment['instructions']:
            for address in instruction['rip_references']:
                try:
                    offset = image.offset(address - image.pe.base)
                except ValueError:
                    continue
                match = re.match(rb'(?:[\x20-\x7e]\x00){4,}', data[offset:offset + 2048])
                if match:
                    text = match.group().decode('utf-16le')
                    if 'bInitialized' in text or 'CreateUI' in text:
                        diagnostic_refs.append(dict(instruction=instruction,
                            literal=dict(file_offset=offset, text=text, encoding='utf-16le'),
                            root_begin_rva=fragment['root_begin_rva']))
    leaf_checks = []
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    for address in (0x145642620, 0x145642630):
        offset = image.offset(address - image.pe.base)
        raw = data[offset:offset + 8]
        rows = list(decoder.disasm(raw, address))
        if (len(rows) != 2 or rows[0].mnemonic != 'movzx'
                or not rows[0].op_str.startswith('eax, byte ptr [rip + ')
                or rows[1].mnemonic != 'ret' or sum(row.size for row in rows) != 8):
            raise ValueError('Reviewed leaf flag accessor changed')
        leaf_checks.append(dict(address=address, file_offset=offset, bytes=raw.hex(),
            sha256=hashlib.sha256(raw).hexdigest(),
            instructions=[dict(address=row.address, mnemonic=row.mnemonic, operands=row.op_str) for row in rows],
            flag_semantics='unresolved'))
    targets = {image.pe.base + root[0] for root in roots}
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(direct_call_candidates(data, section['raw'], section['raw_size'], image.pe.address, targets))
    caller_roots = {image.roots[function] for address, _ in candidates
                    if (function := image.containing(address)) is not None}
    groups = {root: [] for root in caller_roots}
    for function in image.ranges:
        if image.roots[function] in groups:
            groups[image.roots[function]].append(function)
    caller_fragments, failures = [], []
    for root, functions in groups.items():
        try:
            caller_fragments.extend(native.decode_ranges(image, {root}, functions))
        except ValueError as error:
            failures.append(dict(root_begin_rva=root[0], error=str(error)))
    caller_rows = {row['address']: (fragment, index, row) for fragment in caller_fragments
                   for index, row in enumerate(fragment['instructions'])}
    callers, unresolved = [], []
    for address, target in candidates:
        found = caller_rows.get(address)
        if found is None or not checked_call(found[2], target):
            unresolved.append(dict(address=address, target=target, reason='not_decoded_direct_call'))
            continue
        fragment, index, row = found
        callers.append(dict(instruction=row, target=target, root_begin_rva=fragment['root_begin_rva'],
            context=fragment['instructions'][max(0, index - 12):index + 20],
            fragment={key: value for key, value in fragment.items() if key != 'instructions'},
            runtime_visibility_verified=False))
    result = dict(source=source['source'], sha256=source['sha256'],
        ui_links_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
        widget_references=refs, getter_fragments=getters, callers=callers,
        manager_diagnostic_references=diagnostic_refs, leaf_flag_accessors=leaf_checks,
        caller_decode_failures=failures, unresolved_call_candidates=unresolved,
        limitations=['Only direct E8 calls to unwind roots containing reviewed widget paths.',
                     'Literal-containing roots may create, retrieve or present UI; names are not inferred automatically.',
                     'No proof of complete conditions, virtual/tail calls, Android parity or actual visibility.'])
    target = ROOT / 'code-clues/entry-window-code.json'
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(widget_references=len(refs), roots=len(roots), fragments=len(getters),
        direct_callers=len(callers), unresolved=len(unresolved), caller_decode_failures=len(failures))))


if __name__ == '__main__':
    main()
