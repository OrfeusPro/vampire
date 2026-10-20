"""Locate remaining Version/Login input globals with the reviewed PE/RIP indexer.

Static candidates are decoded at their enclosing unwind instruction boundaries.
No process memory, credentials, execution or inferred active profile.
"""
import hashlib
import importlib.util
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('login_inputs_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
TARGETS = {
    0x14b058cb2: 'Version_Input38First_buffer',
    0x14b058cbf: 'Version_Input38Second_buffer',
    0x14b14ae28: 'Version_b0_Login_110_pointer',
    0x14b125530: 'Version_c0_Login_120_dword',
    0x14b520d10: 'NetworkSetting_AppVersion',
}
BUFFER_REGION = (0x14b058c80, 0x14b058d20)
LITERALS = {
    0x148a3a750: ('Android', 'utf-16le'), 0x148e34f60: ('IOS', 'utf-16le'),
    0x148a45270: ('Windows', 'utf-16le'), 0x14899fb38: ('Windows', 'ascii'),
    0x1489bf724: ('_', 'ascii'), 0x14898d7c8: ('Unknown', 'utf-16le'),
    0x14899ce98: ('|', 'utf-16le'), 0x14899cea0: ('%s|%s|%s', 'utf-16le'),
    0x14899ceb8: ('%s|%s', 'utf-16le'), 0x1489e4168: ('::', 'utf-16le'),
    0x1489cb208: ('%d.%d.%d.%d.%d.%s', 'utf-16le'),
}


def memory_candidates(image, targets):
    """Seed roots from common RIP memory encodings; full decode validates hits.

    This byte prefilter is not an instruction decoder or an exhaustive xref index.
    Prefixes are handled by the subsequent unwind-boundary Capstone decode.
    """
    result = []
    pattern = re.compile(rb'[\x80\x81\x83\x88\x89\x8a\x8b\x8d\xc6\xc7\x31\x33\x39\x3b\xb6\xb7][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
    for section in image.pe.sections:
        if section['name'] != '.text': continue
        start, size = section['raw'], section['raw_size']
        for match in pattern.finditer(image.data, start, start + size - 6):
            offset = match.start()
            address = image.pe.base + section['rva'] + offset - start
            displacement = struct.unpack_from('<i', image.data, offset + 2)[0]
            for trailing in (0, 1, 4):
                target = address + 6 + trailing + displacement
                if target in targets: result.append((address, target))
    return result


def build():
    meta = json.loads((native.ROOT / 'code-clues/headless-network-index.json').read_text('utf-8'))
    raw = Path(meta['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != meta['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    targets = set(TARGETS) | set(range(*BUFFER_REGION))
    candidates = native.rip_candidates(image, targets) + memory_candidates(image, targets)
    roots = {image.roots[entry] for address, _ in candidates if (entry := image.containing(address)) is not None}
    fragments = native.decode_ranges(image, roots)
    references = []
    for fragment in fragments:
        for row in fragment['instructions']:
            for address in row['rip_references']:
                if address not in targets: continue
                references.append(dict(target=hex(address), name=TARGETS.get(address, 'Input38_buffer_neighbour'), instruction=row,
                    root=hex(image.pe.base + fragment['root_begin_rva'])))
    data = []
    for address, name in TARGETS.items():
        rva = address - image.pe.base
        section = next(section for section in image.pe.sections if section['rva'] <= rva and
            rva + 16 <= section['rva'] + section['size'])
        if rva >= section['rva'] + section['raw_size']:
            data.append(dict(address=hex(address), name=name, file_backed=False,
                section=section, initial_mapping='PE zero-fill; later writes not resolved'))
            continue
        offset = image.offset(rva)
        value = raw[offset:offset + 16]
        item = dict(address=hex(address), name=name, file_offset=offset,
            bytes=value.hex(), sha256=hashlib.sha256(value).hexdigest())
        if address == 0x14b14ae28:
            pointer = struct.unpack_from('<Q', value)[0]
            target_offset = image.offset(pointer - image.pe.base)
            end = raw.index(b'\0', target_offset, target_offset + 256)
            text = raw[target_offset:end + 1]
            item['pointee'] = dict(address=hex(pointer), file_offset=target_offset, bytes=text.hex(),
                ascii=text[:-1].decode('ascii'), sha256=hashlib.sha256(text).hexdigest())
        data.append(item)
    literal_proofs = []
    for address, (text, encoding) in LITERALS.items():
        offset = image.offset(address - image.pe.base)
        encoded = (text + '\0').encode(encoding)
        if raw[offset:offset + len(encoded)] != encoded: raise ValueError('Version source literal changed')
        literal_proofs.append(dict(address=hex(address), file_offset=offset, text=text, encoding=encoding,
            bytes=encoded.hex(), sha256=hashlib.sha256(encoded).hexdigest()))
    return dict(schema_version=1, source=meta['source'], source_sha256=meta['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        indexer_sha256=hashlib.sha256((HERE / 'build-native-entry-code.py').read_bytes()).hexdigest(),
        targets=data, literals=literal_proofs, buffer_search_region=list(map(hex, BUFFER_REGION)), references=references, fragments=fragments,
        scope='Common RIP-encoding seeded roots; not exhaustive write references or active runtime values.')


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/game-login-input-index.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        roots=sorted({row['root'] for row in report['references']}),
        compiled_pointer=next(item.get('pointee') for item in report['targets'] if 'pointee' in item))))
