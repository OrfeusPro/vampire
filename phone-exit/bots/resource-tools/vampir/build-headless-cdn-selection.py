"""Native config-prefix Find and CDN base selection, with explicit fixture URLs."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cdn_selection_settings', HERE / 'build-headless-sdk-settings.py')
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)
FIND, COMPARE = 0x141428640, 0x1414599a0


def scan_public_records(index_path):
    """Search four exact config markers in bounded records of the fresh pak0."""
    spec = importlib.util.spec_from_file_location('cdn_scan_audit', HERE / 'audit-client-release.py')
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    if audit.sha256(index_path) != index_path.parent.name:
        raise ValueError('Fresh index hash mismatch')
    report = json.loads(index_path.read_text('utf-8'))
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    spec = importlib.util.spec_from_file_location('cdn_public_reader', reader_path)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    if (audit.sha256(reader_path) != report['dependencies']['reader_sha256'] or
            audit.sha256(reader.ROOT / 'tools/oodle-data-shared.dll') != report['dependencies']['oodle_sha256']):
        raise ValueError('Public record decoder changed')
    source = Path(report['source']['path'])
    before = source.stat()
    if audit.sha256(source) != report['source']['sha256']:
        raise ValueError('Public archive changed')
    counts = dict(decoded=0, encrypted_skipped=0, size_skipped=0, errors=0)
    markers, hits = ['NetworkSetting', 'CdnConfigUrl', 'CdnConfigUrlQA', 'ConfigPrefix'], []
    with source.open('rb') as stream:
        for row in report['entries']:
            if row['encrypted']:
                counts['encrypted_skipped'] += 1
                continue
            if max(row['bytes'], row['uncompressed']) > 16 * 1024 * 1024:
                counts['size_skipped'] += 1
                continue
            header = reader.header(stream, row['offset'], report['index_offset'])
            if not header or header['end'] != row['end']:
                raise ValueError('Fresh record mismatch')
            try:
                data = reader.decode(stream, header)
                if data is None or len(data) != row['uncompressed']:
                    raise ValueError('Decoded size mismatch')
            except (ValueError, OSError):
                counts['errors'] += 1
                continue
            counts['decoded'] += 1
            matches = []
            for key in markers:
                for encoding in ['ascii', 'utf-16le']:
                    offset = data.find(key.encode(encoding))
                    if offset >= 0:
                        matches.append(dict(key=key, encoding=encoding, decoded_offset=offset))
            if matches:
                hits.append(dict(entry=row['entry'], offset=row['offset'],
                                 decoded_sha256=hashlib.sha256(data).hexdigest(), matches=matches))
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError('Archive changed during public marker scan')
    return dict(source=report['source'], record_index=str(index_path), record_index_sha256=audit.sha256(index_path),
                dependencies=report['dependencies'], limit_bytes=16 * 1024 * 1024, markers=markers,
                counts=counts, hits=hits, full_config_search=False)


def replay(raw, image, fragments, prefix):
    ping, x = settings.ping, settings.ping.x
    uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
    scratch, stack, stop = 0x20000000, 0x20030000, 0x2003f000
    uc.mem_map(scratch, 0x40000)
    native_roots = {image.roots[image.containing(a)][0] for a in (FIND, COMPARE)}
    allowed = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
               for f in fragments if f['root_begin_rva'] in native_roots]
    allowed.append((0x14563f3e9, 0x14563f424))
    pages = {a & ~4095 for begin, end in allowed for a in range(begin, end + 4095, 4096)}
    for f in fragments:
        if f['root_begin_rva'] in native_roots:
            pages.update(a & ~4095 for i in f['instructions'] for a in i['rip_references'])
    pages.add(0x14b520cf0 & ~4095)
    for page in sorted(pages):
        uc.mem_map(page, 4096)
        try:
            off = image.offset(page - image.pe.base)
        except ValueError:
            continue
        uc.mem_write(page, raw[off:off + 4096])

    def hook(machine, address, size, user):
        if not any(begin <= address < end for begin, end in allowed):
            raise ValueError('Unreviewed selection execution ' + hex(address))

    uc.hook_add(ping.unicorn.UC_HOOK_CODE, hook)
    data = prefix.encode('utf-16le') + b'\0\0'
    if len(data) > 258 or '\0' in prefix:
        raise ValueError('Prefix fixture exceeds bound')
    uc.mem_write(scratch + 0x8000, data)
    uc.mem_write(scratch + 0x1000, struct.pack('<QII', scratch + 0x8000, len(data) // 2, len(data) // 2))
    uc.mem_write(scratch + 0x9000, 'real\0'.encode('utf-16le'))
    uc.mem_write(stack, struct.pack('<Q', stop))
    uc.mem_write(stack + 0x28, struct.pack('<ii', 0, -1))
    for register, value in [(x.UC_X86_REG_RCX, scratch + 0x1000), (x.UC_X86_REG_RDX, scratch + 0x9000),
                            (x.UC_X86_REG_R8, 4), (x.UC_X86_REG_R9, 1), (x.UC_X86_REG_RSP, stack)]:
        uc.reg_write(register, value)
    uc.emu_start(FIND, stop, count=4096)
    if uc.reg_read(x.UC_X86_REG_RIP) != stop:
        raise ValueError('Find budget exceeded')
    index = struct.unpack('<i', struct.pack('<I', uc.reg_read(x.UC_X86_REG_EAX)))[0]
    # Execute the real branch from Initialize, stopping before FString assignment.
    fixture_values = {'normal': 'https://normal.invalid/config', 'qa': 'https://qa.invalid/config'}
    pointers = {}
    for number, (name, global_address) in enumerate([('normal', 0x14b520cf0), ('qa', 0x14b520d00)]):
        text = fixture_values[name].encode('utf-16le') + b'\0\0'
        pointer = scratch + 0xa000 + number * 512
        pointers[name] = pointer
        uc.mem_write(pointer, text)
        uc.mem_write(global_address, struct.pack('<QII', pointer, len(text) // 2, len(text) // 2))
    for register, value in [(x.UC_X86_REG_RBX, index & 0xffffffff), (x.UC_X86_REG_RDI, 0xffffffffffffffff),
                            (x.UC_X86_REG_R12, 0), (x.UC_X86_REG_RSP, stack)]:
        uc.reg_write(register, value)
    uc.emu_start(0x14563f3e9, 0x14563f424, count=64)
    if uc.reg_read(x.UC_X86_REG_RIP) != 0x14563f424:
        raise ValueError('Selection budget exceeded')
    pointer = uc.reg_read(x.UC_X86_REG_RDX)
    name = next((name for name, address in pointers.items() if address == pointer), None)
    if name is None:
        raise ValueError('Unknown selected base fixture')
    return dict(prefix=prefix, find_index_utf16=index, selected=name, selected_fixture=fixture_values[name],
                selected_length=uc.reg_read(x.UC_X86_REG_R8), actual_configuration_proven=False)


def build():
    prior_path = settings.config.native.ROOT / 'code-clues/headless-cdn-config.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = settings.config.native.Image(raw)
    roots = {image.roots[image.containing(a)] for a in [FIND, COMPARE, 0x14563f080, 0x14152ca00,
             0x1445bc080, 0x1445bb3a0]}
    fragments = settings.config.native.decode_ranges(image, roots)
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    if rows[0x14563f3d3]['direct_target'] != FIND or rows[0x1445bc0ad]['rip_references'] != [0x14b2743f8]:
        raise ValueError('Config caller anchor changed')
    literals = []
    for row in rows.values():
        for address in row['rip_references']:
            literal = settings.config.read_literal(raw, image, address)
            if literal:
                literals.append(dict(instruction=row['address'], **literal))
    table_address = rows[0x1414599c0]['rip_references'][0]
    offset = image.offset(table_address - image.pe.base)
    data = raw[offset:offset + 128]
    table = dict(address=table_address, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest())
    prefixes = ['', 'dev', 'real', 'REAL', 'unreal', 'pre_real_post', 'real ', ' real',
                'reál', 'réal', 'reаl', 'rеal', '😀real', 'REALdev', 'devREAL', 'r e a l']
    cases = [replay(raw, image, fragments, prefix) for prefix in prefixes]
    for case in cases:
        folded = case['prefix'].translate(str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'))
        index = folded.find('REAL')
        expected_index = len(folded[:index].encode('utf-16le')) // 2 if index >= 0 else -1
        if case['find_index_utf16'] != expected_index or case['selected'] != ('normal' if index >= 0 else 'qa'):
            raise ValueError('Native prefix selection differs')
    index_path = settings.config.native.ROOT / ('release-snapshots/'
            '0f179fdafc09adab377e40314fd7409428b5961dc846ac300f8f1bb6b3111114/record-indexes/'
            '84eae2ecc71bfcc28f6d2c4d6647d414eda95e15d0fa187f391cf92923463ce8/'
            '8bf5db1a115f85b4eb7fbd2027620f459433b59450cdc62e06073ed0a2a9834e/manifest.json')
    public_scan = scan_public_records(index_path)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                cdn_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, literals=literals, data_anchors=[table], cases=cases, public_scan=public_scan,
                network_ready=False, active_settings_proven=False,
                limitations=['Actual forward ignore-ASCII-case Find and base selection executed, explicit synthetic URLs.',
                    'Other Find modes and full URL builder not executed; no real configuration or addresses acquired.',
                    'Logical Game config name initialization is static; platform hierarchy/overrides/file paths unproven.',
                    'Post-load map registration is static, not a complete parameter-update lifecycle replay.',
                    'Public archive scan excludes encrypted/large records and gaps; absence of markers is scoped only.',
                    'No profile files, accounts, game processes or network used.'])


if __name__ == '__main__':
    report = build()
    target = settings.config.native.ROOT / 'code-clues/headless-cdn-selection.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases'])), indent=2))
