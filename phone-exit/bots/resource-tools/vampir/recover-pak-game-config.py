"""Recover hash-verified PAK directory/Game config using the compiled key callback.

No game process/account files/network. Output is a separate immutable snapshot.
Only two named public Game INI layers are extracted; key bytes are never saved.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
KEY_CALLBACK = 0x1468e62d0
EXE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
ARCHIVE_SHA256 = '7c1efc7b799dd27d2580b4eed279755e60a92a6ce8ace1e9863038137122d179'
GAME_FILES = ('ProjectRED/Config/DefaultGame.ini', 'ProjectRED/Config/Windows/WindowsGame.ini')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def ecb(data, key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if not data or len(data) % 16 or len(data) > 4 * 1024 * 1024:
        raise ValueError('Encrypted PAK buffer exceeds supported bounds')
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(data) + decryptor.finalize()


class Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        if not 0 <= count <= len(self.data) - self.pos:
            raise ValueError('PAK index field exceeds buffer')
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def number(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self):
        count = self.number('<i')
        if not 0 < abs(count) <= 4096:
            raise ValueError('PAK FString exceeds supported bounds')
        unit = 2 if count < 0 else 1
        data = self.take(abs(count) * unit)
        if not data.endswith(bytes(unit)):
            raise ValueError('PAK FString lacks terminator')
        text = data[:-unit].decode('utf-16le' if count < 0 else 'utf-8', 'strict')
        if '\0' in text:
            raise ValueError('NUL inside PAK path')
        return text


def parse_main(data):
    c = Cursor(data)
    mount, entries, seed = c.string(), c.number('<I'), c.number('<Q')
    if not 0 < entries <= 100000:
        raise ValueError('PAK entry count exceeds budget')
    indexes = {}
    for name in ('path_hash', 'full_directory'):
        if c.number('<I') != 1:
            raise ValueError('Required PAK side index missing')
        indexes[name] = dict(offset=c.number('<Q'), size=c.number('<Q'), sha1=c.take(20).hex())
    size = c.number('<I')
    if size > 4 * 1024 * 1024:
        raise ValueError('Encoded entry table exceeds budget')
    encoded_offset = c.pos
    encoded = c.take(size)
    if c.number('<I') != 0 or len(data) - c.pos > 15:
        raise ValueError('Unsupported non-encoded entries or main-index trailer')
    return dict(mount=mount, entry_count=entries, path_hash_seed=seed, side_indexes=indexes,
                encoded_table_offset=encoded_offset, encoded_table_size=size, trailing_bytes=len(data) - c.pos), encoded


def parse_directory(data, expected_count):
    c = Cursor(data)
    count = c.number('<I')
    if count > 10000:
        raise ValueError('PAK directory count exceeds budget')
    rows, seen = [], set()
    for _ in range(count):
        directory = c.string()
        files = c.number('<I')
        if files > expected_count or len(rows) + files > expected_count:
            raise ValueError('PAK directory file count inconsistent')
        for _ in range(files):
            name, offset = c.string(), c.number('<i')
            path = directory + name
            if path in seen or offset < 0:
                raise ValueError('Duplicate or unsupported directory entry')
            seen.add(path)
            rows.append(dict(path=path, encoded_entry_offset=offset))
    if len(rows) != expected_count or len(data) - c.pos > 15:
        raise ValueError('PAK directory count/trailer mismatch')
    return dict(directory_count=count, file_count=len(rows), trailing_bytes=len(data) - c.pos, entries=rows)


def decode_small_entry(encoded, offset):
    c = Cursor(encoded)
    c.pos = offset
    bits = c.number('<I')
    method, blocks = (bits >> 23) & 63, (bits >> 6) & 65535
    encrypted = bool(bits & (1 << 22))
    if method not in (0, 1) or blocks > 1 or bits & 63:
        raise ValueError('Config entry uses unsupported encoded block layout')
    position = c.number('<I' if bits & (1 << 31) else '<Q')
    usize = c.number('<I' if bits & (1 << 30) else '<Q')
    size = c.number('<I' if bits & (1 << 29) else '<Q') if method else usize
    raw_block_size = c.number('<I') if method and encrypted else size
    if not 0 < usize <= 1024 * 1024 or not 0 < size <= 1024 * 1024:
        raise ValueError('Config payload exceeds budget')
    return dict(offset=position, size=size, usize=usize, method=method, encrypted=encrypted,
                blocks=blocks, raw_block_size=raw_block_size, encoded_bits=bits)


def recover_key(raw, image, native, preparation):
    fragments = native.decode_ranges(image, {image.roots[image.containing(KEY_CALLBACK)]})
    class KeyEmulator(preparation.PreparationEmulator):
        def __init__(self):
            super().__init__(raw, image, fragments)
            extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva']) for f in fragments]
            self.allowed.extend(extra)
            pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
            for f in fragments:
                for r in f['instructions']:
                    pages.update(a & ~4095 for a in r['rip_references'])
            regions = list(self.uc.mem_regions())
            for page in sorted(pages):
                if any(lo <= page <= hi for lo, hi, _ in regions):
                    continue
                self.uc.mem_map(page, 4096)
                try:
                    off = image.offset(page - image.pe.base)
                except ValueError:
                    continue
                self.uc.mem_write(page, raw[off:off + 4096])
    cases, outputs = [], []
    for delta, poison in ((0, 0), (1, 0x55), (15, 0xaa), (16, 0xff)):
        emu = KeyEmulator()
        destination = emu.scratch + 0x1000 + delta
        emu.uc.mem_write(destination - 8, bytes([poison]) * 48)
        emu.run(KEY_CALLBACK, rcx=destination)
        around = bytes(emu.uc.mem_read(destination - 8, 48))
        if around[:8] != bytes([poison]) * 8 or around[40:] != bytes([poison]) * 8:
            raise ValueError('Key callback crossed output bounds')
        outputs.append(around[8:40])
        cases.append(dict(destination_delta=delta, poison=poison, output_bytes=32,
                          output_sha256=hashlib.sha256(outputs[-1]).hexdigest(), guards_unchanged=True))
    if len(set(outputs)) != 1:
        raise ValueError('Key callback output depends on fixture layout')
    return outputs[0], dict(fragments=fragments, cases=cases, separate_key_file_saved=False)


def read_verified_index(stream, info, key, limit):
    offset, size = info['offset'], info['size']
    if not 0 <= offset < offset + size <= limit or not 0 < size <= 4 * 1024 * 1024 or size % 16:
        raise ValueError('PAK index range exceeds verified archive')
    stream.seek(offset)
    encrypted = stream.read(size)
    data = ecb(encrypted, key)
    if hashlib.sha1(data).hexdigest() != info['sha1']:
        raise ValueError('Decrypted PAK index SHA1 mismatch')
    return data


def extract_config(stream, entry, encoded, key, reader, limit):
    decoded = decode_small_entry(encoded, entry['encoded_entry_offset'])
    h = reader.header(stream, decoded['offset'], limit)
    if not h or any(h[k] != decoded[k] for k in ('size', 'usize', 'method', 'encrypted')):
        raise ValueError('Directory entry/header disagreement')
    if len(h['blocks']) != decoded['blocks']:
        raise ValueError('Directory block count mismatch')
    ranges = h['blocks'] if h['method'] else [(h['hs'], h['hs'] + h['size'])]
    stored, pieces = [], []
    for a, b in ranges:
        raw_size = b - a
        if h['method'] and raw_size != decoded['raw_block_size']:
            raise ValueError('Directory compressed block size mismatch')
        count = (raw_size + 15) // 16 * 16 if h['encrypted'] else raw_size
        if not 0 < count <= 1024 * 1024 or h['pos'] + a + count > limit:
            raise ValueError('Config ciphertext exceeds archive bounds')
        stream.seek(h['pos'] + a)
        stored.append(stream.read(count))
    stream.seek(h['pos'] + 28)
    header_hash = stream.read(20).hex()
    combined = b''.join(stored)
    # Encrypted record hashes cover stored ciphertext up to FPakEntry.Size.
    if hashlib.sha1(combined[:h['size']]).hexdigest() != header_hash:
        raise ValueError('Stored config ciphertext SHA1 mismatch')
    for cipher, (a, b) in zip(stored, ranges):
        compressed = (ecb(cipher, key) if h['encrypted'] else cipher)[:b - a]
        if h['method']:
            count = min(h['blocksize'], h['usize'] - sum(map(len, pieces)))
            destination, source = ctypes.create_string_buffer(count + 64), ctypes.create_string_buffer(compressed)
            actual = reader.DECOMP(source, len(compressed), destination, count, 1, 0, 0, None, 0, None, None, None, 0, 3)
            if actual != count:
                raise ValueError('Verified config decompression size mismatch')
            compressed = destination.raw[:count]
        pieces.append(compressed)
    payload = b''.join(pieces)[:h['usize']]
    if len(payload) != h['usize']:
        raise ValueError('Config output size mismatch')
    text = payload.decode('utf-8-sig', 'strict')
    selected, section = [], ''
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.startswith('['):
            section = line
        elif section == '[NetworkSetting]' and '=' in line:
            name, value = line.split('=', 1)
            if name in ('CdnConfigUrl', 'CdnConfigUrlQA', 'AppVersion', 'ConfigPrefix', 'CdnConfig', 'CdnConfigEd'):
                selected.append(dict(section='NetworkSetting', key=name, value=value, line=line_number))
    return payload, dict(path=entry['path'], encoded_entry_offset=entry['encoded_entry_offset'],
                         decoded_entry=decoded, header_sha1=header_hash, hash_basis='stored_ciphertext',
                         payload_sha256=hashlib.sha256(payload).hexdigest(), payload_size=len(payload), values=selected)


def recover():
    flow = load('recovery_flow', HERE / 'build-headless-cdn-json-flow.py')
    native = flow.body.head.headers.uri.http.preparation.url.settings.config.native
    preparation = flow.body.head.headers.uri.http.preparation
    prior = json.loads((ROOT / 'code-clues/headless-cdn-json-flow.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXE_SHA256:
        raise ValueError('Unsupported compiled key source')
    image = native.Image(raw)
    key, key_report = recover_key(raw, image, native, preparation)
    probe = load('recovery_probe', HERE / 'probe-cdn-key-in-pak.py')
    index = json.loads(probe.INDEX.read_text('utf-8'))
    if sha256(probe.INDEX) != probe.INDEX.parent.name:
        raise ValueError('Reference release index changed')
    source = index['source']
    archive = Path(source['path'])
    before = archive.stat()
    if (sha256(archive) != ARCHIVE_SHA256 or source['sha256'] != ARCHIVE_SHA256
            or before.st_size != source['size'] or before.st_mtime_ns != source['modified_ns']):
        raise ValueError('Archive no longer matches supported release')
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    if sha256(reader_path) != index['dependencies']['reader_sha256']:
        raise ValueError('PAK header reader changed')
    dll = Path(os.environ.get('PHONEEXIT_RF_RESOURCES', 'F:/PhoneExit Resources/RF Online Next')) / 'tools/oodle-data-shared.dll'
    if sha256(dll) != index['dependencies']['oodle_sha256']:
        raise ValueError('Oodle dependency changed')
    reader = load('recovery_reader', reader_path)
    with archive.open('rb') as stream:
        stream.seek(-512, 2)
        tail = stream.read()
        marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        if (marker < 17 or tail[marker - 17:marker - 1] != bytes(16) or tail[marker - 1] != 1
                or struct.unpack_from('<i', tail, marker + 4)[0] != 11):
            raise ValueError('Unsupported encrypted PAK footer')
        offset, size = struct.unpack_from('<QQ', tail, marker + 8)
        footer_start = before.st_size - 512 + marker - 17
        main_info = dict(offset=offset, size=size, sha1=tail[marker + 24:marker + 44].hex())
        main = read_verified_index(stream, main_info, key, footer_start)
        main_meta, encoded = parse_main(main)
        directory_info = main_meta['side_indexes']['full_directory']
        directory_raw = read_verified_index(stream, directory_info, key, footer_start)
        directory = parse_directory(directory_raw, main_meta['entry_count'])
        by_name = {entry['path']: entry for entry in directory['entries']}
        files, configs = {}, []
        for name in GAME_FILES:
            payload, info = extract_config(stream, by_name[name], encoded, key, reader, offset)
            label = 'DefaultGame.ini' if name.endswith('/DefaultGame.ini') else 'WindowsGame.ini'
            files[label] = payload
            configs.append({**info, 'snapshot_file': label})
    after = archive.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('Archive changed during recovery')
    graph = native.decode_ranges(image, {image.roots[image.containing(a)] for a in
        (0x141553580, 0x14155fd00, 0x142518910, 0x144a97f60, 0x144a8ed10)})
    init_off = image.offset(0x141291600 - image.pe.base)
    report = dict(schema_version=1, source_exe=prior['source'], exe_sha256=EXE_SHA256,
                  source_archive=source, archive_sha256=ARCHIVE_SHA256,
                  reference_record_index_sha256=probe.INDEX.parent.name,
                  tool_sha256=sha256(Path(__file__)), key_callback=key_report, registration_fragments=graph,
                  initializer=dict(address=0x141291600, file_offset=init_off, bytes=raw[init_off:init_off + 12].hex()),
                  main_index=main_info, main_metadata=main_meta, directory_index=directory_info,
                  directory_sha256=hashlib.sha256(directory_raw).hexdigest(), configs=configs,
                  dependencies=index['dependencies'], authoritative_directory_for_archive=True,
                  path_hash_side_index_verified=False,
                  active_runtime_settings_verified=False, network_ready=False)
    files['directory.json'] = (json.dumps(directory, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    report['directory_paths_file_sha256'] = hashlib.sha256(files['directory.json']).hexdigest()
    return report, files


def save(report, files):
    if set(files) - {'DefaultGame.ini', 'WindowsGame.ini', 'directory.json'}:
        raise ValueError('Unsupported snapshot output filename')
    manifest = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    identity = hashlib.sha256(manifest).hexdigest()
    folder = ROOT / 'resource-config-snapshots' / identity
    folder.mkdir(parents=True, exist_ok=True)
    for name, payload in {**files, 'manifest.json': manifest}.items():
        path = folder / name
        try:
            with path.open('xb') as stream:
                stream.write(payload)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise ValueError('Existing immutable config snapshot differs') from None
    return folder / 'manifest.json', identity


if __name__ == '__main__':
    report, files = recover()
    manifest, identity = save(report, files)
    pointer = dict(manifest=str(manifest), sha256=identity,
                          directory_files=report['main_metadata']['entry_count'],
                          config_files=len(report['configs']), active_runtime_settings_verified=False)
    (ROOT / 'code-clues/pak-config-recovery.json').write_text(json.dumps(pointer, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(pointer, indent=2))
