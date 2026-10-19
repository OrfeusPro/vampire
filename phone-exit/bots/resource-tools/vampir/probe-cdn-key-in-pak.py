"""Trial one compiled CDN-derived key against pinned uncompressed PAK records.

Not a PAK key discovery claim. No native decompressor is called with trial
plaintext; only SHA1-matching records could establish the candidate for a record.
No plaintext is saved, even on a match. Old indexes/caches are never changed.
"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')
INDEX = ROOT / ('release-snapshots/0f179fdafc09adab377e40314fd7409428b5961dc846ac300f8f1bb6b3111114/'
                'record-indexes/84eae2ecc71bfcc28f6d2c4d6647d414eda95e15d0fa187f391cf92923463ce8/'
                '8bf5db1a115f85b4eb7fbd2027620f459433b59450cdc62e06073ed0a2a9834e/manifest.json')
ARCHIVE_SHA256 = '7c1efc7b799dd27d2580b4eed279755e60a92a6ce8ace1e9863038137122d179'
FALLBACK_SHA256 = 'bc9e14df56bd151c96cfa00e833f92312ab7dcaa99d213a4cd593231294f091e'


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def probe_record(stream, row, limit, key):
    start, end = row['offset'], row['end']
    if not 0 <= start < end <= limit or end - start > 1024 * 1024:
        raise ValueError('PAK record exceeds pinned bounds')
    stream.seek(start)
    raw = stream.read(end - start)
    if len(raw) != end - start or hashlib.sha256(raw).hexdigest() != row['stored_record_sha256']:
        raise ValueError('PAK record no longer matches fresh index')
    if len(raw) < 53:
        raise ValueError('Truncated PAK record header')
    offset, size, usize, method = struct.unpack_from('<qqqI', raw)
    encrypted = raw[48]
    if (offset != 0 or method != 0 or method != row['method'] or size != usize or size != row['bytes']
            or usize != row['uncompressed'] or encrypted not in (0, 1) or bool(encrypted) != row['encrypted']):
        raise ValueError('Unsupported or inconsistent uncompressed PAK record')
    stored_size = ((size + 15) // 16) * 16 if encrypted else size
    if encrypted and 0 < size <= len(raw) - 53 < stored_size:
        return dict(entry=row['entry'], offset=start, encrypted=True, sha1_matches=None,
                    skipped='aligned_ciphertext_exceeds_record_index_bounds',
                    ciphertext_bytes_required=stored_size, indexed_payload_bytes=len(raw) - 53,
                    plaintext_saved=False)
    if not 0 < size <= stored_size <= len(raw) - 53:
        raise ValueError('PAK payload exceeds record bounds')
    stored = raw[53:53 + stored_size]
    if encrypted:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        decoded = (decryptor.update(stored) + decryptor.finalize())[:size]
    else:
        decoded = stored
    return dict(entry=row['entry'], offset=start, record_sha256=hashlib.sha256(raw).hexdigest(),
                encrypted=bool(encrypted), payload_size=size, header_sha1=raw[28:48].hex(),
                candidate_plaintext_sha256=hashlib.sha256(decoded).hexdigest(),
                sha1_matches=hashlib.sha1(decoded).digest() == raw[28:48], plaintext_saved=False)


def probe_directory(stream, file_size, key):
    stream.seek(max(0, file_size - 512))
    tail = stream.read(512)
    marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
    if marker < 17 or marker + 44 > len(tail):
        raise ValueError('Unsupported PAK footer')
    version, offset, size = struct.unpack_from('<iqq', tail, marker + 4)
    if (version != 11 or tail[marker - 1] != 1 or not 0 < size <= 2 * 1024 * 1024
            or size % 16 or not 0 <= offset < offset + size <= file_size - len(tail) + marker - 17):
        raise ValueError('Encrypted PAK directory exceeds supported bounds')
    expected = tail[marker + 24:marker + 44]
    stream.seek(offset)
    stored = stream.read(size)
    if len(stored) != size:
        raise ValueError('Truncated PAK directory')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    decoded = decryptor.update(stored) + decryptor.finalize()
    return dict(offset=offset, size=size, footer_sha1=expected.hex(),
                footer_prefix_bytes=tail[marker - 17:marker + 44].hex(),
                ciphertext_sha256=hashlib.sha256(stored).hexdigest(),
                ciphertext_sha1_matches=hashlib.sha1(stored).digest() == expected,
                candidate_plaintext_sha256=hashlib.sha256(decoded).hexdigest(),
                matching_plaintext_trims=[n for n in range(16)
                    if hashlib.sha1(decoded[:-n] if n else decoded).digest() == expected],
                directory_parsed=False, plaintext_saved=False)


def build():
    index_bytes = INDEX.read_bytes()
    if hashlib.sha256(index_bytes).hexdigest() != INDEX.parent.name:
        raise ValueError('Fresh index SHA256 mismatch')
    index = json.loads(index_bytes)
    source = index['source']
    archive = Path(source['path'])
    stamp = archive.stat()
    if (source['sha256'] != ARCHIVE_SHA256 or stamp.st_size != source['size']
            or stamp.st_mtime_ns != source['modified_ns'] or file_hash(archive) != ARCHIVE_SHA256):
        raise ValueError('Current archive no longer matches pinned release')
    fallback_path = ROOT / 'code-clues/headless-cdn-fallback.json'
    if file_hash(fallback_path) != FALLBACK_SHA256:
        raise ValueError('CDN key evidence report changed')
    fallback = json.loads(fallback_path.read_text('utf-8'))
    exe = Path(fallback['source'])
    if file_hash(exe) != fallback['sha256']:
        raise ValueError('Compiled key source changed')
    literal = fallback['seed_literal']
    with exe.open('rb') as stream:
        stream.seek(literal['file_offset'])
        seed_bytes = stream.read(len(bytes.fromhex(literal['bytes'])))
    if seed_bytes != bytes.fromhex(literal['bytes']) or hashlib.sha256(seed_bytes).hexdigest() != literal['sha256']:
        raise ValueError('Compiled CDN seed bytes changed')
    key = hashlib.sha256(seed_bytes[:-1]).digest()
    entries = index['entries']
    controls = [r for r in entries if not r['encrypted'] and r['method'] == 0 and 0 < r['bytes'] <= 65536][:8]
    candidates = [r for r in entries if r['encrypted'] and r['method'] == 0 and r['bytes'] <= 65536]
    with archive.open('rb') as stream:
        checked = [probe_record(stream, r, index['index_offset'], key) for r in controls]
        if not checked or not all(r['sha1_matches'] for r in checked):
            raise ValueError('Uncompressed PAK hash control failed')
        trials = [probe_record(stream, r, index['index_offset'], key) for r in candidates]
        directory_trial = probe_directory(stream, stamp.st_size, key)
    after = archive.stat()
    if (after.st_size, after.st_mtime_ns) != (stamp.st_size, stamp.st_mtime_ns):
        raise ValueError('Archive changed during key trial')
    return dict(schema_version=1, source=source, index=str(INDEX), index_sha256=INDEX.parent.name,
                fallback_report_sha256=file_hash(fallback_path), tool_sha256=file_hash(Path(__file__)),
                key_source_exe_sha256=fallback['sha256'], seed_literal=literal,
                candidate_key_sha256=hashlib.sha256(key).hexdigest(), controls=checked, trials=trials,
                directory_trial=directory_trial,
                encrypted_records_total=sum(bool(r['encrypted']) for r in entries),
                matches=sum(r['sha1_matches'] is True for r in trials), network_ready=False,
                limitations=['One CDN-derived candidate tested with AES256-ECB on bounded method-0 records and encrypted directory; directory is not parsed.',
                    'Compressed payloads/gaps and records with insufficient indexed ciphertext bounds remain untested.',
                    'SHA1 controls validate header semantics for checked uncompressed records, not all PAK variants.',
                    'Negative result does not establish a PAK key or absence of configuration.',
                    'No trial plaintext saved or passed to native decompression; no game process, account or network access.'])


if __name__ == '__main__':
    report = build()
    path = ROOT / 'code-clues/cdn-pak-key-probe.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=file_hash(path), controls=len(report['controls']),
                          trials=sum(r['sha1_matches'] is not None for r in report['trials']),
                          skipped=sum(r['sha1_matches'] is None for r in report['trials']),
                          matches=report['matches'], directory_matching_trims=report['directory_trial']['matching_plaintext_trims']), indent=2))
