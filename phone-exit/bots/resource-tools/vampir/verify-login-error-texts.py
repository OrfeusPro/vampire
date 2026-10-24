"""Join two source-verified numeric/name pairs to explicit current EN/RU CSVs."""
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

import importlib.util

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
SOURCE = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
DIRECTORY = 'd2691f91f8d88d15329639bc8457bced595cef0d5ee6b4bfff3b17e98c97f523'
VALUES = {16: 'InvalidState', 37: 'CreateRestrictedServer'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def select_text(rows, key):
    matches = [row for row in rows if row.get('Key') == key]
    if len(matches) != 1 or not matches[0].get('Value'):
        raise ValueError('Missing or ambiguous localized error key')
    return matches[0]['Value']


def verify(root=ROOT):
    names = load('message_numeric_names', HERE / 'inspect-release-result-names.py')
    pair_path, pairs = names.run(source_sha256=SOURCE, owner_address=0x1457d9210,
        values=VALUES, constructor=0x141426950)
    path = Path(root) / 'resource-config-snapshots' / DIRECTORY / 'manifest.json'
    if digest(path) != DIRECTORY:
        raise ValueError('Error directory manifest changed')
    manifest = json.loads(path.read_text('utf-8'))
    if manifest['exe_sha256'] != SOURCE or digest(manifest['source_exe']) != SOURCE:
        raise ValueError('Error table source changed')
    for name, field in (('directory.json', 'directory_paths_file_sha256'),
                        ('encoded-entries.bin', 'encoded_entries_file_sha256')):
        if digest(path.parent / name) != manifest[field]:
            raise ValueError('Error directory material changed')
    directory = json.loads((path.parent / 'directory.json').read_text('utf-8'))
    entries = {x['path']: x for x in directory['entries']}
    if len(entries) != len(directory['entries']):
        raise ValueError('Ambiguous error directory')
    encoded = (path.parent / 'encoded-entries.bin').read_bytes()
    reader_path = HERE.parent / 'rfnext/scan-pak.py'
    reader = load('message_error_reader', reader_path)
    if (digest(reader_path) != manifest['dependencies']['reader_sha256'] or
            digest(reader.ROOT / 'tools/oodle-data-shared.dll') != manifest['dependencies']['oodle_sha256']):
        raise ValueError('Error decoder dependency changed')
    archive = Path(manifest['source_archive']['path'])
    before = archive.stat()
    if digest(archive) != manifest['archive_sha256']:
        raise ValueError('Error archive changed')
    tables, sources = {}, []
    with archive.open('rb') as stream:
        for name in ('CSV/ResultCodeString.csv', 'CSV/L10N/en/ResultCodeString_Name.csv',
                     'CSV/L10N/ru/ResultCodeString_Name.csv'):
            at = entries[name]['encoded_entry_offset']
            if not 0 <= at <= len(encoded) - 4:
                raise ValueError('Error entry prefix outside directory')
            bits = struct.unpack_from('<I', encoded, at)[0]
            at += 4
            method, encrypted = (bits >> 23) & 63, bool(bits & (1 << 22))
            if method != 1 or encrypted:
                raise ValueError('Unsupported error table record')
            values = []
            for flag in (31, 30, 29):
                fmt = '<I' if bits & (1 << flag) else '<Q'
                if at + struct.calcsize(fmt) > len(encoded):
                    raise ValueError('Truncated error entry prefix')
                values.append(struct.unpack_from(fmt, encoded, at)[0])
                at += struct.calcsize(fmt)
            offset, usize, size = values
            header = reader.header(stream, offset, manifest['main_index']['offset'])
            if (not header or header['method'] != method or header['encrypted'] or
                    header['usize'] != usize or header['size'] != size or
                    len(header['blocks']) != ((bits >> 6) & 65535) or
                    not 0 < usize <= 1048576):
                raise ValueError('Error table prefix/header differs')
            data = reader.decode(stream, header)
            if data is None or len(data) != usize:
                raise ValueError('Incomplete error table')
            rows = list(csv.DictReader(io.StringIO(data.decode('utf-8-sig'))))
            tables[name] = rows
            sources.append(dict(path=name, offset=offset, bytes=usize,
                sha256=hashlib.sha256(data).hexdigest(), rows=len(rows)))
    after = archive.stat()
    if ((before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or digest(archive) != manifest['archive_sha256']):
        raise ValueError('Error archive changed during verification')
    for code in VALUES:
        if sum(row.get('Key') == str(code) for row in tables['CSV/ResultCodeString.csv']) != 1:
            raise ValueError('Numeric error row missing or ambiguous')
    return dict(schema=1, source_sha256=SOURCE, directory_sha256=DIRECTORY,
        archive_sha256=manifest['archive_sha256'], tool_sha256=digest(Path(__file__)),
        pair_report=str(pair_path), pair_report_sha256=pair_path.parent.name, tables=sources,
        errors=[dict(code=code, key=key,
            en=select_text(tables['CSV/L10N/en/ResultCodeString_Name.csv'], key),
            ru=select_text(tables['CSV/L10N/ru/ResultCodeString_Name.csv'], key)) for code, key in VALUES.items()],
        network_used=False, profile_activated=False,
        limits=['Static dictionary pointer pairs; map insertion/lookup and CSV loader not executed.',
                'Selected archive variant only; active language/mount and live popup unverified.',
                'Error text does not establish server-side cause of InvalidState or allow creation.'])


if __name__ == '__main__':
    report = verify()
    audit = load('message_error_save', HERE / 'audit-client-release.py')
    path = audit.save_snapshot(ROOT / 'knowledge/login-error-text-checks', report)
    print(json.dumps(dict(report=str(path), sha256=path.parent.name, errors=report['errors']), ensure_ascii=False))
