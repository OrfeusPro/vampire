"""Read-only VAMPIR PAK inventory and bounded unencrypted record extraction.

Uses the existing version-11 RF archive reader and its pinned local Oodle DLL.
No encrypted records or index are decrypted. Large outputs stay outside Git.
"""
import hashlib
import importlib.util
import json
import os
import struct
import time
from pathlib import Path

SOURCE = Path(os.environ.get('PHONEEXIT_VAMPIR_INSTALL', 'C:/Program Files/Netmarble/Netmarble Game/VAMPIR'))
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
HERE = Path(__file__).resolve().parent


def inventory():
    rows = []
    for path in sorted(SOURCE.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in ('.pak', '.utoc', '.ucas'):
            continue
        stat = path.stat()
        with path.open('rb') as stream:
            head = stream.read(65536)
            stream.seek(max(0, stat.st_size - 65536))
            tail = stream.read()
        offset = tail.rfind(struct.pack('<I', 0x5a6f12e1))
        version = struct.unpack_from('<i', tail, offset + 4)[0] if 0 <= offset <= len(tail) - 8 else None
        rows.append(dict(path=str(path), size=stat.st_size, modified_ns=stat.st_mtime_ns,
                         sample_sha256=hashlib.sha256(head + tail).hexdigest(), pak_version=version))
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / 'pc-pak-inventory.json').write_text(json.dumps(dict(source=str(SOURCE), files=rows), indent=2), encoding='utf-8')
    return rows


def main():
    rows = inventory()
    archives = [r for r in rows if r['pak_version'] == 11]
    archives.sort(key=lambda r: (not Path(r['path']).name.startswith(('ProjectRED-', 'pakchunk0-')), r['size']))
    spec = importlib.util.spec_from_file_location('vampir_pak_reader', HERE.parent / 'rfnext' / 'scan-pak.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    progress = []
    for i, record in enumerate(archives):
        path = Path(record['path'])
        folder = ROOT / 'pak-extracted' / path.stem
        stamp = folder / 'source.json'
        metadata = folder / 'entries.json'
        started = time.monotonic()
        try:
            unchanged = stamp.exists() and metadata.exists() and json.loads(stamp.read_text('utf-8')) == record
            if unchanged:
                entries = json.loads(metadata.read_text('utf-8'))
            else:
                entries = reader.scan(path, folder)
                stamp.write_text(json.dumps(record, indent=2), encoding='utf-8')
            candidates = sorted({p for row in entries for p in row.get('paths', [])
                                 if p.startswith('/Game/') and any(k in p.lower() for k in ('worldmap', 'minimap', 'world_map', '/map/', '/maps/', 'datatable'))})
            item = dict(source=record, folder=str(folder), entries=len(entries) - 1,
                        encrypted_records=sum(bool(r.get('encrypted')) for r in entries),
                        scan=entries[-1], candidates=candidates, seconds=round(time.monotonic() - started, 2))
        except Exception as error:
            item = dict(source=record, error=type(error).__name__)
        progress.append(item)
        pending = ROOT / 'pak-scan-progress.json.tmp'
        pending.write_text(json.dumps(progress, ensure_ascii=False, indent=2), encoding='utf-8')
        pending.replace(ROOT / 'pak-scan-progress.json')
        print('Progress', i + 1, '/', len(archives), path.name, 'candidates', len(item.get('candidates', [])), item.get('error', ''), flush=True)
    print('Finished', len(progress), 'archives', flush=True)


if __name__ == '__main__':
    main()
