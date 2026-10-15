"""Read-only bounded string references in the installed shipping executable.

These are compiled-client clues, not recovered implementation or live state.
"""
import hashlib
import json
import mmap
import os
import re
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
INSTALL = Path(os.environ.get('PHONEEXIT_VAMPIR_INSTALL', 'C:/Program Files/Netmarble/Netmarble Game/VAMPIR'))


def main():
    source = INSTALL / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
    dest = ROOT / 'code-clues'
    dest.mkdir(exist_ok=True)
    hits = []
    interesting = re.compile(r'(?<!re)(?<!con)quest|tutorial|ContentsLock|RdData|\.py\b|\.cpp\b', re.I)
    with source.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        digest = hashlib.sha256(data).hexdigest()
        for encoding, pattern in [('ascii', rb'[\x20-\x7e]{6,}'), ('utf-16le', rb'(?:[\x20-\x7e]\x00){6,}')]:
            for match in re.finditer(pattern, data):
                # Avoid enormous accidental strings and embedded tables.
                if len(match.group()) > 4096:
                    continue
                text = match.group().decode(encoding)
                if interesting.search(text) or any(a <= match.start() < b for a, b in
                        [(161100500, 161119500), (161253000, 161259000), (163966000, 163966900)]):
                    hits.append(dict(offset=match.start(), encoding=encoding, text=text))
    report = dict(source=str(source), size=source.stat().st_size, sha256=digest,
                  interpretation='Static compiled strings only; no functions decompiled, no runtime state read', hits=hits)
    (dest / 'shipping-strings.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    focused = [h for h in hits if re.search(r'(?<!re)(?<!con)quest|tutorial', h['text'], re.I)]
    print(json.dumps(dict(total=len(hits), quest_tutorial=len(focused), report=str(dest / 'shipping-strings.json')), ensure_ascii=False))


if __name__ == '__main__':
    main()
