"""Locate server selection guards from client diagnostics; no game or network."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('server_entry_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def build():
    manifest = json.loads((native.ROOT / 'ghidra/entry-manifest.json').read_text('utf-8'))
    raw = Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']:
        raise ValueError('Client changed')
    image = native.Image(raw)
    literals = []
    for text, encoding in (
            ('UServerSelectMyCharacterT::_BeginGame() - ServerId( %d )', 'utf-16le'),
            ('UServerSelectPopup::_InitServerList()', 'utf-16le'),
            ('COMMON_SERVER_WATING_FULL', 'utf-16le'),
            ('class FString __cdecl UNMPlayer::GetJoinedCountryCode(void) const', 'ascii'),
            ('void __cdecl UNMPlayer::SetJoinedCountryCode(const class FString &,bool)', 'ascii')):
        data = (text + '\0').encode(encoding)
        offset = raw.find(data)
        if offset < 0 or raw.find(data, offset + 1) >= 0:
            raise ValueError('Missing or ambiguous server selection literal')
        literals.append(dict(text=text, encoding=encoding, address=image.pe.address(offset), file_offset=offset,
                             bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    targets = {row['address'] for row in literals}
    candidates = native.rip_candidates(image, targets)
    roots = {image.roots[entry] for address, _ in candidates
             if (entry := image.containing(address)) is not None}
    fragments = native.decode_ranges(image, roots)
    references = [dict(root=hex(image.pe.base + f['root_begin_rva']), instruction=row,
                       target=hex(target))
                  for f in fragments for row in f['instructions']
                  for target in row['rip_references'] if target in targets]
    return dict(source=manifest['source'], source_sha256=manifest['source_sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                literals=literals, references=references, fragments=fragments,
                limitations=['Verified instruction-boundary RIP references to exact diagnostics.',
                             'Names identify research entry points, not availability semantics.',
                             'No game launch, process memory, credentials or network.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/server-entry-index.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         references=[dict(root=r['root'], target=r['target']) for r in report['references']])))
