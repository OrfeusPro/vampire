"""Index selected network symbols and verified LEA references; never contact the game."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('headless_native', HERE / 'build-native-entry-code.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

GROUPS = {
    'login': ['PktLobbyLogin', 'PktLobbyLoginResult', 'PktLogin', 'PktLoginResult',
              'PktCharacterListRead', 'PktCharacterListReadResult', 'PktCharacterSelect',
              'PktCharacterSelectResult'],
    'state': ['PktCharacterPosition', 'PktCharacterMove', 'PktCharacterMoveResult',
              'PktCharacterMoveNotify', 'PktWorldInfo', 'PktWorldInfoUpdateNotify'],
    'heartbeat': ['PktPing', 'PktPingResult'],
    'combat': ['PktSkillCastingStart', 'PktSkillCastingStartResult', 'PktSkillStart',
               'PktSkillStartResult', 'PktSkillStartNotify', 'PktActorCombatStateChangeNotify'],
    'dispatcher': ['PacketDispatcher::GetPacketHandler', 'PacketDispatcher::Dispatch',
                   'PacketDispatcher::_AddPacketHandler'],
    'auth': ['UTitleUI::OnSuccessNetmarbleSDKAuth()', 'UTitleUI::ProcessNetmarbleSDK()'],
}


def main():
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Use pinned Capstone 5.0.6')
    meta_path = native.ROOT / 'code-clues/native-enums.json'
    metadata = json.loads(meta_path.read_text('utf-8'))
    data = Path(metadata['source']).read_bytes()
    if hashlib.sha256(data).hexdigest() != metadata['sha256']:
        raise ValueError('Client changed: refresh source evidence first')
    image = native.Image(data)
    symbols, targets = [], {}
    for group, names in GROUPS.items():
        for name in names:
            encoding = 'utf-16le' if group == 'auth' else 'ascii'
            literal = (name + '\0').encode(encoding)
            for match in re.finditer(re.escape(literal), data):
                offset = match.start()
                prefix = b'\0\0' if encoding == 'utf-16le' else b'\0'
                if offset < len(prefix) or data[offset-len(prefix):offset] != prefix:
                    continue
                address = image.pe.address(offset)
                if address is None:
                    continue
                row = dict(group=group, name=name, encoding=encoding, file_offset=offset,
                           address=address, bytes=literal.hex(), sha256=hashlib.sha256(literal).hexdigest())
                symbols.append(row)
                targets[address] = row
    present = {s['name'] for s in symbols}
    missing = [name for names in GROUPS.values() for name in names if name not in present]
    candidates = native.rip_candidates(image, targets)
    roots = {image.roots[f] for address, _ in candidates if (f := image.containing(address)) is not None}
    fragments = native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    xrefs, rejected = [], []
    for address, target in candidates:
        instruction = rows.get(address)
        if instruction is None or instruction['mnemonic'] != 'lea' or target not in instruction['rip_references']:
            rejected.append(dict(address=address, target=target, reason='not a verified LEA boundary'))
            continue
        function = image.containing(address)
        xrefs.append(dict(symbol=targets[target]['name'], group=targets[target]['group'],
                          instruction=instruction, root_begin_rva=image.roots[function][0]))
    report = dict(schema_version=1, source=metadata['source'], sha256=metadata['sha256'],
                  metadata_sha256=hashlib.sha256(meta_path.read_bytes()).hexdigest(),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  image_base=image.pe.base, symbols=symbols, missing=missing,
                  xrefs=xrefs, rejected_candidates=rejected, fragments=fragments,
                  statistics=dict(symbols=len(symbols), xrefs=len(xrefs), roots=len(roots),
                                  fragments=len(fragments), instructions=len(rows)),
                  network_ready=False, limitations=[
                      'Selected exact literals and LEA references only; not a complete protocol index.',
                      'A symbol reference/root does not establish function purpose, packet ID or wire schema.',
                      'No transport, authentication request, encryption or live state reconstructed.',
                      'No game execution, network traffic, account access or process memory reading.'])
    output = native.ROOT / 'code-clues/headless-network-index.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), **report['statistics'], missing=missing,
                          rejected=len(rejected), network_ready=False)))


if __name__ == '__main__':
    main()
