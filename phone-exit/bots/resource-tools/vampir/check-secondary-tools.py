"""Bounded read-only compatibility check against installed Vampir data."""
import json
from pathlib import Path
import struct
import subprocess

from importlib.util import module_from_spec, spec_from_file_location

HERE = Path(__file__).resolve().parent
spec = spec_from_file_location('secondary_install', HERE / 'install-secondary-tools.py')
installer = module_from_spec(spec)
spec.loader.exec_module(installer)
ROOT = installer.ROOT


def main():
    tools = ROOT / 'tools'
    install = json.loads((tools / 'secondary-tools-install.json').read_text('utf-8'))
    for row in install['outputs']:
        if installer.digest(Path(row['path'])) != row['sha256']:
            raise ValueError('Changed installed tool: ' + row['path'])
    output = tools / 'cue4parse-probe'
    inventory = json.loads((ROOT / 'pc-pak-inventory.json').read_text('utf-8'))['files']
    paks = sorted((r for r in inventory if r['pak_version'] == 11), key=lambda r: r['size'])[:3]
    base = next(r for r in inventory if Path(r['path']).name == 'ProjectRED-Windows.pak')
    paks.append(base)
    results = []
    def probe(source, report):
        result = subprocess.run([str(tools / 'dotnet-10.0.402/dotnet.exe'),
            str(output / 'Cue4ParseProbe.dll'), str(source), 'GAME_UE5_5', str(report)],
            capture_output=True, text=True, timeout=60)
        if result.returncode not in (0, 2):
            raise RuntimeError(result.stderr)
        row = json.loads(report.read_text('utf-8'))
        if row['source_sha256'] != installer.digest(source):
            raise ValueError('Input changed during probe')
        return row
    for pak in paks:
        source = Path(pak['path'])
        row = probe(source, output / (source.stem + '-report.json'))
        # Keep blocked result explicit; a future game update may change it.
        results.append(dict(kind='archive', **row))
    extracted = ROOT / 'pak-extracted/ProjectRED-Windows'
    entries = json.loads((extracted / 'entries.json').read_text('utf-8'))
    saved = [r for r in entries if r.get('uasset') and r.get('saved')][:3]
    for entry in saved:
        source = Path(entry['saved'])
        row = probe(source, output / (source.stem + '-summary.json'))
        if row['error'] is not None:
            raise ValueError('Loose summary failed: ' + row['error'])
        data = source.read_bytes()
        # Existing inspect-ui.py package layout, independent of CUE4Parse.
        summary_offset = 36 + struct.unpack_from('<i', data, 32)[0]
        names, names_offset = struct.unpack_from('<ii', data, summary_offset + 4)
        exports, _, imports, _ = struct.unpack_from('<iiii', data, summary_offset + 28)
        h = row['summary']
        if (h['NameCount'], h['NameOffset'], h['ExportCount'], h['ImportCount']) != (names, names_offset, exports, imports):
            raise ValueError('Summary disagrees with existing package reader')
        if not 0 < h['consumed'] <= names_offset <= h['TotalHeaderSize'] == len(data):
            raise ValueError('Invalid package boundaries')
        results.append(dict(kind='loose_header', pak_source=base, entry=entry['entry'],
                            independent_header_match=True, **row))
    dll = Path(install['outputs'][-1]['path'])
    data = dll.read_bytes()
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[:2] != b'MZ' or data[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', data, pe+4)[0] != 0x8664 or not struct.unpack_from('<H', data, pe+22)[0] & 0x2000:
        raise ValueError('Dumper output is not x64 PE DLL')
    report = dict(install=install, results=results,
        dumper7=dict(build_verified=True, pe_x64_dll=True, injected=False, game_compatibility_verified=False),
        profile_basis='NPC-LOOT.md: source-bound EXE literal E:/Work/UE5/Release-5.5; not complete asset version detection',
        limits='No AES keys; no UObject property schemas; no game launch, injection, auth or network')
    path = tools / 'secondary-tools-check.json'
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(report=str(path), archives=len(paks), loose_headers=len(saved),
        archives_mounted=sum(r['count'] is not None for r in results if r['kind'] == 'archive'),
        dumper_x64=True), indent=2))


if __name__ == '__main__':
    main()
