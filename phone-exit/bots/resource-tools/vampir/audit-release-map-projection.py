"""Verify current map-table reuse and reviewed native projection instructions."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def run():
    spec=importlib.util.spec_from_file_location('map_audit_native',HERE/'build-native-entry-code.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    spec=importlib.util.spec_from_file_location('map_audit_storage',HERE/'audit-client-release.py')
    audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
    root=native.ROOT
    snapshot=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if audit.sha256(snapshot)!=SHA:raise ValueError('Current EXE snapshot changed')
    image=native.Image(snapshot.read_bytes())
    comparison=root/'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c'
    export=comparison/'details/run-52ee72db9b11/details.json'
    if audit.sha256(export)!='64f727d1de960cb0f5712ac27d10b4d65975367776eba90b0288d3dfdfd37726':
        raise ValueError('Map Ghidra export changed')
    details=json.loads(export.read_text('utf-8'))
    rows={int(r['address'],16):r for f in details['functions'] for r in f['instructions']}
    anchors={0x145ac29b1:'MOVSS dword ptr [RBX + 0x20],XMM0',
        0x145ac2a15:'MOVSS dword ptr [RBX + 0x24],XMM0',0x145ac2a52:'MOVSS dword ptr [RBX + 0x28],XMM0',
        0x1464ee8d9:'MOVSD qword ptr [RBX + 0xb10],XMM0',0x1464ee8f3:'MOVSD qword ptr [RBX + 0xb18],XMM0',
        0x1464ee90d:'MOVSD qword ptr [RBX + 0xb00],XMM0',0x1464ee929:'MOVSD qword ptr [RBX + 0xb08],XMM0',
        0x1464ee9e3:'DIVSD XMM0,qword ptr [RBX + 0xb00]',0x1464ee9eb:'MOVSD qword ptr [RBX + 0xb20],XMM0',
        0x1464ee9f3:'DIVSD XMM6,qword ptr [RBX + 0xb08]',0x1464ee9fb:'MOVSD qword ptr [RBX + 0xb28],XMM6',
        0x1464fe4d7:'SUBSD XMM8,XMM6',0x1464fe4df:'SUBSD XMM9,XMM7',
        0x1464fe4eb:'MULSD XMM8,qword ptr [RAX + 0xb28]',0x1464fe4f4:'MULSD XMM9,qword ptr [RAX + 0xb20]'}
    for address,text in anchors.items():
        row=rows[address];off=image.offset(address-image.pe.base);data=bytes.fromhex(row['bytes'])
        if row['text']!=text or image.data[off:off+len(data)]!=data:raise ValueError('Projection instruction changed')
    literals=[]
    for address,target,text in ((0x145ac2993,0x1499df670,'GroundDistance'),
            (0x145ac29f7,0x1490ef920,'CenterX'),(0x145ac2a34,0x1490ef928,'CenterY')):
        off=image.offset(target-image.pe.base);data=text.encode()+b'\0'
        row=rows[address];raw=bytes.fromhex(row['bytes'])
        decoded=next(native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64).disasm(raw,address))
        if address+decoded.size+int.from_bytes(raw[-4:],'little',signed=True)!=target or image.data[off:off+len(data)]!=data:
            raise ValueError('Map field literal changed')
        literals.append(dict(address=hex(address),target=hex(target),text=text))
    table_manifest=root/'release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/record-indexes/a4dd6f81f00ad3c4c84b560ca008960315aa5a84655860a517c4d69c16e98896/65fc8722324efe5d0988c9d81420e89db5c309db2eb5de5d4552b16fe1022016/table-snapshots/54728d7a6bef3dfa8ea916b45f29fd1ec972e5e1a5ec1a25688b9a654ca1f7f2/manifest.json'
    if audit.sha256(table_manifest)!=table_manifest.parent.name:raise ValueError('Table manifest changed')
    tables=json.loads(table_manifest.read_text('utf-8'));archive=Path(tables['source']['path'])
    before=archive.stat()
    if audit.sha256(archive)!=tables['source']['sha256']:raise ValueError('Installed map-table archive changed')
    after=archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Archive changed during audit')
    atlas=root/'maps/atlas';index=json.loads((atlas/'index.json').read_text('utf-8'))
    projection=json.loads((atlas/'projection.json').read_text('utf-8'))
    if audit.sha256(atlas/'projection.json')!=index['pixel_projection']['sha256']:raise ValueError('Projection changed')
    data={};proof={}
    selected={'World':'c782ba8bd2c11a82382082da8a0e5487f4479d8605d795455cfc6e987f862c8c',
        'Map':'a17dcb5015fa7e1fca8b052bd59d6d65bd077fcf40901719c70bb06e0749b7b4'}
    for name in ('World','Map'):
        old=index['sources'][name];matches=[t for t in tables['tables'] if t['sha256']==selected[name]]
        if len(matches)!=1:raise ValueError('Reviewed current table is not unique')
        row=matches[0];path=Path(row['file'])
        if audit.sha256(path)!=selected[name]:raise ValueError('Map CSV bytes changed')
        data[name]=list(csv.DictReader(io.StringIO(path.read_text('utf-8-sig'))))
        old_path=root/'table-study'/old['file']
        if audit.sha256(old_path)!=old['sha256']:raise ValueError('Historical map table changed')
        previous=list(csv.DictReader(io.StringIO(old_path.read_text('utf-8-sig'))))
        old_by_id={r['Id']:r for r in previous};new_by_id={r['Id']:r for r in data[name]}
        if len(new_by_id)!=len(data[name]) or len(old_by_id)!=len(previous):raise ValueError('Nonunique map ID')
        required=old['header']
        changed={key:[column for column in required if row.get(column)!=new_by_id.get(key,{}).get(column)]
            for key,row in old_by_id.items()}
        proof[name]=dict(sha256=selected[name],entry=row['entry'],offset=row['offset'],rows=len(data[name]),
            added_ids=sorted(set(new_by_id)-set(old_by_id)),
            added_columns=[c for c in matches[0]['header'] if c not in required],
            changed_previous_fields={k:v for k,v in changed.items() if v})
    maps={r['Id']:r for r in data['Map']}
    for old in projection['map_records']:
        if maps[old['Id']]!={k:v for k,v in old.items() if k!='provenance'}:
            raise ValueError('Reviewed projection map record changed')
    historical_worlds={w['id']:w for w in index['worlds'] if w['map_id'] in projection['map_ids']}
    for world_id,old in historical_worlds.items():
        current=next((r for r in data['World'] if r['Id']==world_id),None)
        if current is None or (current['MapId'],current['LevelPath'])!=(old['map_id'],old['level_path']):
            raise ValueError('Mapped world identity fields changed')
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),
        native_evidence=dict(path=str(export),sha256=audit.sha256(export)),
        anchors=[rows[a] for a in anchors],literals=literals,
        table_manifest=dict(path=str(table_manifest),sha256=audit.sha256(table_manifest)),
        installed_archive=dict(path=str(archive),sha256=tables['source']['sha256']),tables=proof,
        atlas_projection_sha256=audit.sha256(atlas/'projection.json'),
        map_ids=projection['map_ids'],size=projection['size'],center=projection['center'],
        ground_distance=projection['ground_distance'],world_bounds=projection['world_bounds'],
        worlds={r['Id']:r['MapId'] for r in data['World'] if r['MapId'] in projection['map_ids']},
        limits=['Current static map math and exact table bytes checked; not whole native execution.',
            'Only Map10/11; resource texture freshness, runtime map selection, engine correction and walkability remain separate.',
            'No game IO, live coordinates or account identities.'])
    path=audit.save_snapshot(comparison/'map-projection-audit',report)
    return path,report


if __name__=='__main__':
    p,r=run();print(json.dumps(dict(report=str(p),sha256=p.parent.name,worlds=len(r['worlds']))))
