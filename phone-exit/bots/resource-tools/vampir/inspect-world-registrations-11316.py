"""Explicit current NPC/sight constructor E8 owners and nearby registration evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
TARGETS={0x1456c01c0:'PktNpcCreateNotify',0x1456c0360:'PktSightLeaveNotify'}
ANCHORS={
    0x1467b6087:'488d05aa006103',0x1467b608e:'488907',0x1467b60a8:'e8b3a2f0fe',
    0x1467b60b2:'4c8bc7',0x1467b60b5:'488bd0',0x1467b60b8:'488bce',0x1467b60bb:'e800560100',
    0x1467b65cd:'488d05bcfa6003',0x1467b65d4:'488907',0x1467b65ee:'e8cd9bf0fe',
    0x1467b65f8:'4c8bc7',0x1467b65fb:'488bd0',0x1467b65fe:'488bce',0x1467b6601:'e8ba500100'}
FIELD_ANCHORS={
    0x145d7433a:'488b4210',0x145d7433e:'488bf9',0x145d74341:'48894108',0x145d74345:'488bda',
    0x145d74348:'8b4218',0x145d7434b:'894110',0x145d7434e:'0f104220',0x145d74352:'0f114120',
    0x145d74356:'f20f104a30',0x145d7435b:'f20f114930',
    0x145d74392:'4c8b4360',0x145d74396:'ba04000000',0x145d7439b:'488bcf',0x145d7439e:'e84dcd87ff',
    0x145d743a3:'4c8b4368',0x145d743a7:'ba05000000',0x145d743ac:'488bcf',0x145d743af:'e83ccd87ff'}


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    native,scan=load('build-native-entry-code'),load('build-entry-window-code')
    path=native.ROOT/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('World registration source differs')
    if native.capstone.__version__!='5.0.6':raise ValueError('Pinned Capstone required')
    image=native.Image(raw);candidates=[]
    for section in image.pe.sections:
        if section['name']=='.text':
            candidates.extend(scan.direct_call_candidates(raw,section['raw'],section['raw_size'],image.pe.address,set(TARGETS)))
    owners={image.roots[f] for at,_ in candidates if (f:=image.containing(at)) is not None}
    if not 1<=len(owners)<=8:raise ValueError('Explicit constructor owner budget differs')
    fragments=native.decode_ranges(image,owners)
    rows={row['address']:row for fragment in fragments for row in fragment['instructions']}
    if any(rows.get(at,{}).get('bytes')!=value for at,value in ANCHORS.items()):raise ValueError('World registration anchors differ')
    for at in (0x1467b60bb,0x1467b6601):
        if not scan.checked_call(rows[at],0x1467cb6c0):raise ValueError('World dispatcher registration call differs')
    expected_tables={0x149dc6138:(0x1414096c0,0x14153b9d0,0x14679c710),0x149dc6090:(0x1414096c0,0x14153b9d0,0x14679b630)}
    for at,values in expected_tables.items():
        if struct.unpack_from('<3Q',raw,image.offset(at-image.pe.base))!=values:raise ValueError('World handler table differs')
    initializer=native.decode_ranges(image,{image.roots[image.containing(0x145d74330)]})
    field_rows={row['address']:row for fragment in initializer for row in fragment['instructions']}
    if any(field_rows.get(at,{}).get('bytes')!=value for at,value in FIELD_ANCHORS.items()):raise ValueError('NPC key/position/HP field anchors differ')
    for at in (0x145d7439e,0x145d743af):
        if not scan.checked_call(field_rows[at],0x1455f10f0):raise ValueError('NPC stat setter binding differs')
    checked=[]
    for at,target in candidates:
        row=rows.get(at)
        if not scan.checked_call(row,target):raise ValueError('Constructor candidate is not a checked E8 boundary')
        owner=image.roots[image.containing(at)]
        instructions=next(f['instructions'] for f in fragments if any(r['address']==at for r in f['instructions']))
        index=next(i for i,r in enumerate(instructions) if r['address']==at)
        context=instructions[max(0,index-24):index+12]
        tables=[]
        for instruction in context:
            if instruction['mnemonic']!='lea':continue
            for target_table in instruction['rip_references']:
                offset=image.offset(target_table-image.pe.base)
                values=struct.unpack_from('<3Q',raw,offset)
                tables.append(dict(address=hex(target_table),instruction=hex(instruction['address']),slots=[hex(v) for v in values]))
        checked.append(dict(packet=TARGETS[target],constructor=hex(target),call=hex(at),owner=hex(image.pe.base+owner[0]),
            context=context,tables=tables))
    report=dict(source_sha256=SHA,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        registration_anchors={hex(at):value for at,value in ANCHORS.items()},
        npc_field_anchors={hex(at):value for at,value in FIELD_ANCHORS.items()},initializer_fragments=initializer,
        calls=checked,fragments=fragments,network_used=False,
        limits=['Only checked E8 constructor references and their bounded owner roots; no indirect-call absence claim.',
            'Fourteen anchors pair constructor, handler table and dispatcher arguments on allocation-success paths; actor behavior is separate.'])
    result=load('audit-client-release').save_snapshot(native.ROOT/'code-clues/world-registrations-11316',report)
    return result,checked


if __name__=='__main__':
    path,rows=run()
    print(json.dumps(dict(report=str(path),calls=[{k:v for k,v in row.items() if k!='context'} for row in rows])))
