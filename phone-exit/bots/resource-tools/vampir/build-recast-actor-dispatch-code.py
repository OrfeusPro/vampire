"""Pin cooked navigation actor→native serializer and expose unresolved prefix.

No prefix byte is skipped as proven property data. Schema arrays are reflected
native descriptors, not the complete cooked inherited serialization schema.
"""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def read_binding(data,image,table,slot,expected):
    off=image.offset(table+slot-image.pe.base);raw=data[off:off+8]
    if len(raw)!=8 or struct.unpack('<Q',raw)[0]!=expected:raise ValueError('Changed actor serializer virtual slot')
    return dict(table=table,slot=slot,target=expected,file_offset=off,raw_hex=raw.hex())

def prefix_header(raw):
    reader=load('dispatch_prefix_reader','decode-canvas-slots.py').Reader(raw);fields=reader.header()
    if not fields or any(zero for _,zero in fields):raise ValueError('Unexpected actor prefix field mask')
    return dict(header_bytes=reader.pos,raw_hex=raw[:reader.pos].hex(),fields=[dict(index=i,zero=z) for i,z in fields],
        inherited_schema_resolved=False,property_values_decoded=False)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    native=load('actor_dispatch_native','build-native-entry-code.py');source=json.loads((root/'code-clues/native-enums.json').read_bytes())
    data=Path(source['source']).read_bytes();assert sha(data)==source['sha256'];image=native.Image(data)
    paths=['code-clues/navigation-filter-code.json','code-clues/recast-filter-selection-evidence.json',
        'maps/navigation-study/level/index.json','maps/navigation-study/level/nav-parameter-candidates.json']
    inputs={};reports={}
    for path in paths:
        raw=(root/path).read_bytes();inputs[path]=sha(raw);reports[path]=json.loads(raw)
    constructor=reports[paths[0]];selection=reports[paths[1]]
    assert constructor['sha256']==selection['sha256']==source['sha256']
    functions=[0x1454c54e0,0x1454d0020,0x145297f60,0x1452b91e0,0x1452b8ff0,0x14381b2b0,0x1452bc8b0,0x145266670,0x145293b20]
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in functions})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1454d002c,'call','0x145297f60'),(0x1454d0034,'lea','rax, [rip + 0x43a2efd]'),
        (0x1452b91f3,'call','0x141599f90'),(0x1452b91f8,'mov','rdx, rax'),
        (0x1452b91fe,'call','0x1452b8ff0'),(0x1452b9008,'call','0x14381b2b0'),
        (0x1452b901e,'mov','eax, dword ptr [rcx]'),(0x1452b9020,'mov','dword ptr [rdi + 0x768], eax'),
        (0x1452b902a,'add','qword ptr [rax], 4'),(0x1452b906d,'call','qword ptr [rax + 0x28]'),
        (0x1452b9084,'mov','ecx, dword ptr [rdx]'),(0x1452b908a,'add','qword ptr [rax], 4'),
        (0x1452b90c1,'cmp','r9d, 0x14'),(0x1452b90c7,'cmp','r9d, 0x1a'),
        (0x1452b9107,'call','0x1452bc8b0'),(0x1452b9148,'call','0x1452bc8b0'),
        (0x14381b312,'call','0x1417521e0')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed serializer chain anchor '+hex(address))
        anchors.append(row)
    tables=[rows[a]['rip_references'][0] for a in [0x1454d0034,0x145297f7a]]
    assert tables==[0x149872f38,0x14972dc00]
    assert {r['table'] for r in selection['base_initializer_vtables']}==set(tables)
    bindings=[read_binding(data,image,table,slot,target) for table in tables for slot,target in [(0xd8,0x1452b91e0),(0xe0,0x1452b8ff0)]]
    level=reports[paths[2]];candidates=reports[paths[3]];entry=candidates['source']
    assert entry in level['navigation_exports'] and entry['export']['type']=='NnRecastNavMesh'
    raw=(root/'maps/navigation-study/level'/entry['file']).read_bytes();assert sha(raw)==entry['export']['sha256']
    prefix=prefix_header(raw);candidate=candidates['candidates'][0];offset=candidate['offset']
    suffix=raw[offset:];assert struct.unpack_from('<iIi',suffix)==(26,104,0) and offset+108==len(raw)
    # Store native descriptor arrays with exact names/flags/bytes. Only a known
    # bounded table span, not an inferred entire inherited serialization schema.
    schemas=[]
    for name,table,count,registry,getter,label_instruction in [('NavigationData',0x149720b20,14,0x149720bc0,0x145266670,0x1452666b6),
        ('RecastNavMesh',0x14972b230,76,0x14972b4c0,0x145293b20,0x145293b66)]:
        ro=image.offset(registry-image.pe.base);registry_raw=data[ro:ro+56]
        if struct.unpack_from('<Q',registry_raw)[0]!=getter or struct.unpack_from('<Q',registry_raw,40)[0]!=table:raise ValueError('Changed native class property registry')
        label_row=rows[label_instruction];label_offset=image.offset(label_row['rip_references'][0]-image.pe.base);label=(name+'\0').encode('utf-16le')
        if data[label_offset:label_offset+len(label)]!=label:raise ValueError('Changed class getter name')
        anchors.append(label_row)
        entries=[]
        for index in range(count):
            po=image.offset(table+index*8-image.pe.base);ptr=struct.unpack_from('<Q',data,po)[0];off=image.offset(ptr-image.pe.base)
            desc=data[off:off+56];name_ptr=struct.unpack_from('<Q',desc)[0];no=image.offset(name_ptr-image.pe.base)
            end=data.index(b'\0',no,no+160);field=data[no:end].decode('ascii')
            if not field or not field.replace('_','').isalnum():raise ValueError('Unexpected descriptor table bound')
            entries.append(dict(index=index,name=field,descriptor=ptr,file_offset=off,raw_hex=desc.hex(),
                pointer_file_offset=po,pointer_raw_hex=data[po:po+8].hex(),name_file_offset=no,
                gen_flags=struct.unpack_from('<I',desc,24)[0],object_offset_raw=struct.unpack_from('<I',desc,50)[0]))
        schemas.append(dict(class_label=name,table=table,entries=entries,cooked_inherited_order_verified=False,
            class_registry=dict(address=registry,file_offset=ro,raw_hex=registry_raw.hex(),class_getter=getter),
            class_literal=dict(instruction=label_instruction,file_offset=label_offset,raw_hex=label.hex(),text=name)))
    report=dict(source=source['source'],sha256=source['sha256'],input_reports=inputs,fragments=fragments,anchors=anchors,
        virtual_bindings=bindings,native_descriptor_arrays=schemas,actor_export=entry,prefix_header=prefix,
        unresolved_prefix=dict(begin=prefix['header_bytes'],end=offset,raw_hex=raw[prefix['header_bytes']:offset].hex(),
            bytes=offset-prefix['header_bytes'],candidate_end_only=True),
        suffix=dict(offset=offset,raw_hex=suffix.hex(),version=26,length=104,tile_count=0),
        summary=dict(shared_serializer_dispatch_verified=True,native_descriptor_entries=sum(len(s['entries']) for s in schemas),
            prefix_fields=len(prefix['fields']),prefix_values_decoded=False,parameter_boundary_verified=False,
            runtime_parameter_selection_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Cooked type identity and constructor vtables pin the shared serializer. Neither the superclass serializer nor full UObject property deserialization executes here.',
            'Descriptor arrays are native reflected tables only; nested enum/array descriptors and inherited/transient/editor filtering still need schema reconstruction.',
            'Unversioned field indices are retained without invented property names;433bytes before candidate version are explicitly unresolved.',
            'No live actor/CDO selection, package load order, effective filters or movement verified.'])
    path=root/'code-clues/recast-actor-dispatch-code.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report
if __name__=='__main__':main()
