"""Independent byte/type/slot checks for actor serialization evidence."""
import hashlib
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def decode_header_independently(data):
    pos=0;index=0;fields=[];mask_count=0
    for _ in range(64):
        if pos+2>len(data):raise ValueError('Truncated header')
        word=int.from_bytes(data[pos:pos+2],'little');pos+=2
        index+=word%128;count=word//512;has_mask=bool(word&128)
        fields.extend((i,has_mask) for i in range(index,index+count));index+=count
        if has_mask:mask_count+=count
        if word&256:break
    else:raise ValueError('Header fragment bound')
    size=0 if mask_count==0 else 1 if mask_count<=8 else 2 if mask_count<=16 else 4*((mask_count+31)//32)
    if pos+size>len(data):raise ValueError('Truncated mask')
    mask=int.from_bytes(data[pos:pos+size],'little');pos+=size;bit=0;result=[]
    for i,has_mask in fields:
        result.append(dict(index=i,zero=bool(mask&(1<<bit)) if has_mask else False));bit+=int(has_mask)
    return pos,result

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-actor-dispatch-code.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    data=Path(report['source']).read_bytes();assert sha(data)==report['sha256'];inputs={}
    for file,digest in report['input_reports'].items():
        raw=(root/file).read_bytes();assert sha(raw)==digest;inputs[file]=json.loads(raw)
    for fragment in report['fragments']:
        off=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva'];assert sha(data[off:off+size])==fragment['sha256']
    for row in report['anchors']:
        raw=bytes.fromhex(row['bytes']);assert data[row['file_offset']:row['file_offset']+len(raw)]==raw
    expected={(table,slot,target) for table in [0x149872f38,0x14972dc00] for slot,target in [(0xd8,0x1452b91e0),(0xe0,0x1452b8ff0)]}
    assert {(b['table'],b['slot'],b['target']) for b in report['virtual_bindings']}==expected
    for binding in report['virtual_bindings']:
        raw=bytes.fromhex(binding['raw_hex']);assert data[binding['file_offset']:binding['file_offset']+8]==raw
        assert struct.unpack('<Q',raw)[0]==binding['target']
    selection=inputs['code-clues/recast-filter-selection-evidence.json'];assert selection['sha256']==report['sha256']
    assert {b['table'] for b in selection['base_initializer_vtables']}=={t for t,_,_ in expected}
    total=0
    for schema,count in zip(report['native_descriptor_arrays'],[14,76]):
        registry=schema['class_registry'];raw=bytes.fromhex(registry['raw_hex']);assert data[registry['file_offset']:registry['file_offset']+56]==raw
        assert struct.unpack_from('<Q',raw)[0]==registry['class_getter'] and struct.unpack_from('<Q',raw,40)[0]==schema['table']
        literal=schema['class_literal'];raw=bytes.fromhex(literal['raw_hex']);assert raw==(schema['class_label']+'\0').encode('utf-16le')
        assert data[literal['file_offset']:literal['file_offset']+len(raw)]==raw
        assert len(schema['entries'])==count and schema['cooked_inherited_order_verified'] is False
        for index,row in enumerate(schema['entries']):
            total+=1;raw=bytes.fromhex(row['raw_hex']);assert row['index']==index and data[row['file_offset']:row['file_offset']+len(raw)]==raw
            assert struct.unpack_from('<I',raw,24)[0]==row['gen_flags'] and struct.unpack_from('<I',raw,50)[0]==row['object_offset_raw']
            name=row['name'].encode()+b'\0';assert data[row['name_file_offset']:row['name_file_offset']+len(name)]==name
            ptr=bytes.fromhex(row['pointer_raw_hex']);assert data[row['pointer_file_offset']:row['pointer_file_offset']+8]==ptr and struct.unpack('<Q',ptr)[0]==row['descriptor']
    actor=report['actor_export'];level=inputs['maps/navigation-study/level/index.json'];assert actor in level['navigation_exports'] and actor['export']['type']=='NnRecastNavMesh'
    raw=(root/'maps/navigation-study/level'/actor['file']).read_bytes();assert sha(raw)==actor['export']['sha256']
    pos,fields=decode_header_independently(raw);header=report['prefix_header']
    assert pos==header['header_bytes']==10 and fields==header['fields'] and bytes.fromhex(header['raw_hex'])==raw[:pos]
    assert [r['index'] for r in fields]==[29,32,33,34,35,81,91,149] and not any(r['zero'] for r in fields)
    unresolved=report['unresolved_prefix'];assert unresolved['begin']==pos and unresolved['end']==443 and unresolved['bytes']==433
    assert bytes.fromhex(unresolved['raw_hex'])==raw[pos:443] and unresolved['candidate_end_only'] is True
    suffix=report['suffix'];assert suffix['offset']==443 and bytes.fromhex(suffix['raw_hex'])==raw[443:]
    assert struct.unpack_from('<iIi',raw,443)==(26,104,0) and len(raw)==551
    assert report['summary']['parameter_boundary_verified'] is False and report['summary']['prefix_values_decoded'] is False
    result=dict(source_report_sha256=sha(report_raw),virtual_slots_checked=4,native_descriptor_entries_checked=total,
        prefix_header_fields_checked=len(fields),unresolved_prefix_bytes=433,shared_serializer_dispatch_verified=True,
        property_boundary_verified=False,runtime_parameter_selection_verified=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-actor-dispatch-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
