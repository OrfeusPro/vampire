"""Byte audit and independent explicit-value decode of the observed nav actor."""
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
header_audit=load('actor_properties_header_audit','audit-recast-actor-dispatch.py')

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-actor-properties.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    data=Path(report['source']).read_bytes();assert sha(data)==report['sha256']
    assert sha((HERE/'decode-recast-actor-properties.py').read_bytes())==report['builder_sha256']
    assert sha((HERE/'decode-canvas-slots.py').read_bytes())==report['reader_sha256']
    dispatch=(root/'code-clues/recast-actor-dispatch-code.json').read_bytes();assert sha(dispatch)==report['source_dispatch_sha256']
    folder=root/'maps/navigation-study/level';level_raw=(folder/'index.json').read_bytes();assert sha(level_raw)==report['source_level_sha256'];level=json.loads(level_raw)
    parts={}
    for p in level['parts']:
        raw=(folder/p['file']).read_bytes();assert sha(raw)==p['sha256'];parts[p['role']]=raw
    package=load('actor_property_audit_package','inspect-ui.py').exports(parts['asset'],parts['body'],max_exports=40000)
    actor=report['actor_export'];assert actor in level['navigation_exports'];raw=(folder/actor['file']).read_bytes();assert sha(raw)==actor['export']['sha256']
    for f in report['fragments']:
        off=f['file_offset'];size=f['end_rva']-f['begin_rva'];assert sha(data[off:off+size])==f['sha256']
    thunk=report['actor_class_thunk'];b=bytes.fromhex(thunk['raw_hex']);assert data[thunk['file_offset']:thunk['file_offset']+5]==b
    assert thunk['address']+5+struct.unpack_from('<i',b,1)[0]==thunk['target']
    for schema in report['schemas'].values():
        for index,r in enumerate(schema['rows']):
            b=bytes.fromhex(r['raw_hex']);assert r['index']==index and data[r['file_offset']:r['file_offset']+64]==b
            assert struct.unpack_from('<Q',b,16)[0]==r['property_flags'] and struct.unpack_from('<I',b,24)[0]&255==r['kind']
            assert struct.unpack_from('<H',b,48)[0]==r['array_dim']
            assert struct.unpack_from('<Q',data,r['pointer_file_offset'])[0]==r['descriptor']
            name=r['name'].encode()+b'\0';assert data[r['name_file_offset']:r['name_file_offset']+len(name)]==name
        independent=[]
        for i,r in enumerate(schema['rows']):
            nested=i+1<len(schema['rows']) and schema['rows'][i+1]['name']==r['name'] and schema['rows'][i+1]['kind']==22
            assert r['nested_array_child']==nested
            if not r['property_flags'] or nested:continue
            for element in range(r['array_dim']):independent.append(dict(owner=schema['label'],name=r['name'],kind=r['kind'],array_element=element,native_descriptor_index=i,descriptor=r['descriptor']))
        assert independent==schema['slots']
    for registry in report['registries']:
        b=bytes.fromhex(registry['raw_hex']);assert data[registry['file_offset']:registry['file_offset']+56]==b
        assert struct.unpack_from('<Q',b,40 if registry['kind']=='class' else 32)[0]==registry['table']
    for binding in report['super_getter_bindings']:
        instruction=binding['instruction'];b=bytes.fromhex(instruction['bytes'])
        assert data[instruction['file_offset']:instruction['file_offset']+len(b)]==b and instruction['rip_references']==[binding['super_getter']]
    for binding in report['nested_struct_getters']:
        row=report['schemas'][binding['owner']]['rows'][binding['descriptor_index']]
        assert struct.unpack_from('<Q',bytes.fromhex(row['raw_hex']),56)[0]==binding['getter']
    slots=[]
    for cls in ['NnRecastNavMesh','RecastNavMesh','NavigationData','Actor']:
        base_index=len(slots);slots.extend(dict(schema_index=base_index+j,**p) for j,p in enumerate(report['schemas'][cls]['slots']))
    assert slots==report['derived_slots']
    pos,fields=header_audit.decode_header_independently(raw);assert fields==report['decoded']['header_fields'] and pos==10
    expected_bounds=[(10,14),(14,20),(20,26),(26,32),(32,36),(36,110),(110,371),(371,375)]
    records=report['decoded']['properties'];assert [(r['begin'],r['end']) for r in records]==expected_bounds
    for row in records:
        assert bytes.fromhex(row['raw_hex'])==raw[row['begin']:row['end']]
        assert row['property']==slots[row['schema_index']]
    assert records[0]['value']==struct.unpack_from('<f',raw,10)[0]==19.60784339904785
    for record,offset,expected in zip(records[1:4],[14,20,26],[40.,19.60784339904785,19.60784339904785]):
        assert raw[offset:offset+2]==b'\0\x03' and record['value']==dict(CellSize=expected) and struct.unpack_from('<f',raw,offset+2)[0]==expected
    assert records[4]['value']==struct.unpack_from('<f',raw,32)[0]==35.
    parameter_raw=(folder/'nav-parameter-candidates.json').read_bytes();assert sha(parameter_raw)==report['source_parameter_candidate_sha256']
    parameter=json.loads(parameter_raw)['candidates'][0];cell=struct.unpack_from('<f',raw,10)[0]
    reciprocals=[struct.unpack('<f',struct.pack('<f',1./struct.unpack_from('<f',raw,offset)[0]))[0] for offset in [16,22,28]]
    assert report['parameter_consistency']==dict(width_divided_by_cell_size=[w/cell for w in parameter['tile_widths_raw']],
        reciprocal_resolution_float32=reciprocals,candidate_quantization=parameter['parameter_doubles_raw'][3:],
        quantization_matches=reciprocals==parameter['parameter_doubles_raw'][3:],native_generation_formula_verified=False)
    config=records[5]['value'];end,config_header=header_audit.decode_header_independently(raw[36:]);assert end==6 and [f['index'] for f in config_header]==[2,3,6,8]
    assert config['DefaultQueryExtent']==list(struct.unpack_from('<3d',raw,42))==[100.,100.,500.]
    for field,offset in [('NavDataClass',66),('PreferredNavData',90)]:
        a,an,b,bn,length=struct.unpack_from('<5i',raw,offset);assert length==0
        assert config[field]==dict(package=dict(index=a,number=an,text=package['names'][a]),asset=dict(index=b,number=bn,text=package['names'][b]),subpath='')
    assert config['AgentStepHeight']==struct.unpack_from('<f',raw,86)[0]==35.
    assert struct.unpack_from('<i',raw,110)[0]==9;pos=114;areas=[]
    for _ in range(9):
        consumed,fields=header_audit.decode_header_independently(raw[pos:]);pos+=consumed
        assert [f['index'] for f in fields]==[0,1] and not fields[0]['zero']
        size=struct.unpack_from('<i',raw,pos)[0];pos+=4;assert 1<size<100 and raw[pos+size-1]==0
        name=raw[pos:pos+size-1].decode();pos+=size
        identifier=0
        if not fields[1]['zero']:identifier=struct.unpack_from('<i',raw,pos)[0];pos+=4
        areas.append(dict(AreaClassName=name,AreaID=identifier))
    assert pos==371 and areas==records[6]['value']
    assert [(a['AreaClassName'],a['AreaID']) for a in areas]==[('NavArea_Null',0),('NavArea_LowHeight',62),('NavArea_Default',63),
        ('NavArea_Obstacle',10),('NnNavArea_HiddenPath',11),('BP_NavArea_MainRoad_C',1),('BP_NavArea_HiddenPath_C',2),('NnNavArea_Forbidden',3),('NnNavArea_MainRoad',4)]
    ref=struct.unpack_from('<i',raw,371)[0];assert ref==records[7]['value']==5493
    component=package['exports'][ref-1];assert component==report['root_component_export'] and component['outer']==actor['export']['index'] and component['type']=='SceneComponent'
    tail=report['remaining_before_candidate_stream'];assert tail['begin']==375 and tail['end']==443 and tail['bytes']==68 and bytes.fromhex(tail['raw_hex'])==raw[375:443]
    decoder=load('actor_properties_replay','decode-recast-actor-properties.py')
    assert decoder.decode_properties(raw,slots,package['names'],report['schemas'])==report['decoded']
    result=dict(source_report_sha256=sha(report_raw),explicit_properties_checked=8,area_rows_checked=9,properties_end=375,
        remaining_actor_bytes=68,descriptor_indices_checked=True,native_schema_builder_executed=False,
        parameter_boundary_verified=False,runtime_area_ids_verified=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-actor-properties-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
