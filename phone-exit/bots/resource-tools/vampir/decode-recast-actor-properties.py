"""Decode the observed nav actor's explicit properties from native descriptors.

Descriptor-derived indices are checked against all observed fields. Complete
native schema construction/serialization and the remaining actor tail are not
executed; no omitted/default/runtime property value is invented.
"""
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
reader_module=load('nav_actor_property_reader','decode-canvas-slots.py')

def descriptor_schema(data,image,label,table,count):
    rows=[];slots=[]
    for index in range(count):
        pointer_offset=image.offset(table+8*index-image.pe.base);address=struct.unpack_from('<Q',data,pointer_offset)[0]
        off=image.offset(address-image.pe.base);raw=data[off:off+64];name_offset=image.offset(struct.unpack_from('<Q',raw)[0]-image.pe.base)
        end=data.index(b'\0',name_offset,name_offset+160);name=data[name_offset:end].decode('ascii')
        flags=struct.unpack_from('<Q',raw,16)[0];kind=struct.unpack_from('<I',raw,24)[0]&255;dimension=struct.unpack_from('<H',raw,48)[0]
        if not name or not name.replace('_','').isalnum() or not 1<=dimension<=8:raise ValueError('Unexpected native descriptor')
        row=dict(index=index,name=name,kind=kind,property_flags=flags,array_dim=dimension,descriptor=address,
            file_offset=off,raw_hex=raw.hex(),name_file_offset=name_offset,pointer_file_offset=pointer_offset)
        rows.append(row)
        # Zero PropertyFlags descriptors here are nested array/enum children,
        # not separate instance slots. Keep every row as provenance.
    for index,row in enumerate(rows):
        is_array_child=index+1<len(rows) and rows[index+1]['name']==row['name'] and rows[index+1]['kind']==22
        row['nested_array_child']=is_array_child
        if row['property_flags'] and not is_array_child:
            for element in range(row['array_dim']):slots.append(dict(owner=label,name=row['name'],kind=row['kind'],array_element=element,
                native_descriptor_index=index,descriptor=row['descriptor']))
    return dict(label=label,table=table,rows=rows,slots=slots,ordering_basis='derived class first; reflected array order; expand ArrayDim; omit zero-PropertyFlags descriptors and same-name array children preceding array22',
        complete_native_schema_builder_executed=False)

def fstring(reader):
    length=reader.read('<i')
    if not 1<=length<=4096 or reader.pos+length>len(reader.data):raise ValueError('Unsupported bounded ANSI FString')
    raw=reader.data[reader.pos:reader.pos+length];reader.pos+=length
    if raw[-1]!=0 or b'\0' in raw[:-1]:raise ValueError('Unterminated/embedded-NUL FString')
    return raw[:-1].decode('utf-8')

def decode_properties(raw,slots,names,schemas):
    reader=reader_module.Reader(raw);header=reader.header();records=[]
    def soft_path():
        pairs=[]
        for _ in range(2):
            index,number=reader.read('<ii')
            if not 0<=index<len(names) or number<0:raise ValueError('Invalid soft path name')
            pairs.append(dict(index=index,number=number,text=names[index]+('_'+str(number-1) if number else '')))
        sub_length=reader.read('<i')
        if sub_length!=0:raise ValueError('Nonempty soft subpath unsupported')
        return dict(package=pairs[0],asset=pairs[1],subpath='')
    def float_value():
        value=reader.read('<f')
        if not math.isfinite(value):raise ValueError('Nonfinite float property')
        return value
    for index,zero in header:
        if zero or index>=len(slots):raise ValueError('Unsupported actor field mask/index')
        prop=slots[index];name=prop['name'];start=reader.pos
        if name in ['CellSize','AgentRadius']:
            if prop['kind']!=10:raise ValueError('Native float descriptor mismatch')
            value=float_value()
        elif name=='NavMeshResolutionParams':
            if prop['kind']!=25:raise ValueError('Native resolution struct descriptor mismatch')
            fields=reader.header()
            if fields!=[(0,False)] or schemas['NavMeshResolutionParam']['slots'][0]['name']!='CellSize':raise ValueError('Unsupported resolution struct fields')
            value=dict(CellSize=float_value())
        elif name=='NavDataConfig':
            if prop['kind']!=25:raise ValueError('Native config descriptor mismatch')
            fields=reader.header();value={};config_slots=schemas['NavDataConfig']['slots']+schemas['NavAgentProperties']['slots']
            for field,field_zero in fields:
                if field_zero or field>=len(config_slots):raise ValueError('Unsupported config field')
                label=config_slots[field]['name']
                if label=='DefaultQueryExtent':
                    vector=reader.read('<3d')
                    if any(not math.isfinite(v) for v in vector):raise ValueError('Invalid extent')
                    value[label]=vector
                elif label in ['NavDataClass','PreferredNavData']:value[label]=soft_path()
                elif label=='AgentStepHeight':value[label]=float_value()
                else:raise ValueError('Unreviewed config property '+label)
        elif name=='SupportedAreas':
            if prop['kind']!=22:raise ValueError('Native array descriptor mismatch')
            count=reader.read('<i')
            if not 0<=count<=64:raise ValueError('Area count bound')
            value=[];area_slots=schemas['SupportedAreaData']['slots']
            for _ in range(count):
                fields=reader.header();area={}
                for field,field_zero in fields:
                    if field>=len(area_slots):raise ValueError('Area property bound')
                    label=area_slots[field]['name']
                    if label=='AreaClassName':
                        if field_zero:raise ValueError('Area name omitted')
                        area[label]=fstring(reader)
                    elif label=='AreaID':area[label]=0 if field_zero else reader.read('<i')
                    else:raise ValueError('Explicit class reference requires additional decoding')
                if set(area)!={'AreaClassName','AreaID'} or not 0<=area['AreaID']<64:raise ValueError('Incomplete area record')
                value.append(area)
            if len({a['AreaID'] for a in value})!=len(value):raise ValueError('Duplicate area IDs')
        elif name=='RootComponent':
            if prop['kind']!=82:raise ValueError('Root component type mismatch')
            value=reader.read('<i')
            if value<=0:raise ValueError('Root is not a local export')
        else:raise ValueError('Unsupported explicit actor property '+name)
        records.append(dict(schema_index=index,property=prop,begin=start,end=reader.pos,raw_hex=raw[start:reader.pos].hex(),value=value))
    return dict(header_fields=[dict(index=i,zero=z) for i,z in header],header_bytes=records[0]['begin'],
        properties=records,properties_end=reader.pos,remaining_bytes=len(raw)-reader.pos,
        complete_actor_serialization_decoded=False)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    native=load('nav_actor_properties_native','build-native-entry-code.py');source=json.loads((root/'code-clues/native-enums.json').read_bytes())
    data=Path(source['source']).read_bytes();assert sha(data)==source['sha256'];image=native.Image(data)
    dispatch_raw=(root/'code-clues/recast-actor-dispatch-code.json').read_bytes();dispatch=json.loads(dispatch_raw);assert dispatch['sha256']==source['sha256']
    folder=root/'maps/navigation-study/level';level_raw=(folder/'index.json').read_bytes();level=json.loads(level_raw)
    parts={}
    for part in level['parts']:
        raw=(folder/part['file']).read_bytes();assert sha(raw)==part['sha256'];parts[part['role']]=raw
    package=load('nav_actor_properties_package','inspect-ui.py').exports(parts['asset'],parts['body'],max_exports=40000)
    entry=dispatch['actor_export'];actor=(folder/entry['file']).read_bytes();assert sha(actor)==entry['export']['sha256']
    definitions=[('NnRecastNavMesh',0x14985ca08,3),('RecastNavMesh',0x14972b230,76),('NavigationData',0x149720b20,14),('Actor',0x1491696c0,88),
        ('NavMeshResolutionParam',0x149729ac0,3),('NavDataConfig',0x1491728f0,4),('NavAgentProperties',0x149172650,5),('SupportedAreaData',0x149720488,3)]
    schemas={name:descriptor_schema(data,image,name,table,count) for name,table,count in definitions}
    slots=[]
    for label in ['NnRecastNavMesh','RecastNavMesh','NavigationData','Actor']:
        for row in schemas[label]['slots']:slots.append(dict(schema_index=len(slots),**row))
    decoded=decode_properties(actor,slots,package['names'],schemas)
    expected={29:'CellSize',32:'NavMeshResolutionParams',33:'NavMeshResolutionParams',34:'NavMeshResolutionParams',35:'AgentRadius',81:'NavDataConfig',91:'SupportedAreas',149:'RootComponent'}
    assert {r['schema_index']:r['property']['name'] for r in decoded['properties']}==expected
    root_ref=next(r['value'] for r in decoded['properties'] if r['property']['name']=='RootComponent')
    target=package['exports'][root_ref-1];assert target['outer']==entry['export']['index'] and target['type']=='SceneComponent'
    # Pin struct descriptors to their native getter registries and class arrays
    # to constructor/reflection relationships. Do not imply full UObject schema.
    getter_pairs=[(0x1454c54e0,0x14985ccd0,0x14985ca08),(0x143094460,0x14916aca0,0x1491696c0)]
    registries=[]
    for getter,registry,table in getter_pairs:
        off=image.offset(registry-image.pe.base);raw=data[off:off+56]
        assert struct.unpack_from('<Q',raw)[0]==getter and struct.unpack_from('<Q',raw,40)[0]==table
        registries.append(dict(kind='class',getter=getter,address=registry,file_offset=off,raw_hex=raw.hex(),table=table))
    for getter,registry,table in [(0x145293c90,0x14b133eb8,0x149729ac0),(0x143861630,0x14b0c28d8,0x1491728f0),
        (0x143830040,0x14b0c28a0,0x149172650),(0x145268890,0x14b1334b0,0x149720488)]:
        off=image.offset(registry-image.pe.base);raw=data[off:off+56];assert struct.unpack_from('<Q',raw,32)[0]==table
        registries.append(dict(kind='struct',getter=getter,address=registry,file_offset=off,raw_hex=raw.hex(),table=table))
    actor_thunk_offset=image.offset(0x143094460-image.pe.base);actor_thunk=data[actor_thunk_offset:actor_thunk_offset+5]
    assert actor_thunk==bytes.fromhex('e93bc17700')
    fragments=native.decode_ranges(image,{image.roots[image.containing(a)] for a in [0x1438105a0,0x1454c54e0,0x145293b20,0x145266670,0x145293c90,0x143861630,0x143830040,0x145268890]})
    instructions={r['address']:r for f in fragments for r in f['instructions']};super_bindings=[]
    for address,parent in [(0x1454c551b,0x145293b20),(0x145293b5b,0x145266670),(0x1452666ab,0x143094460)]:
        row=instructions[address]
        if row['mnemonic']!='lea' or row['rip_references']!=[parent]:raise ValueError('Changed native superclass getter')
        super_bindings.append(dict(instruction=row,super_getter=parent))
    struct_getters=[]
    for schema,index,getter in [('RecastNavMesh',29,0x145293c90),('NavigationData',1,0x143861630),('NavigationData',12,0x145268890)]:
        row=schemas[schema]['rows'][index];ptr=struct.unpack_from('<Q',bytes.fromhex(row['raw_hex']),56)[0]
        if ptr!=getter:raise ValueError('Changed nested struct getter')
        struct_getters.append(dict(owner=schema,descriptor_index=index,getter=getter))
    config_registry=next(r for r in registries if r['getter']==0x143861630)
    assert struct.unpack_from('<Q',bytes.fromhex(config_registry['raw_hex']),8)[0]==0x143830040
    parameter_raw=(folder/'nav-parameter-candidates.json').read_bytes();parameter=json.loads(parameter_raw)['candidates'][0]
    cell=decoded['properties'][0]['value'];resolutions=[r['value']['CellSize'] for r in decoded['properties'][1:4]]
    reciprocal32=lambda value:struct.unpack('<f',struct.pack('<f',1./value))[0]
    consistency=dict(width_divided_by_cell_size=[w/cell for w in parameter['tile_widths_raw']],
        reciprocal_resolution_float32=[reciprocal32(v) for v in resolutions],candidate_quantization=parameter['parameter_doubles_raw'][3:],
        quantization_matches=parameter['parameter_doubles_raw'][3:]==[reciprocal32(v) for v in resolutions],
        native_generation_formula_verified=False)
    report=dict(source=source['source'],sha256=sha(data),source_dispatch_sha256=sha(dispatch_raw),source_level_sha256=sha(level_raw),
        builder_sha256=sha(Path(__file__).read_bytes()),reader_sha256=sha((HERE/'decode-canvas-slots.py').read_bytes()),
        source_parameter_candidate_sha256=sha(parameter_raw),parameter_consistency=consistency,
        actor_export=entry,schemas=schemas,registries=registries,fragments=fragments,
        actor_class_thunk=dict(address=0x143094460,file_offset=actor_thunk_offset,raw_hex=actor_thunk.hex(),target=0x1438105a0),
        derived_slots=slots,decoded=decoded,root_component_export=target,super_getter_bindings=super_bindings,nested_struct_getters=struct_getters,
        remaining_before_candidate_stream=dict(begin=decoded['properties_end'],end=443,bytes=443-decoded['properties_end'],
            raw_hex=actor[decoded['properties_end']:443].hex(),semantics_verified=False),
        summary=dict(explicit_property_records=len(decoded['properties']),property_bytes_consumed=decoded['properties_end'],
            remaining_actor_tail_bytes=443-decoded['properties_end'],serialized_area_records=9,property_boundary_verified=False,
            runtime_area_ids_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Derived-first order, ArrayDim expansion and nested-child exclusion agree with all8observed fields; full native schema builder not executed.',
            'Properties are explicit cooked values, not live CDO/instance/filter activation; omitted fields are not filled.',
            'SupportedArea names/IDs belong to this actor export; AreaClass pointer values are not serialized in these rows and are not invented.',
            '68remaining superclass/actor bytes before candidate stream still need serializer branch/version interpretation; offset443 boundary remains unproved.'])
    path=root/'code-clues/recast-actor-properties.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report
if __name__=='__main__':main()
