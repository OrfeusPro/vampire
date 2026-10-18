"""Verify per-instance Actor.RootComponent after decoding point-link prefixes."""
import hashlib,importlib.util,json,os,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main(root):
    def module(name,file):
        s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
    native=module('point_native','build-native-entry-code.py');decoder=module('point_decoder','decode-navigation-point-links.py')
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    im=native.Image(exe);schema=[]
    for index,(name,flag) in enumerate(zip(decoder.FIELDS,decoder.FLAGS)):
        po=im.offset(0x90c13f0)+index*8 if index<2 else im.offset(0x90c1040)+(index-2)*8
        off=im.offset(struct.unpack_from('<Q',exe,po)[0]-im.pe.base);raw=exe[off:off+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base)
        if exe[no:no+len(name)+1]!=name.encode()+b'\0' or struct.unpack_from('<I',raw,24)[0]&255!=flag:raise ValueError('Changed point-link schema')
        schema.append(dict(index=index,name=name,flag=flag,descriptor_offset=off,descriptor_bytes=raw.hex(),pointer_offset=po,pointer_bytes=exe[po:po+8].hex()))
    # Verify Actor's serialized property order, excluding enum-underlying and array-inner descriptors.
    prefix=[];start=im.offset(0x91698b0)-62*8
    for i in range(63):
        po=start+i*8;ad=struct.unpack_from('<Q',exe,po)[0];off=im.offset(ad-im.pe.base);raw=exe[off:off+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base)
        end=exe.find(b'\0',no);name=exe[no:end].decode('ascii');flag=struct.unpack_from('<I',raw,24)[0]&255
        prefix.append(dict(name=name,flag=flag,descriptor_offset=off,descriptor_bytes=raw.hex(),pointer_offset=po,pointer_bytes=exe[po:po+8].hex()))
    if prefix[0]['name']!='PrimaryActorTick' or prefix[-1]['name']!='RootComponent':raise ValueError('Changed Actor prefix boundaries')
    serial=[x for i,x in enumerate(prefix) if x['name']!='UnderlyingType' and not(i+1<len(prefix) and prefix[i+1]['name']==x['name'] and prefix[i+1]['flag']==22)]
    if len(serial)!=58 or serial[57]['name']!='RootComponent':raise ValueError('Changed Actor root index')
    # PointLinks is the native inner/array pair, followed by SegmentLinks inner/array.
    lift_arrays=[]
    for j,name in enumerate(['PointLinks','PointLinks','SegmentLinks','SegmentLinks']):
        po=im.offset(0x987d470)+j*8;off=im.offset(struct.unpack_from('<Q',exe,po)[0]-im.pe.base);raw=exe[off:off+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base)
        if exe[no:no+len(name)+1]!=name.encode()+b'\0':raise ValueError('Changed NnLift arrays')
        lift_arrays.append(dict(name=name,descriptor_offset=off,descriptor_bytes=raw.hex(),pointer_offset=po,pointer_bytes=exe[po:po+8].hex()))
    bp=root/'maps/navigation-study/lift-blueprints';settings_path=bp/'instance-settings.json';settings=json.loads(settings_path.read_text('utf-8'));level=root/'maps/navigation-study/level';results=[]
    for instance in settings['instances']:
        raw=(level/instance['parent']['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=instance['parent']['export']['sha256']:raise ValueError('Changed lift parent')
        reader=decoder.canvas.Reader(raw);reader.pos=instance['decoded_prefix_bytes'];offset=instance['blueprint_prefix_property_count'];root_index=offset+8+57;points=None;root_ref=None;unknown=[]
        first_unknown=instance['unknown_fields'][0] if instance['unknown_fields'] else None
        for index,zero in instance['field_indices']:
            if first_unknown is None or index<first_unknown:continue
            if index==offset+6:points=decoder.array(reader,zero)
            elif index==root_index:root_ref=0 if zero else reader.read('<i')
            else:unknown=[i for i,z in instance['field_indices'] if i>=index];break
        if root_ref is None or root_ref!=instance['properties']['SceneRoot']:raise ValueError('Actor.RootComponent differs from verified SceneRoot')
        results.append(dict(parent=instance['parent'],point_links=points,actor_root_property_index=root_index,actor_root_component=root_ref,scene_root=root_ref,root_reference_verified=True,remaining_unknown_fields=unknown,decoded_prefix_bytes=reader.pos,unresolved_suffix_hex=raw[reader.pos:].hex(),world_coordinates_verified=False,runtime_walkability_verified=False))
    enums=source['enums'].get('ENavLinkDirection',[])
    for row in enums:
        no=row['name_offset'];raw=row['name'].encode()+b'\0'
        if exe[no:no+len(raw)]!=raw:raise ValueError('Changed nav direction enum')
    report=dict(source=source,native_link_properties=schema,native_actor_prefix=prefix,native_lift_arrays=lift_arrays,actor_root_serialized_index=57,direction_enum=enums,instance_settings_sha256=hashlib.sha256(settings_path.read_bytes()).hexdigest(),instances=results,summary=dict(instances=len(results),verified_actor_roots=len(results),point_link_arrays=sum(r['point_links'] is not None for r in results),point_links=sum(len(r['point_links'] or []) for r in results),routes_verified=0),limitations=['Actor root references verified in this cooked snapshot; runtime replacement/attachment/movement not excluded.','SupportedAgents raw32 storage observed consistently; selector bits are not evaluated as movement permissions.','PointLink and SmartLink are distinct records; no graph edge, runtime direction or traversal guarantee inferred.','Missing PointLinks array is not an empty array; omitted values require archetypes.'])
    path=bp/'point-links.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(summary=report['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())));return report
if __name__=='__main__':main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir')))
