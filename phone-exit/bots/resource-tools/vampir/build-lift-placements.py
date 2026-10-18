"""Join source lift parents to exact scene children and preserve explicit placements."""
import hashlib,importlib.util,json,os,struct
from collections import defaultdict
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main(root):
    spec=importlib.util.spec_from_file_location('lift_native',HERE/'build-native-entry-code.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed native source')
    im=native.Image(exe);schema=[]
    # Pointer array contains inner element descriptors before outer array properties.
    for index,pointer,address,name,flag in [(5,0x14912aab8,0x14912a480,'RelativeLocation',25),(6,0x14912aac0,0x14912a4c0,'RelativeRotation',25),(7,0x14912aac8,0x14912a500,'RelativeScale3D',25),(10,0x14912aae0,0x14912a5c0,'bAbsoluteLocation',12)]:
        off=im.offset(address-im.pe.base);raw=exe[off:off+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base);po=im.offset(pointer-im.pe.base)
        if exe[no:no+len(name)+1]!=name.encode()+b'\0' or struct.unpack_from('<I',raw,24)[0]&255!=flag or struct.unpack_from('<Q',exe,po)[0]!=address:raise ValueError('Changed SceneComponent property '+name)
        schema.append(dict(index=index,name=name,descriptor_offset=off,descriptor_bytes=raw.hex(),name_offset=no,pointer_offset=po,pointer_bytes=exe[po:po+8].hex(),object_offset=struct.unpack_from('<I',raw,50)[0]))
    prefix=[]
    expected=['PhysicsVolume','AttachParent','AttachSocketName','AttachChildren','AttachChildren','ClientAttachedChildren','ClientAttachedChildren','RelativeLocation','RelativeRotation','RelativeScale3D','ComponentVelocity','bComponentToWorldUpdated','bAbsoluteLocation']
    for j,name in enumerate(expected):
        po=im.offset(0x912aa80)+j*8;ad=struct.unpack_from('<Q',exe,po)[0];off=im.offset(ad-im.pe.base);raw=exe[off:off+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base)
        if exe[no:no+len(name)+1]!=name.encode()+b'\0':raise ValueError('Changed SceneComponent prefix order')
        prefix.append(dict(name=name,gen_flags=struct.unpack_from('<I',raw,24)[0]&255,descriptor_offset=off,descriptor_bytes=raw.hex(),pointer_offset=po,pointer_bytes=exe[po:po+8].hex()))
    serialized=[r['name'] for j,r in enumerate(prefix) if not(j+1<len(prefix) and prefix[j+1]['name']==r['name'] and prefix[j+1]['gen_flags']==22)]
    for item in schema:
        if serialized[item['index']]!=item['name']:raise ValueError('Changed serialized SceneComponent index')
    folder=root/'maps/navigation-study/level';levelpath=folder/'index.json';level=json.loads(levelpath.read_text('utf-8'));parts={}
    for part in level['parts']:
        raw=(folder/part['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=part['sha256']:raise ValueError('Changed level part')
        parts[part['role']]=raw
    spec=importlib.util.spec_from_file_location('lift_package',HERE/'inspect-ui.py');package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
    parsed=package.exports(parts['asset'],parts['body'],max_exports=40000);exports={r['index']:r for r in parsed['exports']};children=defaultdict(list)
    for export in exports.values():children[export['outer']].append(export)
    spec=importlib.util.spec_from_file_location('lift_decoder',HERE/'decode-lift-placements.py');decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
    lifts=[];out=folder/'lifts';out.mkdir(exist_ok=True)
    def save(export):
        start=export['offset']-len(parts['asset']);raw=parts['body'][start:start+export['size']]
        if hashlib.sha256(raw).hexdigest()!=export['sha256']:raise ValueError('Changed component export')
        path=out/f"export-{export['index']}.bin";path.write_bytes(raw);return raw,dict(export=export,file='lifts/'+path.name)
    for link in level['navigation_exports']:
        if link['export']['type']!='NnNavLinkCustomComponent':continue
        parent=exports[link['export']['outer']];scenes=[e for e in children[parent['index']] if e['type']=='SceneComponent']
        if len(scenes)!=1:raise ValueError('Scene child ambiguity')
        _,parent_source=save(parent);raw,scene_source=save(scenes[0]);lifts.append(dict(link=link,parent=parent_source,scene_component=scene_source,placement=decoder.decode(raw),relation='Link.outer = Parent.index = SceneComponent.outer',root_component_verified=False,relative_endpoints_transformed=False,runtime_available_verified=False))
    result=dict(source=source,native_properties=schema,native_property_prefix=prefix,level_index_sha256=hashlib.sha256(levelpath.read_bytes()).hexdigest(),lifts=lifts,summary=dict(lifts=len(lifts),explicit_locations=sum('RelativeLocation' in x['placement']['properties'] for x in lifts),explicit_rotations=sum('RelativeRotation' in x['placement']['properties'] for x in lifts),explicit_scales=sum('RelativeScale3D' in x['placement']['properties'] for x in lifts),explicit_absolute_location=sum('bAbsoluteLocation' in x['placement']['properties'] for x in lifts),world_transforms_verified=0,routes_verified=0),limitations=['Export outer proves parentage only; root-component role, attachment graph and archetype defaults unresolved.','Explicit relative transform is not necessarily actor/world transform. Omitted rotation/scale/flags remain absent.','No link endpoint transformed, no map route drawn, no game traversal performed.'])
    path=folder/'lift-placements.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(summary=result['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest()),ensure_ascii=False));return result
if __name__=='__main__':main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir')))
