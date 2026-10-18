"""Verify native spline parameter schema and decode explicit lift instance prefixes."""
import hashlib,importlib.util,json,os,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main(root):
    def module(name,file):
        spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    native=module('spline_native','build-native-entry-code.py');decoder=module('spline_decoder','decode-spline-action-params.py');package=module('spline_package','inspect-ui.py')
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    im=native.Image(exe);schema=[]
    for index,(name,flag) in enumerate(zip(decoder.FIELDS,decoder.FLAGS)):
        po=im.offset(0x98184b0)+index*8;off=im.offset(struct.unpack_from('<Q',exe,po)[0]-im.pe.base);raw=exe[off:off+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base)
        if exe[no:no+len(name)+1]!=name.encode()+b'\0' or struct.unpack_from('<I',raw,24)[0]&255!=flag:raise ValueError('Changed spline property schema')
        schema.append(dict(index=index,name=name,flag=flag,descriptor_offset=off,descriptor_bytes=raw.hex(),name_offset=no,pointer_offset=po,pointer_bytes=exe[po:po+8].hex()))
    # The native NnLift prefix is separate from Blueprint-defined fields.
    lift_names=['bAutoActivation','SplineActionParams','SceneRoot','Spline','TriggerComponent','SmartLinkComp'];native_prefix=[]
    for index,name in enumerate(lift_names):
        po=im.offset(0x987d440)+index*8;off=im.offset(struct.unpack_from('<Q',exe,po)[0]-im.pe.base);raw=exe[off:off+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base)
        if exe[no:no+len(name)+1]!=name.encode()+b'\0':raise ValueError('Changed NnLift prefix')
        native_prefix.append(dict(index=index,name=name,pointer_offset=po,pointer_bytes=exe[po:po+8].hex(),descriptor_offset=off,descriptor_bytes=raw.hex()))
    bpdir=root/'maps/navigation-study/lift-blueprints';bpindex=bpdir/'index.json';bps=json.loads(bpindex.read_text('utf-8'));counts={};class_sources=[]
    for bp in bps['blueprints']:
        parts=[]
        for part in bp['parts']:
            raw=(bpdir/part['file']).read_bytes()
            if hashlib.sha256(raw).hexdigest()!=part['sha256']:raise ValueError('Changed Blueprint bytes')
            parts.append(raw)
        parsed=package.exports(*parts);cls=bp['inheritance']['class_export'];start=cls['offset']-len(parts[0]);raw=parts[1][start:start+cls['size']];r=decoder.canvas.Reader(raw)
        # Observed class UObject prefix: explicit construction-script/handler/frame references.
        for index,zero in r.header():
            if index not in [7,8,9] or zero:raise ValueError('Unknown generated-class property prefix')
            ref=r.read('<i')
            if not 0<=ref<=len(parsed['exports']):raise ValueError('Bad class prefix reference')
        if r.read('<I')!=0:raise ValueError('Unknown class object suffix')
        if r.read('<i')!=bp['inheritance']['super_index']:raise ValueError('UStruct superclass mismatch')
        children=r.read('<i')
        if not 0<=children<=10000:raise ValueError('Invalid class child count')
        for _ in range(children):
            ref=r.read('<i')
            if not 0<ref<=len(parsed['exports']):raise ValueError('Invalid class child')
        count=r.read('<i')
        if not 0<=count<=1000:raise ValueError('Invalid own property count')
        counts[cls['name']]=count;class_sources.append(dict(class_name=cls['name'],own_property_count=count,super_name=bp['inheritance']['super_name'],export=cls,checked_prefix_bytes=raw[:r.pos].hex()))
    if counts!={'BP_Lift_C':2,'BP_Lift_Test_C':1,'BP_Lift_Type01_C':0}:raise ValueError('Changed lift class properties')
    cumulative={'BP_Lift_C':2,'BP_Lift_Test_C':3,'BP_Lift_Type01_C':2}
    leveldir=root/'maps/navigation-study/level';placements_path=leveldir/'lift-placements.json';placements=json.loads(placements_path.read_text('utf-8'));rows=[]
    for lift in placements['lifts']:
        spec=lift['parent'];raw=(leveldir/spec['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=spec['export']['sha256']:raise ValueError('Changed instance')
        r=decoder.canvas.Reader(raw);fields=r.header();offset=cumulative[spec['export']['type']];values={};unknown=[]
        for index,zero in fields:
            if index==offset-1:values['BlueprintObjectReference']=0 if zero else r.read('<i')
            elif index==offset:
                value=0 if zero else r.read('<B')
                if value not in [0,1]:raise ValueError('Invalid auto activation flag')
                values['bAutoActivation']=bool(value)
            elif index==offset+1:values['SplineActionParams']=decoder.decode(r,zero)
            elif offset+2<=index<=offset+5:values[lift_names[index-offset]]=0 if zero else r.read('<i')
            else:unknown=[i for i,z in fields if i>=index];break
        expected_scene=lift['scene_component']['export']['index'];expected_link=lift['link']['export']['index']
        if values.get('SceneRoot')!=expected_scene or values.get('SmartLinkComp')!=expected_link:raise ValueError('Instance component reference mismatch')
        rows.append(dict(parent=spec,properties=values,field_indices=fields,blueprint_prefix_property_count=offset,native_scene_root_reference_verified=True,actor_root_component_override_resolved=False,unknown_fields=unknown,decoded_prefix_bytes=r.pos,unresolved_suffix_hex=raw[r.pos:].hex(),world_transform_verified=False))
    report=dict(source=source,native_spline_properties=schema,native_lift_properties=native_prefix,blueprint_index_sha256=hashlib.sha256(bpindex.read_bytes()).hexdigest(),placements_sha256=hashlib.sha256(placements_path.read_bytes()).hexdigest(),class_sources=class_sources,instances=rows,summary=dict(instances=len(rows),verified_scene_references=len(rows),explicit_auto_activation=sum('bAutoActivation' in r['properties'] for r in rows),spline_params=sum('SplineActionParams' in r['properties'] for r in rows),routes_verified=0),limitations=['SceneRoot and SmartLinkComp references verified for each instance; Actor.RootComponent and attachment/runtime overrides still unresolved.','SplineActionParams numerical fields remain in client units; name alone does not establish seconds or execution behavior.','Omitted settings are not inherited/default values; unknown instance fields and suffix bytes retained.'])
    path=bpdir/'instance-settings.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(summary=report['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())));return report
if __name__=='__main__':main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir')))
