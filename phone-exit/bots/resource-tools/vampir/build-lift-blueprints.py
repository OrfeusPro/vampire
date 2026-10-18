"""Verify lift Blueprint inheritance and native default root construction."""
import hashlib,importlib.util,json,os,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent

def class_parent(asset,parsed):
    summary=36+struct.unpack_from('<i',asset,32)[0];ec,eo,ic,io=struct.unpack_from('<iiii',asset,summary+28)
    classes=[r for r in parsed['exports'] if r['type']=='BlueprintGeneratedClass']
    if len(classes)!=1:raise ValueError('Expected one generated class')
    cls=classes[0];offset=eo+(cls['index']-1)*96;super_index=struct.unpack_from('<i',asset,offset+4)[0]
    if not -ic<=super_index<0:raise ValueError('Expected imported superclass')
    pos=io+(-super_index-1)*32;name_index=struct.unpack_from('<i',asset,pos+20)[0]
    if not 0<=name_index<len(parsed['names']):raise ValueError('Invalid superclass name')
    return dict(class_export=cls,super_index=super_index,super_name=parsed['names'][name_index],export_table_offset=offset,export_table_bytes=asset[offset:offset+96].hex(),import_offset=pos,import_bytes=asset[pos:pos+32].hex())

def main(root):
    spec=importlib.util.spec_from_file_location('lift_root_native',HERE/'build-native-entry-code.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed client EXE')
    im=native.Image(exe);fragments=native.decode_ranges(im,{im.roots[im.containing(0x1454fd410)]});rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [(0x1454fd506,'call','0x141746350'),(0x1454fd50b,'mov','qword ptr [rsi + 0x3c0], rax'),(0x1454fd512,'mov','rbx, rax'),(0x1454fd531,'mov','qword ptr [rsi + 0x1b8], rbx'),(0x1454fd69a,'call','0x141746350'),(0x1454fd6bd,'mov','qword ptr [rsi + 0x3d8], rbx')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed native lift root anchor')
        anchors.append(row)
    descriptors=[]
    for address,name,offset in [(0x14987d1e0,'SceneRoot',0x3c0),(0x149168fe0,'RootComponent',0x1b8)]:
        pos=im.offset(address-im.pe.base);raw=exe[pos:pos+56];no=im.offset(struct.unpack_from('<Q',raw)[0]-im.pe.base)
        if exe[no:no+len(name)+1]!=name.encode()+b'\0' or struct.unpack_from('<I',raw,50)[0]!=offset:raise ValueError('Changed root property descriptor')
        descriptors.append(dict(name=name,address=address,file_offset=pos,bytes=raw.hex(),object_offset=offset,name_offset=no))
    literals=[]
    for name in ['Scene']:
        # Discover the checked Scene literal xref inside this constructor instead of assuming its instruction offset.
        found=[]
        for row in rows.values():
            for va in row['rip_references']:
                try:pos=im.offset(va-im.pe.base)
                except ValueError:continue
                if exe[pos:pos+len(name)*2+2]==name.encode('utf-16le')+b'\0\0':found.append((row,pos))
        if len(found)!=1:raise ValueError('Expected unique Scene literal in lift constructor')
        row,pos=found[0];anchors.append(row);literals.append(dict(name=name,file_offset=pos,bytes=exe[pos:pos+12].hex()))
    folder=root/'pak-extracted/pakchunk100-Windows';source_pak=json.loads((folder/'source.json').read_text('utf-8'));path=Path(source_pak['path']);stat=path.stat()
    with path.open('rb') as stream:
        head=stream.read(65536);stream.seek(max(0,stat.st_size-65536));sample=hashlib.sha256(head+stream.read()).hexdigest()
    if stat.st_size!=source_pak['size'] or stat.st_mtime_ns!=source_pak['modified_ns'] or sample!=source_pak['sample_sha256']:raise ValueError('Changed Blueprint PAK')
    entries_raw=(folder/'entries.json').read_bytes();entries=json.loads(entries_raw)
    spec=importlib.util.spec_from_file_location('lift_bp_pak',HERE.parent/'rfnext/scan-pak.py');pak=importlib.util.module_from_spec(spec);spec.loader.exec_module(pak)
    spec=importlib.util.spec_from_file_location('lift_bp_package',HERE/'inspect-ui.py');package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
    out=root/'maps/navigation-study/lift-blueprints';out.mkdir(exist_ok=True);blueprints=[]
    with path.open('rb') as stream:
        for eid,expected in [(2292,'NnLift'),(2296,'BP_Lift_C'),(2298,'BP_Lift_C')]:
            parts=[];provenance=[]
            for record_id in [eid,eid+1]:
                record=next(r for r in entries if r.get('entry')==record_id);h=pak.header(stream,record['offset'],entries[-1]['index_offset'])
                if not h or h['encrypted'] or h['usize']>1024**2:raise ValueError('Unexpected Blueprint record')
                raw=pak.decode(stream,h);parts.append(raw);name=f'{record_id}.bin';(out/name).write_bytes(raw);provenance.append(dict(file=name,record=record,sha256=hashlib.sha256(raw).hexdigest()))
            parsed=package.exports(*parts);parent=class_parent(parts[0],parsed)
            if parent['super_name']!=expected:raise ValueError('Changed lift inheritance')
            blueprints.append(dict(parts=provenance,inheritance=parent,exports=parsed['exports'],names=parsed['names'],default_properties_decoded=False))
    report=dict(source=source,source_pak=source_pak,entries_sha256=hashlib.sha256(entries_raw).hexdigest(),native_anchors=anchors,native_descriptors=descriptors,native_literals=literals,native_fragments=fragments,blueprints=blueprints,native_default_scene_root_verified=True,instance_root_overrides_resolved=False,world_transforms_verified=False,routes_verified=0,limitations=['Native default constructor assigns the created Scene object to SceneRoot and Actor.RootComponent; runtime/Blueprint overrides are not excluded.','Blueprint inheritance is verified by generated-class superclass import, not by similar filenames.','Scene defaults, inherited flags, attachment graph and lift activation conditions still require decoding.','No relative endpoint transformed to world coordinates and no route certified.'])
    dest=out/'index.json';dest.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(blueprints=len(blueprints),native_anchors=len(anchors),sha256=hashlib.sha256(dest.read_bytes()).hexdigest())));return report
if __name__=='__main__':main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir')))
