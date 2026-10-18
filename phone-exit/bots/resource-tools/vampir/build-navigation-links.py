"""Source-linked lift component properties; never emit a traversable graph."""
import hashlib,importlib.util,json,os,struct
from collections import Counter
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main(root):
    spec=importlib.util.spec_from_file_location('native',HERE/'build-native-entry-code.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    im=native.Image(exe);schema=[]
    for index,address,name,flag in [(1,0x149728f90,'CustomLinkId',25),(2,0x149728fd0,'AuxiliaryCustomLinkId',25),(6,0x1497290f0,'LinkRelativeStart',25),(7,0x149729130,'LinkRelativeEnd',25)]:
        off=im.offset(address-im.pe.base);raw=exe[off:off+56];ptr=struct.unpack_from('<Q',raw)[0];nameoff=im.offset(ptr-im.pe.base);arrayoff=im.offset(0x9729510)+index*8
        if exe[nameoff:nameoff+len(name)+1]!=name.encode()+b'\0' or struct.unpack_from('<I',raw,24)[0]!=flag or struct.unpack_from('<Q',exe,arrayoff)[0]!=address:raise ValueError('Changed nav link schema')
        schema.append(dict(index=index,name=name,descriptor_offset=off,descriptor_bytes=raw.hex(),name_offset=nameoff,object_offset=struct.unpack_from('<I',raw,50)[0],array_pointer_offset=arrayoff,array_pointer_bytes=exe[arrayoff:arrayoff+8].hex()))
    fragments=native.decode_ranges(im,{im.roots[im.containing(a)] for a in [0x145458c80,0x145299d50]})
    instructions={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [(0x145458c94,'call','0x145299d50'),(0x145458ca0,'mov','qword ptr [rbx], rax'),(0x145299d62,'call','0x1452c35d0'),(0x145299d70,'mov','qword ptr [rbx], rax')]:
        row=instructions[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed navigation constructor chain')
        anchors.append(row)
    spec=importlib.util.spec_from_file_location('link_decoder',HERE/'decode-navigation-links.py');decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
    folder=root/'maps/navigation-study/level';levelpath=folder/'index.json';level=json.loads(levelpath.read_text('utf-8'));rows=[]
    for item in level['navigation_exports']:
        if item['export']['type']!='NnNavLinkCustomComponent':continue
        raw=(folder/item['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=item['export']['sha256']:raise ValueError('Changed link export')
        rows.append(dict(source=item,decoded=decoder.decode(raw)))
    result=dict(source=source,level_index_sha256=hashlib.sha256(levelpath.read_bytes()).hexdigest(),native_properties=schema,constructor_anchors=anchors,constructor_fragments=fragments,links=rows,summary=dict(components=len(rows),explicit_starts=sum('LinkRelativeStart' in r['decoded']['properties'] for r in rows),explicit_ends=sum('LinkRelativeEnd' in r['decoded']['properties'] for r in rows),unknown_field_components=sum(bool(r['decoded']['unknown_fields']) for r in rows),parents=dict(Counter(r['source']['export']['parent'].split('_UAID')[0] for r in rows)),routes_verified=0,navigation_ready=False),limitations=['Only explicitly serialized IDs/local endpoints decoded using native property-array order; omitted values stay absent.','Parent actor transform, direction, enabled state, archetype defaults, lift motion and runtime conditions not resolved.','Unknown property fields and all suffix bytes retained. Suffix semantics not inferred from zero bytes.','These components are not graph edges or verified routes.'])
    path=folder/'link-properties.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(summary=result['summary'],sha256=hashlib.sha256(path.read_bytes()).hexdigest()),ensure_ascii=False));return result
if __name__=='__main__':main(Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir')))
