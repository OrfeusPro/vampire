"""Verify current GridSlot getter/metadata links without treating writes as CDO defaults."""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('grid_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
ROOTS=(0x143579900,0x14357b7a0,0x1435b51e0)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def inspect(request):
    if request['source_sha256']!=SHA or request['question']!='ui-nktileview-property-schema':raise ValueError('Unreviewed request')
    if not set(map(hex,ROOTS)) <= {f['address'] for f in request['functions']}:raise ValueError('Missing explicit roots')
    raw=Path(request['source']).read_bytes()
    if sha(raw)!=SHA:raise ValueError('EXE changed')
    image=native.Image(raw);roots=set()
    for address in ROOTS:
        r=image.containing(address)
        if r is None or image.pe.base+image.roots[r][0]!=address:raise ValueError('Unwind root changed')
        roots.add(image.roots[r])
    fragments=native.decode_ranges(image,roots)
    rows={r['address']:r for f in fragments for r in f['instructions']}
    def ref(at,target):
        if rows[at]['mnemonic']!='lea' or rows[at]['rip_references']!=[target]:raise ValueError('Source reference changed')
    def text(at,target,value):
        ref(at,target);o=image.offset(target-image.pe.base);expected=value.encode('utf-16le')+b'\0\0'
        if raw[o:o+len(expected)]!=expected:raise ValueError('Class/package literal changed')
    text(0x143579946,0x148fdb8da,'GridSlot')
    text(0x143579955,0x148fbc818,'/Script/UMG')
    text(0x1435b5226,0x148fdd7aa,'PanelSlot')
    text(0x1435b5235,0x148fbc818,'/Script/UMG')
    ref(0x14357993b,0x14356ab00)
    ref(0x14357b7b0,0x148fdbe50)
    if rows[0x14357b7be]['direct_target']!=0x1417d1b20:raise ValueError('Metadata helper changed')
    leaf=0x14356ab00;o=image.offset(leaf-image.pe.base)
    if image.containing(leaf) is not None or raw[o:o+5]!=bytes.fromhex('e9dba60400') or raw[o+5:o+16]!=b'\xcc'*11:raise ValueError('Leaf thunk boundary changed')
    if leaf+5+struct.unpack_from('<i',raw,o+1)[0]!=0x1435b51e0:raise ValueError('Parent thunk target changed')
    o=image.offset(0x148fdbe50-image.pe.base);metadata=raw[o:o+64]
    if struct.unpack_from('<Q',metadata)[0]!=0x143579900 or struct.unpack_from('<Q',metadata,0x28)[0]!=0x148fdbbf0:raise ValueError('Class/property array metadata link changed')
    return dict(source_sha256=SHA,fragments=fragments,
                metadata=dict(address='0x148fdbe50',sha256=sha(metadata),bytes=metadata.hex(),
                              class_getter_offset=0,property_array_offset=0x28,property_array='0x148fdbbf0'),
                parent_thunk=dict(address=hex(leaf),bytes=raw[image.offset(leaf-image.pe.base):image.offset(leaf-image.pe.base)+16].hex(),target='0x1435b51e0'),
                limits=['Static metadata block ties exact GridSlot getter to descriptor array; helper not executed.',
                        'PanelSlot thunk pointer passed by getter; generic registration helper argument semantics not independently proven.',
                        'Constructor defaults, CDO/archetype copying, Nudge type and cooked compatibility remain unresolved.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();result=inspect(json.loads(a.request.read_bytes()))
    result['inspector_sha256']=sha(Path(__file__).read_bytes());result['request_sha256']=sha(a.request.read_bytes())
    with a.output.open('x',encoding='utf8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(dict(output=str(a.output),fragments=len(result['fragments']),metadata=result['metadata']['address'])))
