"""Decode GridSlot candidates with explicit native descriptor evidence; never choose runtime order."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE_SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
FIELDS=['Padding','HorizontalAlignment','VerticalAlignment','Row','RowSpan','Column','ColumnSpan','Layer','Nudge']
FLAGS=[25,0,0,3,3,3,3,3,25]


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


props=load('grid_props','extract-ui-properties.py')
canvas=load('grid_canvas','decode-canvas-slots.py')
raw_exports=load('grid_exports','inspect-ui.py')


def sha(data):return hashlib.sha256(data).hexdigest()


def decode(raw):
    reader=canvas.Reader(raw)
    fields=FIELDS+['Parent','Content'];result={};explicit=[]
    for index,zero in reader.header():
        if index>=len(fields):raise ValueError('Unknown GridSlot property index')
        name=fields[index]
        if name in result:raise ValueError('Repeated property')
        explicit.append(name)
        if zero:
            result[name]=dict(left=0,top=0,right=0,bottom=0) if index==0 else [0,0] if index==8 else 0
        else:
            result[name]=reader.margin() if index==0 else reader.read('<B') if index in (1,2) else list(reader.read('<dd')) if index==8 else reader.read('<i')
        if index in (1,2) and result[name] not in range(4):raise ValueError('Unknown alignment')
    if reader.read('<I')!=0 or reader.pos!=len(raw):raise ValueError('Unaccounted serialization suffix')
    for name in ['Parent','Content']:
        if result.get(name,0)<=0:raise ValueError('Missing local object link')
    if any(not math.isfinite(v) for v in result.get('Padding',{}).values()):raise ValueError('Invalid margin')
    if any(not math.isfinite(v) for v in result.get('Nudge',[])):raise ValueError('Invalid nudge')
    return dict(explicit_properties=result,serialized_fields=explicit,
                omitted_properties=[name for name in fields if name not in result])


def run(root,exe,class_request=None):
    data=exe.read_bytes()
    if sha(data)!=SOURCE_SHA:raise ValueError('Unreviewed executable SHA')
    schema=props.extract(data,FIELDS,FLAGS,anchor_index=4)
    class_links=None
    if class_request is not None:
        checker=load('grid_class_links','inspect-grid-class-links.py')
        request=json.loads(class_request.read_bytes())
        if request['source_sha256']!=sha(data):raise ValueError('Class proof belongs to another EXE SHA')
        class_links=checker.inspect(request)
        if class_links['metadata']['property_array']!=hex(props.native.PE(data).address(schema['array_offset'])):
            raise ValueError('Class metadata points to a different property array')
    pe=props.native.PE(data)
    if pe.address(schema['array_offset'])!=0x148fdbbf0:raise ValueError('Descriptor array moved; review required')
    records=[];failed=[];cache={}
    index_bytes=(root/'ui-catalog/index.json').read_bytes()
    for entry in json.loads(index_bytes)['windows']:
        file=entry.get('source_file',entry['file'])
        if file in cache:continue
        cache[file]=True
        catalog=json.loads((root/'ui-catalog'/entry['file']).read_bytes())
        base=root/'ui-layout-study'/file.removesuffix('.json')
        asset,body=base.with_suffix('.uasset').read_bytes(),base.with_suffix('.uexp').read_bytes()
        if sha(asset)!=catalog['asset_sha256'] or sha(body)!=catalog['body_sha256']:raise ValueError('Cooked source changed')
        exports=raw_exports.exports(asset,body)['exports'];by_id={e['index']:e for e in exports}
        for e in exports:
            if e['type']!='GridSlot':continue
            proof=dict(file=file,slot_export=e['index'],offset=e['offset'],size=e['size'],sha256=e['sha256'],
                       asset_sha256=sha(asset),body_sha256=sha(body))
            try:
                value=decode(bytes.fromhex(e['serialized_hex']));fields=value['explicit_properties']
                parent,child=by_id[fields['Parent']],by_id[fields['Content']]
                if parent['type']!='GridPanel':raise ValueError('Parent is not GridPanel')
                records.append(dict(source=proof,decoded=value,parent={k:parent[k] for k in ['index','name','type','sha256']},
                                    content={k:child[k] for k in ['index','name','type','sha256']}))
            except (ValueError,KeyError) as error:failed.append(dict(source=proof,error=str(error)))
    return dict(schema=1,kind='grid_slot_candidate_decode',native_source=dict(path=str(exe),sha256=SOURCE_SHA),
                descriptor_schema=schema,array_address='0x148fdbbf0',catalog_index_sha256=sha(index_bytes),
                tools={p:sha((HERE/p).read_bytes()) for p in ['decode-grid-slots.py','extract-ui-properties.py','decode-canvas-slots.py','inspect-ui.py']},
                records=records,failures=failed,class_links=class_links,
                limits=[('Static GridSlot metadata association checked; superclass schema/defaults unresolved.' if class_links else
                         'Descriptor names/types/order verified in current EXE; UGridSlot class association and superclass schema not independently proven.'),
                        'Cooked packages are historical; compatibility with current EXE is not established.',
                        'Parent/Content indices 9/10 are observed candidates checked against exact local exports, not proven inheritance metadata.',
                        'Omissions remain unknown, not Row=0 or Span=1. No row/column/runtime geometry applied.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--exe',type=Path,default=Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--class-request',type=Path,help='Explicit current request for the checked class getter/metadata roots')
    args=parser.parse_args();result=run(args.root,args.exe,args.class_request)
    with args.output.open('x',encoding='utf8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(dict(output=str(args.output),decoded=len(result['records']),failures=len(result['failures']))))
