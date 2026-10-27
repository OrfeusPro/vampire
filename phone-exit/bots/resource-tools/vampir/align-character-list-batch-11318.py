"""Fixed CharacterList context batch: candidate matching only, followed by native checks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent
OLD='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NEW='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NAMES=('waiting-end', 'character-list-envelope', 'character-record', 'character-extensions', 'character-list-records', 'character-list-handler')


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run(root,exports=(),alignment=None):
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    images={}
    for sha in (OLD,NEW):
        raw=(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('CharacterList alignment source SHA changed')
        images[sha]=native.Image(raw)
    contexts={name:json.loads((HERE/'knowledge/native-contexts'/(name+'-11316.json')).read_text('utf-8')) for name in NAMES}
    roots=set()
    def gather(value):
        if isinstance(value,dict):
            for k,v in value.items():
                if k=='functions':roots.update(int(at,16) for at in v.values())
                if k in ('prepare','constructor') and isinstance(v,str):roots.add(int(v,16))
                gather(v)
        elif isinstance(value,list):
            for v in value:gather(v)
    for context in contexts.values():gather(context)
    if len(roots)!=40:raise ValueError('Explicit CharacterList root set changed')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    cached={};fragments={}
    for sha,image in images.items():
        fragments[sha]={}
        for part,owner in image.roots.items():fragments[sha].setdefault(owner,[]).append(part)
    def rows(sha,at):
        key=(sha,at)
        if key not in cached:
            try:
                image=images[sha];part=image.containing(at)
                if part is None or image.roots[part][0]+image.pe.base!=at:raise ValueError('Not a root')
                pieces=native.decode_ranges(image,{image.roots[part]},functions=fragments[sha][image.roots[part]])
                cached[key]=[r for piece in pieces for r in piece['instructions']]
            except ValueError:cached[key]=None
        return cached[key]
    def shape(items):
        if items is None:return None
        positions={r['address']:n for n,r in enumerate(items)};result=[]
        for row in items:
            data=bytearray.fromhex(row['bytes']);ins=next(decoder.disasm(data,row['address']));edge=None
            if row['call'] or row['branch']:
                target=row['direct_target']
                if target is not None:
                    edge=('local',positions[target]) if target in positions else ('external',)
                    data[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
            if row['rip_references']:data[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
            result.append((data.hex(),edge))
        return result
    mapped={0x1467cd7b0:0x1467cdc80}
    if alignment:
        previous=json.loads(Path(alignment).read_text('utf-8'))
        if previous['source_sha256']!=NEW or previous['baseline_sha256']!=OLD:
            raise ValueError('Candidate alignment source differs')
        mapped.update({int(a,16):int(b,16) for a,b in previous['roots'].items()})
    candidates={};unknown={};links={};calls={}
    def add(a,b):links.setdefault(a,set()).add(b)
    # The gate has verified inline data and its own source-specific validator.
    gate_old=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11316.json').read_text('utf-8'))
    gate_new=json.loads((HERE/'knowledge/native-contexts/version-result-handler-11318.json').read_text('utf-8'))
    for name in ('gate_state','gate_error'):add(int(gate_old['fixtures'][name],16),int(gate_new['fixtures'][name],16))
    def bind(old,new):
        mapped[old]=new;add(old,new)
        for a,b in zip(rows(OLD,old),rows(NEW,new)):
            add(a['address'],b['address'])
            for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
            if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
            if a['call']:calls[a['address']]=(b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
    for old in sorted(roots-{0x1467cd7b0}):
        expected=shape(rows(OLD,old));hits=[]
        if expected is None:unknown[hex(old)]='Old root is not linearly decodable';continue
        if old in mapped:hits=[mapped[old]] if shape(rows(NEW,mapped[old]))==expected else []
        elif alignment and hex(old) in previous['candidates']:
            hits=[int(at,16) for at in previous['candidates'][hex(old)] if shape(rows(NEW,int(at,16)))==expected]
        else:
            off=images[OLD].offset(old-images[OLD].pe.base);prefix=images[OLD].data[off:off+4]
            for begin,end,unwind in images[NEW].ranges:
                current=begin+images[NEW].pe.base
                if abs(current-old)>0x10000:continue
                part=images[NEW].containing(current)
                if images[NEW].roots[part][0]!=begin:continue
                old_part=images[OLD].containing(old)
                if end-begin!=old_part[1]-old_part[0]:continue
                off=images[NEW].offset(begin)
                if images[NEW].data[off:off+4]!=prefix:continue
                if shape(rows(NEW,current))==expected:hits.append(current)
        candidates[hex(old)]=[hex(at) for at in sorted(set(hits))]
        if len(set(hits))!=1:unknown[hex(old)]='Missing/ambiguous complete instruction/control shape';continue
        bind(old,hits[0])
    # Collection resize wrappers have identical code. Their identities are
    # determined by slots in the actual source-linked callback tables.
    def objects(value):
        if isinstance(value,dict):
            yield value
            for v in value.values():yield from objects(v)
        elif isinstance(value,list):
            for v in value:yield from objects(v)
    for context in contexts.values():
        for item in objects(context):
            for block in item.get('blocks',[]):
                at=int(block['address'],16)
                if len(links.get(at,()))!=1:continue
                size=len(bytes.fromhex(block['bytes']));new=next(iter(links[at]))
                values=[]
                for sha,address in ((OLD,at),(NEW,new)):
                    offset=images[sha].offset(address-images[sha].pe.base)
                    values.append(images[sha].data[offset:offset+size])
                for offset in range(0,size-size%8,8):
                    a,b=(struct.unpack_from('<Q',raw,offset)[0] for raw in values)
                    if a in roots:add(a,b)
    # Identical wrappers are resolved by an already matched native caller,
    # never by choosing the closest address or the first candidate.
    for old_text in list(unknown):
        old=int(old_text,16);referenced=links.get(old,set())
        if len(referenced)==1 and hex(next(iter(referenced))) in candidates.get(old_text,[]):
            bind(old,next(iter(referenced)));del unknown[old_text]
    add(0x1467cd7b0,0x1467cdc80)
    report=dict(source_sha256=NEW,baseline_sha256=OLD,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        roots={hex(a):hex(b) for a,b in mapped.items()},candidates=candidates,unknown=unknown,
        semantic_verification=False,network_used=False)
    target=load('research-workflow').snapshot(root,'character-list-batch-alignment-11318',report)
    return target,report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--alignment',type=Path)
    args=parser.parse_args()
    path,report=run(args.root,alignment=args.alignment)
    print(json.dumps(dict(report=str(path),roots=report['roots'],unknown=report['unknown'])))
