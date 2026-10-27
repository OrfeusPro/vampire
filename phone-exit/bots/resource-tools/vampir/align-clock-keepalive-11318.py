"""Fixed Clock/keepalive context batch: candidate matching only, followed by native checks."""
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
ROOTS=tuple(int(at,16) for at in '1415482f0 14155ffc0 14156acd0 1415da330 1415da870 1445d7cb0 1445d9ed0 144ab2280 145d5d010 1467ab7a0 1467cf680 14561bca0 1456baaf0 1456db410 1456e8280 1456f00c0 145821fb0 1458220f0 14584f120 14584f3d0 14584f4f0 145dafa00 145db2bb0 145db30e0 1467cf320'.split())


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run(root,exports=(),alignment=None):
    native,bindings=load('build-native-entry-code'),load('update-bindings')
    images={}
    for sha in (OLD,NEW):
        raw=(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Clock/keepalive alignment source SHA changed')
        images[sha]=native.Image(raw)
    roots=set(ROOTS)
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
    mapped={}
    if alignment:
        previous=json.loads(Path(alignment).read_text('utf-8'))
        if previous['source_sha256']!=NEW or previous['baseline_sha256']!=OLD:
            raise ValueError('Candidate alignment source differs')
        mapped.update({int(a,16):int(b,16) for a,b in previous['roots'].items()})
    candidates={};unknown={};links={};calls={}
    def add(a,b):links.setdefault(a,set()).add(b)
    def bind(old,new):
        mapped[old]=new;add(old,new)
        for a,b in zip(rows(OLD,old),rows(NEW,new)):
            add(a['address'],b['address'])
            for x,y in zip(a['rip_references'],b['rip_references']):add(x,y)
            if a['direct_target'] is not None:add(a['direct_target'],b['direct_target'])
            if a['call']:calls[a['address']]=(b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
    for old in sorted(roots):
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
    # Identical wrappers are resolved by an already matched native caller,
    # never by choosing the closest address or the first candidate.
    for old_text in list(unknown):
        old=int(old_text,16);referenced=links.get(old,set())
        if len(referenced)==1 and hex(next(iter(referenced))) in candidates.get(old_text,[]):
            bind(old,next(iter(referenced)));del unknown[old_text]
    report=dict(source_sha256=NEW,baseline_sha256=OLD,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        roots={hex(a):hex(b) for a,b in mapped.items()},candidates=candidates,unknown=unknown,
        links={hex(a):[hex(b) for b in sorted(bs)] for a,bs in links.items()},
        semantic_verification=False,network_used=False)
    target=load('research-workflow').snapshot(root,'clock-keepalive-alignment-11318',report)
    return target,report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--alignment',type=Path)
    args=parser.parse_args()
    path,report=run(args.root,alignment=args.alignment)
    print(json.dumps(dict(report=str(path),roots=report['roots'],unknown=report['unknown'])))
