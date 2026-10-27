"""Find bounded stat-function candidates; no semantic admission, exports or game IO."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
OLD='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NEW='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
ROOTS=(0x1456c4740,0x1456c5630,0x1456c6690,0x1457a8030,0x145734dd0,
       0x14573d240,0x1457a7f70,0x145d8b830,0x145d8b8d0,0x1455f0130)
AUXILIARY_ROOTS=(0x145787640,)  # PktCharacter reader -> initial-stat collection callsite.
WINDOW=0x10000
# The existing 1.13.16 whole-reader proofs establish callback-table slot +16.
# Each old table value is checked before using the independently matched callback.
CALLBACK_TABLES={0x1456c4740:0x1456c6690,0x145734dd0:0x14573d240}


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def instruction_shape(rows,decoder):
    """Keep immediate values/local topology, normalize external edges and RIP displacement."""
    positions={row['address']:index for index,row in enumerate(rows)}
    result=[]
    for row in rows:
        raw=bytearray.fromhex(row['bytes'])
        instructions=list(decoder.disasm(raw,row['address']))
        if len(instructions)!=1 or instructions[0].size!=len(raw):
            raise ValueError('Exactly one complete decoded instruction required')
        instruction=instructions[0];edge=None
        if row['call'] or row['branch']:
            target=row['direct_target']
            if target is not None:
                edge=('local',positions[target]) if target in positions else ('external',)
                raw[instruction.imm_offset:instruction.imm_offset+instruction.imm_size]=bytes(instruction.imm_size)
        if row['rip_references']:
            raw[instruction.disp_offset:instruction.disp_offset+instruction.disp_size]=bytes(instruction.disp_size)
        result.append((raw.hex(),edge))
    return result


def select_candidates(candidates):
    """Never resolve ambiguity by distance or list order."""
    roots={};unknown={}
    for old,values in candidates.items():
        values=sorted(set(values))
        if len(values)==1:roots[old]=values[0]
        else:unknown[old]='Missing/ambiguous complete instruction/control shape'
    return roots,unknown


def callback_candidates(old_rows,candidate_rows,old_callback,new_callback,old_word,new_word):
    """Constrain shape matches by exact source-linked callback slots, never proximity."""
    sites=[]
    for index,row in enumerate(old_rows):
        if row['mnemonic']!='lea':continue
        for reference,table in enumerate(row['rip_references']):
            try:callback=old_word(table+16)
            except ValueError:continue
            if callback==old_callback:sites.append((index,reference,table))
    if not sites:return sorted(candidate_rows),[]
    hits=[];proofs=[]
    for address,rows in candidate_rows.items():
        bindings=[]
        for index,reference,table in sites:
            if index>=len(rows) or reference>=len(rows[index]['rip_references']):break
            current_table=rows[index]['rip_references'][reference]
            try:callback=new_word(current_table+16)
            except ValueError:break
            if callback!=new_callback:break
            bindings.append(dict(old_instruction=hex(old_rows[index]['address']),
                new_instruction=hex(rows[index]['address']),old_table=hex(table),
                new_table=hex(current_table),slot_offset=16,
                old_callback=hex(old_callback),new_callback=hex(new_callback)))
        else:
            hits.append(address);proofs.append(dict(candidate=address,bindings=bindings))
    return sorted(hits),proofs


def estat_rows(enums,rejected):
    if any(row.get('enum')=='EStat' for row in rejected):raise ValueError('Ambiguous EStat descriptor arrays')
    rows=enums.get('EStat')
    if not isinstance(rows,list) or not rows:raise ValueError('Missing current EStat descriptor array')
    names={};values=set()
    for row in rows:
        name,value=row['name'],row['value']
        if (not isinstance(name,str) or not name.startswith('EStat::') or type(value) is not int
                or name in names or value in values):raise ValueError('Duplicate or invalid EStat descriptor')
        names[name]=value;values.add(value)
    required={'EStat::Level':3,'EStat::Hp':4,'EStat::MaxHp':5,'EStat::Mp':9,'EStat::MaxMp':10}
    return rows,all(names.get(name)==value for name,value in required.items())


def run(root,*,extract_estat=False):
    native=load('build-native-entry-code');workflow=load('research-workflow')
    images={};fragments={}
    for sha in (OLD,NEW):
        path=root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Stat alignment source SHA changed')
        images[sha]=native.Image(raw);fragments[sha]={}
        for fragment,owner in images[sha].roots.items():fragments[sha].setdefault(owner,[]).append(fragment)
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    cached={}
    def rows(sha,address):
        key=(sha,address)
        if key not in cached:
            image=images[sha];part=image.containing(address)
            if part is None or image.roots[part][0]+image.pe.base!=address:
                raise ValueError('Stat candidate must be an exact unwind root')
            pieces=native.decode_ranges(image,{image.roots[part]},functions=fragments[sha][image.roots[part]])
            cached[key]=[row for piece in pieces for row in piece['instructions']]
        return cached[key]
    candidates={};decode_errors={};signatures={}
    for old in ROOTS+AUXILIARY_ROOTS:
        text=hex(old)
        try:expected=instruction_shape(rows(OLD,old),decoder)
        except ValueError:
            candidates[text]=[];decode_errors[text]='Old root is not completely decodable';continue
        old_part=images[OLD].containing(old);old_offset=images[OLD].offset(old-images[OLD].pe.base)
        prefix=images[OLD].data[old_offset:old_offset+4];hits=[]
        for begin,end,unwind in images[NEW].ranges:
            current=begin+images[NEW].pe.base
            if abs(current-old)>WINDOW or end-begin!=old_part[1]-old_part[0]:continue
            part=images[NEW].containing(current)
            if images[NEW].roots[part][0]!=begin:continue
            offset=images[NEW].offset(begin)
            if images[NEW].data[offset:offset+4]!=prefix:continue
            try:matched=instruction_shape(rows(NEW,current),decoder)==expected
            except ValueError:continue
            if matched:hits.append(hex(current))
        candidates[text]=sorted(set(hits))
        signatures[text]=dict(instructions=len(expected),
            shape_sha256=hashlib.sha256(json.dumps(expected,separators=(',',':')).encode()).hexdigest())
    roots,unknown=select_candidates(candidates);unknown.update(decode_errors)
    constrained={};callback_proofs={}
    def word(sha,address):
        image=images[sha];offset=image.offset(address-image.pe.base)
        if offset+8>len(image.data):raise ValueError('Callback slot outside source')
        return struct.unpack_from('<Q',image.data,offset)[0]
    for old,callback in CALLBACK_TABLES.items():
        old_text=hex(old)
        if old_text not in unknown or hex(callback) not in roots:continue
        available={address:rows(NEW,int(address,16)) for address in candidates[old_text]}
        hits,proofs=callback_candidates(rows(OLD,old),available,callback,int(roots[hex(callback)],16),
            lambda address:word(OLD,address),lambda address:word(NEW,address))
        constrained[old_text]=hits;callback_proofs[old_text]=proofs
        if len(hits)==1:
            roots[old_text]=hits[0];del unknown[old_text]
    links={};root_proofs={}
    def link(old,new):links.setdefault(hex(old),set()).add(hex(new))
    for old_text,new_text in roots.items():
        old,new=int(old_text,16),int(new_text,16)
        before,after=rows(OLD,old),rows(NEW,new)
        root_proofs[old_text]=dict(new_address=new_text,**signatures[old_text],
            old_bytes_sha256=hashlib.sha256(b''.join(bytes.fromhex(row['bytes']) for row in before)).hexdigest(),
            new_bytes_sha256=hashlib.sha256(b''.join(bytes.fromhex(row['bytes']) for row in after)).hexdigest())
        for a,b in zip(before,after):
            link(a['address'],b['address'])
            if a['direct_target'] is not None:link(a['direct_target'],b['direct_target'])
            for x,y in zip(a['rip_references'],b['rip_references']):link(x,y)
    report=dict(schema=1,source_sha256=NEW,baseline_sha256=OLD,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        root_scope=[hex(root) for root in ROOTS],auxiliary_root_scope=[hex(root) for root in AUXILIARY_ROOTS],
        search_window=WINDOW,roots=roots,candidates=candidates,
        unknown=unknown,proofs=root_proofs,callback_candidates=constrained,
        callback_bindings=callback_proofs,links={a:sorted(b) for a,b in sorted(links.items())},
        semantic_verification=False,native_replay_verified=False,network_used=False,profile_activated=False,
        limits=['Whole unwind-fragment instruction/control shape candidates only; external callees and RIP targets remain unproven.',
                'No new Ghidra export, game request, process-memory read or runtime decoder admission.',
                'PktCharacter initial-stat callsite binding, packet registration and fresh native cases remain required.'])
    path=workflow.snapshot(root,'stat-batch-alignment-11318',report)
    enum_path=None;enum_report=None
    if extract_estat:
        extractor=load('extract-native-enums');enums,rejected=extractor.extract(images[NEW].data)
        selected,known_vitals=estat_rows(enums,rejected)
        enum_report=dict(schema=1,source_sha256=NEW,
            tool_sha256=hashlib.sha256((HERE/'extract-native-enums.py').read_bytes()).hexdigest(),
            producer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            enums={'EStat':selected},known_vital_ids_match=known_vitals,network_used=False,
            limits=['Contiguous native pointer/int64 descriptors; no runtime stat reader/apply or display admission.'])
        enum_path=workflow.snapshot(root,'stat-enums-11318',enum_report)
    return path,report,enum_path,enum_report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--extract-estat',action='store_true')
    args=parser.parse_args();path,report,enum_path,enum_report=run(args.root,extract_estat=args.extract_estat)
    print(json.dumps(dict(report=str(path),roots=report['roots'],unknown=report['unknown'],
        estat_report=str(enum_path) if enum_path else None,
        estat_members=len(enum_report['enums']['EStat']) if enum_report else None)))
