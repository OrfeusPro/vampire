"""Locate explicitly named current packets through checked instruction boundaries."""
import hashlib
import importlib.util
from pathlib import Path
import json
import struct
import argparse

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def run(packet='PktPingResult', *, source_sha=SHA, record=False):
    if source_sha != SHA:
        raise ValueError('Explicit reviewed source snapshot required')
    if record or packet not in ('PktCharacterLevelUpNotify','PktStatChangeNotify'):
        raise ValueError('Explicit current stat packet required')
    spec=importlib.util.spec_from_file_location('ping_result_native',HERE/'build-native-entry-code.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    spec=importlib.util.spec_from_file_location('ping_result_audit',HERE/'audit-client-release.py')
    audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
    path=native.ROOT/'client-code-snapshots'/source_sha/'ProjectRED-Win64-Shipping.exe'
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=source_sha:raise ValueError('Current source differs')
    image=native.Image(raw)
    literals=[]
    for section in image.pe.sections:
        if section['name']!='.rdata':continue
        start,end=section['raw'],section['raw']+section['raw_size']
        literal_bytes=packet.encode()+b'\0'
        at=raw.find(literal_bytes,start,end)
        while at>=0:
            if not record or at==start or raw[at-1]==0:literals.append(image.pe.address(at))
            at=raw.find(literal_bytes,at+1,end)
    if len(literals)!=1:raise ValueError('Ambiguous literal: '+packet)
    def references(target):
        candidates=native.rip_candidates(image,{target:{}})
        roots={image.roots[f] for at,_ in candidates if (f:=image.containing(at)) is not None}
        fragments=native.decode_ranges(image,roots)
        rows={i['address']:i for f in fragments for i in f['instructions']}
        checked=[dict(instruction=rows[at],owner=hex(image.pe.base+image.roots[image.containing(at)][0]))
            for at,_ in candidates if at in rows and rows[at]['mnemonic']=='lea' and rows[at]['rip_references']==[target]]
        # A constructor can be a short leaf without unwind metadata. Do not guess
        # its start by walking backwards: report the LEA site for explicit review.
        for at,_ in candidates:
            if image.containing(at) is not None:continue
            offset=image.offset(at-image.pe.base)
            decoded=list(native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64).disasm(raw[offset:offset+96],at))
            leaf=[]
            for instruction in decoded:
                leaf.append(dict(address=hex(instruction.address),mnemonic=instruction.mnemonic,
                    operands=instruction.op_str,bytes=instruction.bytes.hex()))
                if instruction.mnemonic=='ret':break
                if instruction.mnemonic not in ('lea','mov','xor'):break
            if leaf and leaf[0]['mnemonic']=='lea' and leaf[-1]['mnemonic']=='ret':
                checked.append(dict(owner=hex(at),leaf_candidate=True,instructions=leaf))
        return checked,fragments
    names,name_fragments=references(literals[0])
    if len(names)!=1:raise ValueError('Ambiguous current name getter')
    getter=int(names[0]['owner'],16);locations=[]
    for section in image.pe.sections:
        if section['name']!='.rdata':continue
        start,end=section['raw'],section['raw']+section['raw_size']
        at=raw.find(struct.pack('<Q',getter),start,end)
        while at>=0:
            if at%8==0:locations.append(at)
            at=raw.find(struct.pack('<Q',getter),at+1,end)
    if len(locations)!=1:raise ValueError('Ambiguous current name slot')
    name_slot=0x28 if record else 0x38
    table=image.pe.address(locations[0]-name_slot)
    slots=struct.unpack_from('<6Q' if record else '<8Q',raw,locations[0]-name_slot)
    if record and not all(any(section['name']=='.text' and image.pe.base+section['rva']<=value<image.pe.base+section['rva']+section['raw_size'] for section in image.pe.sections) for value in slots):
        raise ValueError('Candidate record table contains non-code slots')
    id_bytes=raw[image.offset(slots[5]-image.pe.base):][:6]
    if not record and (len(id_bytes)!=6 or id_bytes[0]!=0xb8 or id_bytes[-1]!=0xc3):
        raise ValueError('Candidate getter '+hex(slots[5])+' is not MOV EAX,imm;RET: '+id_bytes.hex())
    packet_id=None if record else struct.unpack_from('<I',id_bytes,1)[0]
    if not record and (packet_id>65535 or (packet=='PktPingResult' and packet_id!=17)):raise ValueError('Unexpected packet ID')
    ctors,ctor_fragments=references(table)
    expected_id,expected_reader={'PktCharacterLevelUpNotify':(321,0x1456c4b20),'PktStatChangeNotify':(322,0x1456c5a10)}[packet]
    if packet_id!=expected_id or slots[4]!=expected_reader:
        raise ValueError('Current stat ID / reader slot binding differs')
    reviewed=[]
    for item in ctors:
        rows=item.get('instructions',[])
        if (item.get('leaf_candidate') is True and len(rows)>=3
                and rows[0]['mnemonic']=='lea' and rows[0]['operands'].startswith('rax, [rip ')
                and any(row['bytes']=='488901' for row in rows[1:3]) and rows[-1]['bytes']=='c3'
                and all(row['bytes']=='488901' or (row['mnemonic']=='mov' and row['operands'].startswith('byte ptr [rcx + '))
                        for row in rows[1:next(i for i,row in enumerate(rows) if row['bytes']=='488901')+1])):
            start=int(rows[0]['address'],16);lea=bytes.fromhex(rows[0]['bytes'])
            if start+len(lea)+struct.unpack_from('<i',lea,3)[0]!=table:
                raise ValueError('Current stat constructor vptr target differs')
            reviewed.append(item)
    if len(reviewed)!=1:raise ValueError('Expected exact stat leaf constructor vptr store')
    report=dict(source_sha256=source_sha,tool_sha256=audit.sha256(Path(__file__)),
        binding_verified=True,reviewed_constructors=reviewed,reader=hex(expected_reader),
        packet=packet,packet_id=packet_id,literal=hex(literals[0]),literal_bytes=literal_bytes.hex(),name_references=names,
        candidate_table=hex(table),table_bytes=raw[locations[0]-name_slot:locations[0]+8].hex(),
        slots=[hex(a) for a in slots],id_getter_bytes=id_bytes.hex(),constructor_candidates=ctors,
        fragments=name_fragments+ctor_fragments,
        limits=['Name-slot +38, ID slot +28 and reader slot +20 are bound through the exact source vtable and reviewed constructor vptr store.',
            'Exact source SHA and whole-unwind instruction boundaries are checked; no Ghidra analysis or game IO.',
            'Reader semantics are separately established by current whole native replay; handler registration and UI/engine side effects are not established here.'])
    if record:
        report['kind']='record_candidate'
        report['slot5_bytes']=report.pop('id_getter_bytes')
    category='stat-packet-bindings-11318'
    target=audit.save_snapshot(native.ROOT/'code-clues'/category,report)
    return target,report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet',default='PktPingResult')
    parser.add_argument('--source-sha',default=SHA)
    parser.add_argument('--record',action='store_true',help='Discover a named data record without inventing a network packet ID')
    args=parser.parse_args()
    path,r=run(args.packet,source_sha=args.source_sha,record=args.record);print(json.dumps(dict(report=str(path),packet_id=r['packet_id'],table=r['candidate_table'],
        slots=r['slots'],constructors=[v['owner'] for v in r['constructor_candidates']])))
