"""Locate current PingResult through literal and checked instruction boundaries."""
import hashlib
import importlib.util
from pathlib import Path
import json
import struct

HERE=Path(__file__).resolve().parent
SHA='98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def run():
    spec=importlib.util.spec_from_file_location('ping_result_native',HERE/'build-native-entry-code.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    spec=importlib.util.spec_from_file_location('ping_result_audit',HERE/'audit-client-release.py')
    audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
    path=native.ROOT/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Current source differs')
    image=native.Image(raw)
    literals=[]
    for section in image.pe.sections:
        if section['name']!='.rdata':continue
        start,end=section['raw'],section['raw']+section['raw_size']
        at=raw.find(b'PktPingResult\0',start,end)
        while at>=0:
            literals.append(image.pe.address(at));at=raw.find(b'PktPingResult\0',at+1,end)
    if len(literals)!=1:raise ValueError('Ambiguous PingResult literal')
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
    table=image.pe.address(locations[0]-0x38)
    slots=struct.unpack_from('<8Q',raw,locations[0]-0x38)
    id_bytes=raw[image.offset(slots[5]-image.pe.base):][:6]
    if id_bytes!=b'\xb8\x11\x00\x00\x00\xc3':raise ValueError('Candidate getter is not ID17')
    ctors,ctor_fragments=references(table)
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),
        literal=hex(literals[0]),literal_bytes=b'PktPingResult\0'.hex(),name_references=names,
        candidate_table=hex(table),table_bytes=raw[locations[0]-0x38:locations[0]+8].hex(),
        slots=[hex(a) for a in slots],id_getter_bytes=id_bytes.hex(),constructor_candidates=ctors,
        fragments=name_fragments+ctor_fragments,
        limits=['Name-slot displacement 0x38 remains a hypothesis until constructor vptr store is reviewed.',
            'Exact source SHA and whole-unwind instruction boundaries are checked; no Ghidra analysis or game IO.',
            'Reader and handler semantics are not established by names or table candidates.'])
    target=audit.save_snapshot(native.ROOT/'code-clues/release-ping-result-discovery',report)
    return target,report


if __name__=='__main__':
    path,r=run();print(json.dumps(dict(report=str(path),table=r['candidate_table'],
        slots=r['slots'],constructors=[v['owner'] for v in r['constructor_candidates']])))
