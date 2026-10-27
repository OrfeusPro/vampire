"""Explicit code/data boundary and two-level native switch for one source-bound gate."""
import hashlib
import struct

SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
ENTRY,END,TABLE,INDEX,DISPATCH=0x1467cdc80,0x1467ce097,0x1467ce098,0x1467ce0a8,0x1467cde9d


def rows(native,image,source_sha):
    if source_sha!=SHA:raise ValueError('Unreviewed switch source')
    fragment=image.containing(ENTRY)
    if fragment is None or image.roots[fragment][0]+image.pe.base!=ENTRY or fragment[1]+image.pe.base!=0x1467ce18b:
        raise ValueError('Switch unwind range differs')
    offset=image.offset(ENTRY-image.pe.base);raw=image.data[offset:offset+END-ENTRY]
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    result=[]
    for ins in decoder.disasm(raw,ENTRY):
        refs=[ins.address+ins.size+op.mem.disp for op in ins.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
        branch=ins.group(native.capstone.CS_GRP_JUMP);call=ins.group(native.capstone.CS_GRP_CALL)
        direct=ins.operands[0].imm if (branch or call) and ins.operands and ins.operands[0].type==native.X86_OP_IMM else None
        result.append(dict(address=ins.address,bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,operands=ins.op_str,
            rip_references=refs,call=call,branch=branch,direct_target=direct))
    if sum(len(bytes.fromhex(r['bytes'])) for r in result)!=len(raw) or result[-1]['mnemonic']!='ret':
        raise ValueError('Switch code boundary/gap differs')
    return result


def validate(native,h):
    code=rows(native,h.image,h.sha);actual=next(f for f in h.fragments if int(f['address'],16)==ENTRY)
    if not all(actual.get(k) is True for k in ('decompilation_completed','block_coverage_complete','direct_flow_coverage_complete')):
        raise ValueError('Switch Ghidra coverage incomplete')
    if {int(r['address'],16):r['bytes'] for r in actual['instructions']}!={r['address']:r['bytes'] for r in code}:
        raise ValueError('Switch export code/data separation differs')
    def data(at,size):
        off=h.image.offset(at-h.image.pe.base);return h.raw[off:off+size]
    table,index=data(TABLE,16),data(INDEX,227)
    if hashlib.sha256(table).hexdigest()!='7ac50e5a186878319d6d6ac853c5f3e006f2d98eca064c61198cc403bf958e56':
        raise ValueError('Switch RVA table SHA differs')
    if hashlib.sha256(index).hexdigest()!='80b46077930ed5c4209bac8836c3206d2cea4cc9687597d79612f82100069e54':
        raise ValueError('Switch index table SHA differs')
    targets=[h.image.pe.base+v for v in struct.unpack('<4I',table)]
    if max(index)>3 or any(t not in {r['address'] for r in code} for t in targets):
        raise ValueError('Switch target is outside verified code')
    # Exact dispatch sequence proves the bounds, image base and both table reads.
    sequence=bytes.fromhex('8d83e7faffff3de20000000f87e3010000488d15772183f948980fb68402a8e07c068b8c8298e07c064803caffe1')
    if data(0x1467cde71,len(sequence))!=sequence or data(END,1)!=b'\x90':
        raise ValueError('Switch dispatch/bounds bytes differ')
    local={r['address'] for r in code}
    for row in code:
        if row['branch']:
            if row['direct_target'] is None and row['address']!=DISPATCH:raise ValueError('Unreviewed indirect gate branch')
            if row['direct_target'] is not None and row['direct_target'] not in local:raise ValueError('Gate branch leaves verified code')
    return dict(index_hex=index.hex(),index_sha256=hashlib.sha256(index).hexdigest(),targets=[hex(t) for t in targets],
        dispatch=hex(DISPATCH),code_instructions=len(code),code_end=hex(END),input_first=0x519,input_count=227)
