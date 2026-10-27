"""Explicit 1.13.20 code/data boundary and two-level result-gate switch.

Callers verify the complete EXE SHA before creating the image/harness. This
module checks the declared code, data tables and dispatch on that source only;
it does not grant runtime admission or model the external service effects.
"""
import hashlib
import struct

SHA='544ef516fb168caaac13d2072ef02393d69407e964b0d8f338d50ded5cf3804c'
ENTRY,END,TABLE,INDEX,DISPATCH=0x1467d0c60,0x1467d1077,0x1467d1078,0x1467d1088,0x1467d0e7d
UNWIND_END=0x1467d116b
TABLE_SHA='5429c703d32b27e2560601367105386ad43b12ff46ddfb79a8444f97359265c7'
INDEX_SHA='80b46077930ed5c4209bac8836c3206d2cea4cc9687597d79612f82100069e54'
DISPATCH_START=0x1467d0e51
DISPATCH_BYTES=bytes.fromhex('8d83e7faffff3de20000000f87e3010000488d1597f182f948980fb6840288107d068b8c8278107d064803caffe1')


def rows(native,image,source_sha):
    if source_sha!=SHA:raise ValueError('Unreviewed switch source')
    fragment=image.containing(ENTRY)
    if fragment is None or image.roots[fragment][0]+image.pe.base!=ENTRY or fragment[1]+image.pe.base!=UNWIND_END:
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
    if hashlib.sha256(table).hexdigest()!=TABLE_SHA:
        raise ValueError('Switch RVA table SHA differs')
    if hashlib.sha256(index).hexdigest()!=INDEX_SHA:
        raise ValueError('Switch index table SHA differs')
    targets=[h.image.pe.base+v for v in struct.unpack('<4I',table)]
    if max(index)>3 or any(t not in {r['address'] for r in code} for t in targets):
        raise ValueError('Switch target is outside verified code')
    # The exact sequence proves the range guard, image base, indexed byte/RVA
    # reads and final dispatch. Indexed displacements are not ordinary RIP refs.
    if data(DISPATCH_START,len(DISPATCH_BYTES))!=DISPATCH_BYTES or data(END,1)!=b'\x90':
        raise ValueError('Switch dispatch/bounds bytes differ')
    local={r['address'] for r in code}
    for row in code:
        if row['branch']:
            if row['direct_target'] is None and row['address']!=DISPATCH:raise ValueError('Unreviewed indirect gate branch')
            if row['direct_target'] is not None and row['direct_target'] not in local:raise ValueError('Gate branch leaves verified code')
    return dict(index_hex=index.hex(),index_sha256=hashlib.sha256(index).hexdigest(),targets=[hex(t) for t in targets],
        dispatch=hex(DISPATCH),code_instructions=len(code),code_end=hex(END),input_first=0x519,input_count=227)
