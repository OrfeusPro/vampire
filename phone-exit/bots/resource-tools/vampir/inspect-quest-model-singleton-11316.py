"""Exact current quest-model global MOV/LEA xrefs; offline navigation only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE=Path(__file__).resolve().parent
SOURCE='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
TARGET=0x14b5e4d60


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    native,audit=load('build-native-entry-code'),load('audit-client-release')
    path=native.ROOT/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe'
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE:raise ValueError('Current EXE differs')
    image=native.Image(raw)
    # The known leaf getter establishes the exact address to search, not its writer.
    getter=0x1455be4b0;offset=image.offset(getter-image.pe.base)
    if raw[offset:offset+8].hex()!='488b05a9680206c3':raise ValueError('Model getter differs')
    candidates=[getter];read_candidates=0
    # Include MOV load/store. The existing rip_candidates helper scans LEA only.
    for section in image.pe.sections:
        if section['name']!='.text':continue
        start,size=section['raw'],section['raw_size'];text=raw[start:start+size]
        for match in re.finditer(rb'[\x48-\x4f][\x89\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]',text):
            at=start+match.start()
            if at+7>start+size:continue
            address=image.pe.address(at)
            if address+7+struct.unpack_from('<i',raw,at+3)[0]!=TARGET:continue
            if raw[at+1]==0x8b:
                read_candidates+=1;continue
            candidates.append(address)
    if len(candidates)>32:raise ValueError('Explicit candidate budget exceeded')
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    rows=[]
    for address in candidates:
        fragment=image.containing(address)
        if fragment:
            root=image.roots[fragment]
            decoded=native.decode_ranges(image,{root},functions=[fragment])[0]
            instruction=next((r for r in decoded['instructions'] if r['address']==address),None)
            if instruction is None or TARGET not in instruction['rip_references']:continue
            boundary='whole_unwind_fragment';root_address=hex(image.pe.base+root[0])
        elif address==getter:
            instruction=dict(address=address,bytes=raw[offset:offset+7].hex(),mnemonic='mov',operands='rax, qword ptr [rip + 0x60268a9]')
            boundary='reviewed_exact_leaf_getter';root_address=None
        else:
            rows.append(dict(address=hex(address),state='unresolved_without_unwind_root'));continue
        ins=next(decoder.disasm(bytes.fromhex(instruction['bytes']),address))
        if ins.mnemonic not in ('mov','lea') or not any(op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP and ins.address+ins.size+op.mem.disp==TARGET for op in ins.operands):
            raise ValueError('Reference decode differs')
        access='address' if ins.mnemonic=='lea' else 'write' if ins.operands[0].type==native.X86_OP_MEM else 'read'
        rows.append(dict(address=hex(address),root=root_address,boundary=boundary,access=access,
            bytes=bytes(ins.bytes).hex(),mnemonic=ins.mnemonic,operands=ins.op_str))
    exports=[];instructions={}
    for run,roots in [('run-55e835912cda',{0x1455ab3c0,0x1455ac490,0x1455b2ce0}),
                      ('run-d9e2c6d1988d',{0x1455b4d40}),('run-dee1f2864d6e',{0x1455f4a80,0x1455fd350})]:
        export=native.ROOT/'ghidra/request-exports'/SOURCE/run/'details.json'
        report=json.loads(export.read_text('utf-8'))
        if report['new_source_sha256']!=SOURCE:raise ValueError('Export source differs')
        functions=[f for f in report['functions'] if int(f['address'],16) in roots]
        if len(functions)!=len(roots):raise ValueError('Explicit model roots missing')
        for function in functions:
            if not function['decompilation_completed'] or not function['block_coverage_complete']:raise ValueError('Incomplete model export')
            for row in function['instructions']:
                at=int(row['address'],16);content=bytes.fromhex(row['bytes']);off=image.offset(at-image.pe.base)
                if raw[off:off+len(content)]!=content:raise ValueError('Model instructions differ')
                instructions[at]=row
        exports.append(dict(path=str(export),sha256=audit.sha256(export),roots=[hex(a) for a in sorted(roots)]))
    anchors={0x1455ab40a:'488d05d7893504',0x1455f4a90:'e8bb880000',0x1455f4a95:'40887b28'}
    for at,content in anchors.items():
        if instructions.get(at,{}).get('bytes')!=content:raise ValueError('Model binding anchor differs')
    # The constructor assigns this table after base initialization. Resolve its
    # exact virtual +0x48 slot rather than searching for an analytically named method.
    ctor=next(f for f in json.loads(Path(exports[0]['path']).read_text('utf-8'))['functions'] if f['address']=='0x1455ab3c0')
    ctor_rows=ctor['instructions'];n=next(i for i,r in enumerate(ctor_rows) if r['address']=='0x1455ab40a')
    if ctor_rows[n+1]['bytes']!='488907':raise ValueError('Final vtable store differs')
    table=0x149903de8;slot=table+0x48
    if struct.unpack_from('<Q',raw,image.offset(slot-image.pe.base))[0]!=0x1455b4d40:raise ValueError('Model virtual slot differs')
    result=dict(source_sha256=SOURCE,tool_sha256=audit.sha256(Path(__file__)),target=hex(TARGET),getter=hex(getter),exports=exports,
        binding=dict(constructor='0x1455ab3c0',vtable=hex(table),virtual_48='0x1455b4d40',
            apply_state='0x1455f4a80',apply_progress='0x1455fd350',state_byte_offset='0x28',task_pointer_offset='0x30'),
        references=rows,read_candidate_count=read_candidates,network_used=False,limits=[
            'Exact RIP-relative qword MOV/LEA candidates only; not all possible indirect accesses or stores.',
            'Read candidates are counted only; writer/address references and the pinned getter are decoded.',
            'Unwind fragments establish instruction boundaries; leaf getter is separately pinned to exact eight bytes.',
            'Static constructor/vtable and state-application route only; factory, virtual task copy and task ordering remain unresolved.',
            'No process memory, game execution, injection, commands or online-session changes.'])
    artifact=audit.save_snapshot(native.ROOT/'code-clues/quest-model-singleton-11316',result)
    return artifact,result


if __name__=='__main__':
    artifact,result=run();print(json.dumps(dict(artifact=str(artifact),references=result['references']),ensure_ascii=False))
