"""Fixed SDK/GMC2/NID source/export/code-data guard; no network or runtime changes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def verify(context,root):
    root=Path(root)
    if context['source_sha256']!=SHA:raise ValueError('Unreviewed SDK batch source')
    source=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('SDK batch source changed')
    native=load('build-native-entry-code');image=native.Image(raw)
    roots={int(at,16) for at in context['roots'].values()}
    if len(roots)!=34:raise ValueError('Fixed SDK root set changed')
    functions={};evidence=[]
    for run,digest in context['exports'].items():
        if not run.startswith('run-') or '/' in run or '\\' in run:raise ValueError('SDK export path differs')
        path=root/'ghidra/request-exports'/SHA/run/'details.json';data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('SDK batch export SHA changed')
        document=json.loads(data)
        if document['new_source_sha256']!=SHA:raise ValueError('SDK batch export source differs')
        evidence.append(dict(path=str(path),sha256=digest))
        for function in document['functions']:
            at=int(function['address'],16)
            if at in roots:
                if at in functions:raise ValueError('Duplicate SDK root export')
                functions[at]=function
    if set(functions)!=roots:raise ValueError('SDK batch root export missing')
    shapes=load('audit-launcher-shape-11318');special={int(item['current'],16):item for item in context['switches']}
    if set(special)!={0x144532710,0x1450e3fb0}:raise ValueError('Unreviewed SDK switch roots')
    cases=[]
    for at,function in functions.items():
        if at not in special:
            shapes.normalize_function(native,image,function)
            continue
        item=special[at]
        if (not function['block_coverage_complete'] or not function['direct_flow_coverage_complete']
                or len(function['instructions'])!=item['instructions']):
            raise ValueError('SDK switch code coverage differs')
        code={int(row['address'],16):bytes.fromhex(row['bytes']) for row in function['instructions']}
        decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
        end=at
        for address,data in sorted(code.items()):
            if address!=end:raise ValueError('SDK switch code gap')
            off=image.offset(address-image.pe.base)
            if raw[off:off+len(data)]!=data:raise ValueError('SDK switch instruction differs')
            instructions=list(decoder.disasm(data,address))
            if len(instructions)!=1 or instructions[0].size!=len(data):raise ValueError('SDK switch instruction boundary')
            ins=instructions[0]
            if ins.group(native.capstone.CS_GRP_JUMP) and ins.operands[0].type==native.capstone.x86.X86_OP_IMM:
                if ins.operands[0].imm not in code:raise ValueError('SDK switch direct branch outside code')
            end=address+len(data)
        table=int(item['table'],16);data=bytes.fromhex(item['bytes'])
        off=image.offset(table-image.pe.base)
        if (len(data)!=item['count']*4 or raw[off:off+len(data)]!=data
                or hashlib.sha256(data).hexdigest()!=item['sha256']):raise ValueError('SDK switch table differs')
        part=image.containing(at)
        if part is None or image.roots[part][0]+image.pe.base!=at:raise ValueError('SDK switch unwind root differs')
        # Only one padding byte separates the last native RET and each table.
        if table-end!=1 or raw[image.offset(end-image.pe.base)] not in (0x90,0xcc):
            raise ValueError('SDK switch code/data padding differs')
        if table+len(data)!=image.pe.base+part[1]:raise ValueError('SDK switch table/unwind extent differs')
        for index,rva in enumerate(struct.unpack('<'+'I'*item['count'],data)):
            target=image.pe.base+rva
            if target not in code:raise ValueError('SDK switch table target outside code')
            cases.append(dict(root=hex(at),index=index,target=hex(target)))
    for name,digest in context['generated_files'].items():
        path=HERE/name
        if path.name!=name or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('SDK generated replay changed')
    return dict(source_sha256=SHA,roots=sorted(hex(at) for at in roots),switch_cases=cases,
                evidence=evidence,network_used=False,profile_activated=False)
