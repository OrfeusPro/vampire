"""Current launcher keys/request/response source guard from existing exports only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
SHA='d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
EXPORTS={
    'run-5e88e50e265d':'8a81049376b63fbb7b476c3381aae08b0f9e325360c73ddf249f2108e3d799b4',
    'run-652644c53992':'fd7a0e84eb9246d0eaa4b57e864eb1e4c99d41609e705a3f4c1e1dd61a9f22ad',
    'run-8b262adbaa98':'6da48cc0ed1312cb30f3141e86f01ea9569ae81b4f08d853c2efca264bd98fcb',
    'run-e3abc26162e7':'0c9394ae43e34f37e6bf092b6788883dee745525de939b4f67c2544703c24d42',
}
REQUESTS=(('launcher/token',0x1444eecd0,0x1444df0b0,0x1444cc4b0,0x144522f90),
          ('launcher/sign-in',0x144503e10,0x1444df1a0,0x1444d3a30,0x144523110))


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def audit(root=None):
    root=Path(root) if root else Path('F:/PhoneExit Resources/Vampir')
    source=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe';raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Launcher source SHA changed')
    native=load('build-native-entry-code');image=native.Image(raw)
    normalizer=load('audit-launcher-shape-11318')
    keys=load('audit-launcher-references-11318').KEYS+load('replay-launcher-result-getters-11318').KEYS
    roots={row[1] for row in keys}|{r[1] for r in REQUESTS}|{r[3] for r in REQUESTS}
    functions={};evidence=[]
    for run,expected in EXPORTS.items():
        path=root/'ghidra/request-exports'/SHA/run/'details.json';data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Launcher export SHA changed')
        document=json.loads(data)
        if document['new_source_sha256']!=SHA:raise ValueError('Launcher export source differs')
        evidence.append(dict(path=str(path),sha256=expected))
        for f in document['functions']:
            at=int(f['address'],16)
            if at in roots:
                if at in functions:raise ValueError('Duplicate launcher root')
                functions[at]=f
    if set(functions)!=roots or len(roots)!=14:raise ValueError('Launcher whole root missing')
    checked={at:normalizer.normalize_function(native,image,f) for at,f in functions.items()}
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    def data(at,size):
        off=image.offset(at-image.pe.base);return raw[off:off+size]
    def matches_literal(at,value):
        try:return data(at,len(value))==value
        except ValueError:return False  # BSS globals cannot contain file literals.
    labels=[]
    for label,entry,literal,global_at in keys:
        proof=checked[entry];refs={int(r['target'],16) for r in proof['references']}
        if not {literal,global_at}<=refs or data(literal,(len(label)+1)*2)!=(label+'\0').encode('utf-16le'):
            raise ValueError('Launcher key literal/global changed')
        arguments={};found=False
        for row in functions[entry]['instructions']:
            ins=next(decoder.disasm(bytes.fromhex(row['bytes']),int(row['address'],16)))
            if ins.mnemonic=='lea' and ins.operands[1].type==native.X86_OP_MEM and ins.operands[1].mem.base==native.X86_REG_RIP:
                arguments[ins.reg_name(ins.operands[0].reg)]=ins.address+ins.size+ins.operands[1].mem.disp
            if ins.mnemonic=='call' and ins.operands[0].type==native.capstone.x86.X86_OP_IMM and ins.operands[0].imm==0x141426b30:
                if arguments.get('rcx')!=global_at or arguments.get('rdx')!=literal:
                    raise ValueError('Launcher key constructor arguments differ')
                found=True
        if not found:raise ValueError('Launcher key constructor absent')
        labels.append(dict(key=label,function=hex(entry),global_address=hex(global_at),literal=hex(literal)))
    requests=[];responses=[]
    for route,entry,callback,target,transport in REQUESTS:
        proof=checked[entry];refs={int(r['target'],16) for r in proof['references']};calls={int(r['target'],16) for r in proof['calls']}
        required={'nmDeviceKey','deviceKey','countryCode','os'}
        required|={'gameCode','buildCode','credential'} if route.endswith('/token') else {'launcherToken'}
        if any(global_at not in refs for label,_,_,global_at in keys if label in required):
            raise ValueError('Launcher request key reference absent')
        if not {callback,0x149530980}<=refs or transport not in calls:
            raise ValueError('Launcher callback/header/transport differs')
        literals=[at for at in refs if matches_literal(at,(route+'\0').encode('utf-16le'))]
        if len(literals)!=1:raise ValueError('Launcher endpoint literal missing or ambiguous')
        jump=data(callback,5)
        if jump[0]!=0xe9 or callback+5+struct.unpack_from('<i',jump,1)[0]!=target:
            raise ValueError('Launcher callback thunk differs')
        requests.append(dict(function=hex(entry),endpoint=route,callback=hex(callback),callback_root=hex(target),
            transport=hex(transport),key_references=sorted(required),header_reference='0x149530980'))
        response=checked[target];refs={int(r['target'],16) for r in response['references']};calls={int(r['target'],16) for r in response['calls']}
        getter,dispatcher=(0x14447d460,0x1444e57f0) if route.endswith('/token') else (0x14447d210,0x1444e6ac0)
        if not {0x14b563da0,0x14b563df0}<=refs or not {getter,dispatcher}<=calls:
            raise ValueError('Launcher result key/getter/dispatcher differs')
        responses.append(dict(function=hex(target),result_getter=hex(getter),dispatcher=hex(dispatcher),direct_sign_up_reference=None))
    return dict(schema=1,source=str(source),source_sha256=SHA,method='static',network_requests=0,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),evidence=evidence,
        keys=labels,requests=requests,responses=responses,
        functions=[dict(address=hex(at),instruction_count=len(checked[at]['shape'])) for at in sorted(roots)],
        limits=['Whole source bytes/blocks, ten initializer argument bindings and two request/response chains checked statically.',
                'Field values, JSON/HTTP execution and callbacks use separate registered native checks; this audit does not execute them.',
                'No real SDK/browser/server acceptance or game protocol proof.'])
