"""Source-only binding of launcher key labels, request references and callback thunks."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
KEYS = (
    ('buildCode',0x1411b0170,0x14952cbe8,0x14b563cb0),
    ('countryCode',0x1411b0260,0x14952cd88,0x14b563d70),
    ('credential',0x1411b0290,0x14952ccb8,0x14b563d20),
    ('deviceKey',0x1411b02f0,0x14952cc88,0x14b563d00),
    ('gameCode',0x1411b03e0,0x14952cbd0,0x14b563ca0),
    ('launcherToken',0x1411b04a0,0x14952cc68,0x14b563cf0),
    ('nmDeviceKey',0x1411b04d0,0x14952cca0,0x14b563d10),
    ('os',0x1411b0500,0x14952cda0,0x14b563d80),
)


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    shapes=load('audit-launcher-shape-11318'); _, comparison=shapes.run()
    native=load('build-native-entry-code');audit=load('audit-client-release')
    sha=shapes.SOURCES[1][0]
    raw=(native.ROOT/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Launcher key source changed')
    image=native.Image(raw)
    context=json.loads((HERE/'knowledge/native-contexts/launcher-references-11318.json').read_text('utf-8'))
    path=native.ROOT/'ghidra/request-exports'/sha/context['run']/'details.json'
    if audit.sha256(path)!=context['sha256']:raise ValueError('Launcher key export changed')
    exported=json.loads(path.read_text('utf-8'))
    if exported['new_source_sha256']!=sha:raise ValueError('Launcher key export source differs')
    functions={int(f['address'],16):f for f in exported['functions']}
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
    keys=[]
    for label,entry,literal,global_at in KEYS:
        function=functions[entry]
        checked=shapes.normalize_function(native,image,function)
        refs={int(r['target'],16) for r in checked['references']}
        if not {literal,global_at}<=refs:raise ValueError('Launcher key label/global references differ')
        off=image.offset(literal-image.pe.base);data=(label+'\0').encode('utf-16le')
        if raw[off:off+len(data)]!=data:raise ValueError('Launcher key literal changed')
        calls={int(c['target'],16) for c in checked['calls']}
        if 0x141426b30 not in calls or 0x1487e976c not in calls:
            raise ValueError('Launcher key string initialization/cleanup registration differs')
        # Verify argument registers at the actual string initialization call.
        rows=function['instructions'];call_index=next(i for i,r in enumerate(rows)
            if bytes.fromhex(r['bytes'])[:1]==b'\xe8' and
            int(r['address'],16)+5+struct.unpack('<i',bytes.fromhex(r['bytes'])[1:])[0]==0x141426b30)
        args={}
        for row in rows[:call_index]:
            ins=next(decoder.disasm(bytes.fromhex(row['bytes']),int(row['address'],16)))
            if ins.mnemonic=='lea' and len(ins.operands)==2 and ins.operands[1].type==native.X86_OP_MEM and ins.operands[1].mem.base==native.X86_REG_RIP:
                args[ins.reg_name(ins.operands[0].reg)]=ins.address+ins.size+ins.operands[1].mem.disp
        if args.get('rcx')!=global_at or args.get('rdx')!=literal:raise ValueError('Launcher key constructor arguments differ')
        keys.append(dict(key=label,initializer=hex(entry),literal=hex(literal),global_address=hex(global_at)))
    requests=[]
    for pair,callback,target,transport in zip(comparison['pairs'],
        (0x1444df0b0,0x1444df1a0),(0x1444cc4b0,0x1444d3a30),(0x144522f90,0x144523110)):
        refs={int(r['current']['target'],16) for r in pair['data_references']}
        calls={int(r['current']['target'],16) for r in pair['external_calls']}
        required={'nmDeviceKey','deviceKey','countryCode','os'}
        required|={'gameCode','buildCode','credential'} if pair['route']=='launcher/token' else {'launcherToken'}
        if any(global_at not in refs for label,_,_,global_at in KEYS if label in required):
            raise ValueError('Launcher request key-global reference absent')
        if callback not in refs or 0x149530980 not in refs or transport not in calls:
            raise ValueError('Launcher callback/header/transport reference absent')
        off=image.offset(callback-image.pe.base);jump=raw[off:off+5]
        if jump[0]!=0xe9 or callback+5+struct.unpack_from('<i',jump,1)[0]!=target:
            raise ValueError('Launcher callback tail target changed')
        requests.append(dict(route=pair['route'],function=pair['current'],key_references=sorted(required),
            callback=hex(callback),callback_bytes=jump.hex(),callback_target=hex(target),transport=hex(transport),
            header_reference='0x149530980'))
    report=dict(source_sha256=sha,tool_sha256=audit.sha256(Path(__file__)),
        context_sha256=audit.sha256(HERE/'knowledge/native-contexts/launcher-references-11318.json'),
        exports=comparison['exports']+[dict(path=str(path),sha256=audit.sha256(path))],keys=keys,requests=requests,
        network_used=False,profile_activation=False,compatibility='not_established',
        limits=['Static references/initializer register arguments and exact callback E9 only; request field value provenance and serialization not executed.',
                'Callback targets, header usage and transport implementations remain unverified; no response parsing, SDK state or live auth.'])
    target=audit.save_snapshot(native.ROOT/'code-clues/launcher-references-11318',report)
    return target,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),keys=len(result['keys']),requests=len(result['requests']))))
