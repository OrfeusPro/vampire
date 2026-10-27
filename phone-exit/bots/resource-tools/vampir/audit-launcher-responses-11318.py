"""Complete response shapes with identity-checked indirect CRT calls; no HTTP or execution."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
EXPORTS=(
    ('d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960','run-aa8c16b9c37f',
     '68a258e1f298e7e607337b366ef673deb7af1fece47a33bf24442fbc9647cd0e',(0x1444cc1b0,0x1444d3730)),
    ('d30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c','run-e3abc26162e7',
     '0c9394ae43e34f37e6bf092b6788883dee745525de939b4f67c2544703c24d42',(0x1444cc4b0,0x1444d3a30)))


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run():
    normalizer=load('audit-launcher-shape-11318');native=load('build-native-entry-code')
    imports=load('build-object-zero-init-code');audit=load('audit-client-release')
    versions=[];evidence=[]
    for sha,run_id,expected,addresses in EXPORTS:
        raw=(native.ROOT/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:raise ValueError('Response source changed')
        image=native.Image(raw);path=native.ROOT/'ghidra/request-exports'/sha/run_id/'details.json'
        if audit.sha256(path)!=expected:raise ValueError('Response export changed')
        export=json.loads(path.read_text('utf-8'))
        if export['new_source_sha256']!=sha:raise ValueError('Response export source differs')
        functions={int(f['address'],16):f for f in export['functions']}
        decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);decoder.detail=True
        checked=[]
        for entry in addresses:
            function=functions[entry]
            result=normalizer.normalize_function(native,image,function,legacy=sha==EXPORTS[0][0])
            imported=[];shape=[]
            for offset,encoded,edge in result['shape']:
                at=entry+offset
                if edge and edge[0]=='indirect':
                    row=next(r for r in function['instructions'] if int(r['address'],16)==at)
                    ins=next(decoder.disasm(bytes.fromhex(row['bytes']),at))
                    if ins.mnemonic=='call' and len(ins.operands)==1 and ins.operands[0].type==native.X86_OP_MEM and ins.operands[0].mem.base==native.X86_REG_RIP:
                        slot=ins.address+ins.size+ins.operands[0].mem.disp
                        identity=imports.import_at(raw,image,slot)
                        if (identity['dll'].lower(),identity['name'])!=('api-ms-win-crt-convert-l1-1-0.dll','_wtoi'):
                            raise ValueError('Unexpected indirect response import')
                        edge=('import',identity['dll'].lower(),identity['name'])
                        imported.append(dict(offset=offset,identity=identity))
                shape.append((offset,encoded,edge))
            if len(imported)!=1:raise ValueError('Response indirect import coverage changed')
            result.update(shape=shape,imports=imported);checked.append(result)
        versions.append(checked);evidence.append(dict(path=str(path),sha256=expected))
    pairs=[]
    for i,route in enumerate(('launcher/token','launcher/sign-in')):
        old,new=versions[0][i],versions[1][i]
        if old['shape']!=new['shape']:raise ValueError('Response complete shape/local edges changed')
        refs={int(r['target'],16) for r in new['references']}
        calls={int(c['target'],16) for c in new['calls']}
        getter,dispatcher=(0x14447d460,0x1444e57f0) if i==0 else (0x14447d210,0x1444e6ac0)
        if not {0x14b563da0,0x14b563df0}<=refs or not {getter,dispatcher}<=calls:
            raise ValueError('Response key/getter/dispatch reference changed')
        pairs.append(dict(route=route,old=hex(EXPORTS[0][3][i]),current=hex(EXPORTS[1][3][i]),
            instructions=len(new['shape']),shape_equal=True,imports=[old['imports'],new['imports']],
            key_global_references=['0x14b563da0','0x14b563df0'],result_getter=hex(getter),dispatcher=hex(dispatcher),
            external_calls=[dict(old=a,current=b) for a,b in zip(old['calls'],new['calls'])],
            data_references=[dict(old=a,current=b) for a,b in zip(old['references'],new['references'])]))
    report=dict(source_sha256=EXPORTS[1][0],baseline_sha256=EXPORTS[0][0],tool_sha256=audit.sha256(Path(__file__)),
        exports=evidence,pairs=pairs,network_used=False,native_execution=False,profile_activation=False,
        compatibility='not_established',limits=['Complete response instruction/local-edge shapes and CRT import identity checked statically.',
            'Key references/getter/dispatch calls are not execution or response acceptance. External implementations, active context, JSON field values and transport remain unverified.'])
    target=audit.save_snapshot(native.ROOT/'code-clues/launcher-responses-11318',report)
    return target,report


if __name__=='__main__':
    path,result=run();print(json.dumps(dict(artifact=str(path),functions=len(result['pairs']))))
