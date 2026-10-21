"""Discover three explicitly requested current math helpers; no legacy pointer mutation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import uuid

HERE=Path(__file__).resolve().parent
SOURCE_SHA='98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
ENTRIES={'0x14144a8e0','0x1414458e0','0x1487eb5e0'}


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def run(request_path,comparison):
    native=load('release_math_native',HERE/'build-native-entry-code.py')
    workflow=load('release_math_workflow',HERE/'research-workflow.py')
    request=json.loads(request_path.read_text('utf-8'))
    if digest(request_path)!=request_path.parent.name or request['source_sha256']!=SOURCE_SHA:
        raise ValueError('Expected immutable current-source request')
    if not ENTRIES <= {f['address'] for f in request['functions']}:
        raise ValueError('Math helpers must belong to the explicit request')
    receipt_path=comparison/'provenance.json'
    receipt=json.loads(receipt_path.read_text('utf-8'))
    source=Path(receipt['new_source'])
    if receipt['new_source_sha256']!=SOURCE_SHA or digest(source)!=SOURCE_SHA:
        raise ValueError('Current math source changed')
    if request['require_installed_match']:
        installed=Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
        if digest(installed)!=SOURCE_SHA:raise ValueError('Installed client changed')
    root=native.ROOT;lock=json.loads((HERE/'ghidra-tools.lock.json').read_text('utf-8'))
    tools=root/'tools/ghidra'
    for name in ('ghidra','jdk'):
        if json.loads((tools/lock[name]['directory']/'.phoneexit-verified.json').read_text('utf-8'))!=lock[name]:
            raise ValueError('Pinned math tooling required')
    script=HERE/'ExportVampirReleaseMath.java'
    inputs={str(p):digest(p) for p in (Path(__file__),script,request_path,receipt_path)}
    with workflow.locked(root,'research'),workflow.locked(root,'ghidra'):
        out=comparison/'math'/('run-'+uuid.uuid4().hex[:12]);out.mkdir(parents=True)
        env=os.environ.copy();env['JAVA_HOME']=str(tools/lock['jdk']['directory'])
        env['GHIDRA_HEADLESS_MAXMEM']='2G'
        env['GHIDRA_HEADLESS_JAVA_OPTIONS']='-Duser.home='+(HERE.parents[2]/'.tools/vampir-ghidra-home').as_posix()
        command=[str(tools/lock['ghidra']['directory']/'support/analyzeHeadless.bat'),
            receipt['command'][1],'NewRelease','-process',source.name,'-noanalysis','-max-cpu','2',
            '-scriptPath',str(HERE),'-postScript',script.name,SOURCE_SHA,str(out)]
        print(json.dumps(dict(output=str(out))),flush=True)
        with (out/'headless.log').open('w',encoding='utf-8') as stream:
            result=subprocess.run(command,env=env,stdout=stream,stderr=subprocess.STDOUT)
        if result.returncode:raise ValueError('Math discovery failed; inspect '+str(out/'headless.log'))
        if any(digest(Path(p))!=sha for p,sha in inputs.items()):raise ValueError('Math inputs changed during discovery')
        report=json.loads((out/'functions.json').read_text('utf-8'))
        if report['source_sha256']!=SOURCE_SHA or len(report['functions'])!=3:
            raise ValueError('Incomplete current math report')
        if {f['address'].lower() for f in report['functions']}!=ENTRIES:
            raise ValueError('Unexpected math entries')
        raw=source.read_bytes();image=native.Image(raw);ranges=[]
        for function in report['functions']:
            if not function['completed']:raise ValueError('Math decompilation incomplete')
            for r in function['ranges']:
                start,end=int(r['start'],16),int(r['end_exclusive'],16)
                if not 0<end-start<=65536:raise ValueError('Math range outside explicit budget')
                off=image.offset(start-image.pe.base)
                ranges.append(dict(name=function['name'],start=start,end=end,file_offset=off,
                    sha256=hashlib.sha256(raw[off:off+end-start]).hexdigest()))
        files={p.name:digest(p) for p in out.iterdir() if p.suffix in ('.c','.json')}
        provenance=dict(source_sha256=SOURCE_SHA,source=str(source),inputs=inputs,tools=lock,
            command=command,files=files,ranges=ranges,native_execution=False,
            limits=['Only three explicit math entries; Ghidra flow discovery, not native behavioral proof.',
                'Old math exports and latest pointers remain unchanged.'])
        path=out/'provenance.json'
        path.write_bytes(workflow.canonical(provenance))
        return dict(report=str(path),sha256=digest(path),ranges=len(ranges))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--comparison',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(run(args.request,args.comparison)))
