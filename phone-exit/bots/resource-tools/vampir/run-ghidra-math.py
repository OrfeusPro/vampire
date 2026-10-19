"""Pinned Ghidra body discovery for two assembly math helpers, with source hashes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import uuid

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('math_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)


def main():
    root=native.ROOT
    manifest=json.loads((root/'ghidra/entry-manifest.json').read_text('utf-8'))
    raw=Path(manifest['source']).read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!=manifest['source_sha256']:raise ValueError('Client changed before math discovery')
    lock=json.loads((HERE/'ghidra-tools.lock.json').read_text('utf-8'));tools=root/'tools/ghidra'
    for name in ('ghidra','jdk'):
        if json.loads((tools/lock[name]['directory']/'.phoneexit-verified.json').read_text('utf-8'))!=lock[name]:
            raise ValueError('Use pinned Ghidra/JDK tools')
    out=root/'ghidra'/('math-'+digest[:12])/('run-'+uuid.uuid4().hex[:12]);out.mkdir(parents=True)
    env=os.environ.copy();env['JAVA_HOME']=str(tools/lock['jdk']['directory']);env['GHIDRA_HEADLESS_MAXMEM']='2G'
    env['GHIDRA_HEADLESS_JAVA_OPTIONS']='-Duser.home='+(HERE.parents[2]/'.tools/vampir-ghidra-home').as_posix()
    script=HERE/'ExportVampirMath.java';script_digest=hashlib.sha256(script.read_bytes()).hexdigest()
    command=[str(tools/lock['ghidra']['directory']/'support/analyzeHeadless.bat'),str(root/'ghidra/projects'),
        'Vampir_'+digest[:12],'-process',Path(manifest['source']).name,'-noanalysis','-max-cpu','2',
        '-scriptPath',str(HERE),'-postScript',script.name,digest,str(out)]
    log=out/'headless-export.log';print(json.dumps(dict(output=str(out),log=str(log))),flush=True)
    with log.open('w',encoding='utf-8') as stream:result=subprocess.run(command,env=env,stdout=stream,stderr=subprocess.STDOUT)
    if result.returncode:raise ValueError('Math export failed; inspect '+str(log))
    if hashlib.sha256(script.read_bytes()).hexdigest()!=script_digest:raise ValueError('Math exporter changed during discovery')
    report=json.loads((out/'functions.json').read_text('utf-8'))
    if report['source_sha256']!=digest or len(report['functions'])!=2:raise ValueError('Incomplete math export')
    image=native.Image(raw);ranges=[]
    for function in report['functions']:
        if not function['completed']:raise ValueError('Incomplete math function')
        for r in function['ranges']:
            start,end=int(r['start'],16),int(r['end_exclusive'],16)
            if not 0<end-start<=65536:raise ValueError('Math function range bound')
            off=image.offset(start-image.pe.base);data=raw[off:off+end-start]
            ranges.append(dict(name=function['name'],start=start,end=end,file_offset=off,sha256=hashlib.sha256(data).hexdigest()))
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.suffix in ('.c','.json')}
    provenance=dict(source_sha256=digest,source=manifest['source'],script_sha256=script_digest,
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),tools=lock,files=files,ranges=ranges)
    (out/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
    latest=dict(output=str(out),source_sha256=digest,provenance_sha256=hashlib.sha256((out/'provenance.json').read_bytes()).hexdigest())
    (root/'ghidra/latest-math.json').write_text(json.dumps(latest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(output=str(out),ranges=len(ranges))))


if __name__=='__main__':main()
