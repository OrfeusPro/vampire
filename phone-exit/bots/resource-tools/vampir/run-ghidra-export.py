"""Run pinned Ghidra in a separate resource project, never execute the client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES','F:/PhoneExit Resources/Vampir'))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--reuse',action='store_true')
    args=parser.parse_args()
    lock=json.loads((HERE/'ghidra-tools.lock.json').read_text('utf-8'))
    manifest_path=ROOT/'ghidra/entry-manifest.json';manifest=json.loads(manifest_path.read_text('utf-8'))
    with Path(manifest['source']).open('rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
    if digest!=manifest['source_sha256']:raise ValueError('Client changed; regenerate manifest first')
    tools=ROOT/'tools/ghidra'
    for name in ('ghidra','jdk'):
        marker=tools/lock[name]['directory']/'.phoneexit-verified.json'
        if json.loads(marker.read_text('utf-8'))!=lock[name]:raise ValueError('Install pinned tools first')
    work=ROOT/'ghidra';projects=work/'projects';projects.mkdir(exist_ok=True)
    project='Vampir_'+digest[:12]
    out=work/('export-'+digest[:12])/('run-'+uuid.uuid4().hex[:12]);out.mkdir(parents=True)
    script_digest=hashlib.sha256((HERE/'ExportVampirFunctions.java').read_bytes()).hexdigest()
    runner_digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    manifest_digest=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    env=os.environ.copy();env['JAVA_HOME']=str(tools/lock['jdk']['directory'])
    env['GHIDRA_HEADLESS_MAXMEM']='2G'
    home=HERE.parents[2]/'.tools/vampir-ghidra-home';home.mkdir(exist_ok=True)
    env['GHIDRA_HEADLESS_JAVA_OPTIONS']='-Duser.home='+home.as_posix()
    command=[str(tools/lock['ghidra']['directory']/'support/analyzeHeadless.bat'),str(projects),project]
    exists=(projects/(project+'.gpr')).exists()
    if exists and not args.reuse:raise ValueError('Project exists: use --reuse to process it without reimport')
    if args.reuse:
        if not exists:raise ValueError('No project to reuse')
        command+=['-process',Path(manifest['source']).name]
    else:command+=['-import',manifest['source']]
    command+=['-noanalysis','-max-cpu','2','-scriptPath',str(HERE),'-postScript','ExportVampirFunctions.java',str(manifest_path),str(out)]
    log=out/'headless-export.log'
    print(json.dumps(dict(log=str(log),output=str(out),functions=len(manifest['functions']),reuse=args.reuse)),flush=True)
    with log.open('w',encoding='utf-8') as stream:
        result=subprocess.run(command,env=env,stdout=stream,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError('Ghidra failed; inspect '+str(log))
    if script_digest!=hashlib.sha256((HERE/'ExportVampirFunctions.java').read_bytes()).hexdigest() or runner_digest!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('Exporter source changed during execution; partial results preserved')
    report=json.loads((out/'functions.json').read_text('utf-8'))
    if report['source_sha256']!=digest or len(report['functions'])!=len(manifest['functions']):raise ValueError('Incomplete Ghidra report')
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file() and p.suffix in ('.c','.json') and p.name!='provenance.json'}
    provenance=dict(source_sha256=digest,manifest_sha256=manifest_digest,
        script_sha256=script_digest,runner_sha256=runner_digest,tools=lock,files=files)
    (out/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
    complete=sum(f['completed'] for f in report['functions'])
    print(json.dumps(dict(output=str(out),completed=complete,total=len(report['functions']))))
    if complete!=len(report['functions']):raise ValueError('Some decompilations failed; partial results preserved')
    latest=dict(output=str(out),source_sha256=digest,report_sha256=hashlib.sha256((out/'functions.json').read_bytes()).hexdigest())
    pending=work/'latest-export.tmp';pending.write_text(json.dumps(latest,indent=2)+'\n',encoding='utf-8')
    pending.replace(work/'latest-export.json')


if __name__=='__main__':main()
