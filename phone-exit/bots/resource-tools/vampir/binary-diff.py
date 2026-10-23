"""Pinned offline BinExport/BinDiff adapter. Matches are candidates, never facts."""
import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    temp.replace(path)


def files(folder):
    return {str(p.relative_to(folder)).replace('\\','/'): digest(p)
            for p in sorted(folder.rglob('*')) if p.is_file()}


def verify_files(folder, expected):
    for relative, sha in expected.items():
        path = (folder/relative).resolve()
        if not path.is_relative_to(folder.resolve()) or digest(path) != sha:
            raise ValueError('Tool changed: '+relative)


def command(argv, log, env=None):
    with log.open('w', encoding='utf-8') as stream:
        # Wait for the owned child; no timeout leaving a JVM behind.
        subprocess.run([str(v) for v in argv], env=env, stdout=stream,
                       stderr=subprocess.STDOUT, check=True)


def setup(root):
    tools = root/'tools/binary-diff'
    tools.mkdir(parents=True, exist_ok=True)
    lock = json.loads((HERE/'binary-diff-tools.lock.json').read_text('utf-8'))
    ghidra = json.loads((HERE/'ghidra-tools.lock.json').read_text('utf-8'))
    receipt = tools/'install.json'
    if receipt.exists():
        prior = json.loads(receipt.read_text('utf-8'))
        if prior['lock'] == lock and prior['ghidra'] == ghidra:
            if prior['dependency_metadata_sha256'] != digest(HERE/'binexport-verification-metadata.xml'):
                raise ValueError('Pinned dependency metadata changed')
            verify_files(tools, prior['files'])
            return prior
        raise ValueError('Existing installation differs; preserve it and use a separate resource root')
    installer = module('install-secondary-tools')
    for record in lock.values():
        if isinstance(record, dict): installer.install(record, tools)
    target = tools/'bindiff8'
    if not (target/'ProgramFiles/BinDiff/bin/bindiff.exe').exists():
        command(['msiexec.exe','/a', tools/'bindiff8.msi','/qn',
                 'TARGETDIR='+str(target.resolve()), '/l*v', tools/'msi-extract.log'],
                tools/'msi-command.log')
    gh = root/'tools/ghidra'/ghidra['ghidra']['directory']
    jdk = root/'tools/ghidra'/ghidra['jdk']['directory']
    for name, path in [('ghidra',gh), ('jdk',jdk)]:
        if json.loads((path/'.phoneexit-verified.json').read_text('utf-8')) != ghidra[name]:
            raise ValueError('Unverified Ghidra/JDK installation')
    source = tools/'source'/('binexport-'+lock['binexport']['commit'])/'java'
    metadata = HERE/'binexport-verification-metadata.xml'
    if not metadata.exists(): raise ValueError('Pinned Gradle dependency verification metadata missing')
    (source/'gradle').mkdir(exist_ok=True)
    shutil.copyfile(metadata, source/'gradle/verification-metadata.xml')
    (tools/'tmp').mkdir(exist_ok=True)
    env = dict(os.environ, JAVA_HOME=str(jdk), GHIDRA_INSTALL_DIR=str(gh),
               GRADLE_USER_HOME=str(tools/'gradle-home'),
               JAVA_TOOL_OPTIONS='"-Djdk.net.unixdomain.tmpdir='+str(tools/'tmp')+'" '
                   '-Djavax.net.ssl.trustStoreType=Windows-ROOT -Djavax.net.ssl.trustStore=NONE')
    command([tools/'gradle-8.14.3/bin/gradle.bat','--no-daemon', '--dependency-verification','strict',
             '-p',source,'buildExtension'], tools/'build.log',env)
    bundles = list((source/'dist').glob('*.zip'))
    if len(bundles)!=1: raise ValueError('Ambiguous extension output')
    extension = tools/'extension'
    extension.mkdir(exist_ok=True)
    with zipfile.ZipFile(bundles[0]) as bundle:
        for member in bundle.infolist():
            if not (extension/member.filename).resolve().is_relative_to(extension.resolve()):
                raise ValueError('Unsafe extension path')
        bundle.extractall(extension)
    pinned = {**{str(p.relative_to(tools)).replace('\\','/'):digest(p)
                 for p in (tools/lock['bindiff']['archive'],tools/lock['binexport']['archive'],
                           tools/lock['gradle']['archive'],bundles[0])},
              **{'extension/'+p:s for p,s in files(extension).items()},
              **{'bindiff8/'+p:s for p,s in files(target).items()}}
    result = dict(schema=1,lock=lock,ghidra=ghidra,files=pinned,
                  dependency_metadata_sha256=digest(metadata))
    save(receipt,result)
    return result


def installation(root):
    tools=root/'tools/binary-diff'
    value=json.loads((tools/'install.json').read_text('utf-8'))
    if value['lock']!=json.loads((HERE/'binary-diff-tools.lock.json').read_text('utf-8')):
        raise ValueError('Tool lock differs')
    if value['ghidra']!=json.loads((HERE/'ghidra-tools.lock.json').read_text('utf-8')):
        raise ValueError('Ghidra lock differs')
    verify_files(tools,value['files'])
    return tools,value


def project_inputs(project):
    database=project.with_suffix('.rep')
    parts=sorted(database.rglob('*.gbf'))
    if not parts: raise ValueError('Ghidra project databases missing')
    return {str(p.relative_to(project.parent)):digest(p) for p in [project,*parts]}


def checked_export(path):
    data=json.loads(path.read_text('utf-8'))
    for field, sha_field in [('source','source_sha256'),('export','export_sha256')]:
        if digest(data[field])!=data[sha_field]: raise ValueError('Export provenance changed: '+field)
    return data


def export(root, source, project, program, heap_gib=4):
    if heap_gib not in (2,4,8,16):raise ValueError('Unsupported heap budget')
    tools, installed=installation(root)
    source=source.resolve(); project=project.resolve()
    sha=digest(source)
    if project.suffix!='.gpr' or not project.is_file(): raise ValueError('Explicit existing Ghidra project required')
    inputs=project_inputs(project)
    script=HERE/'ghidra/CheckedBinExport.java'
    input_key=dict(source_sha256=sha,project=str(project),program=program,project_inputs=inputs,
                   install_sha256=digest(tools/'install.json'),script_sha256=digest(script))
    key=hashlib.sha256(json.dumps(input_key,sort_keys=True).encode()).hexdigest()
    out=root/'binary-diff/exports'/sha/key
    out.mkdir(parents=True,exist_ok=True)
    receipt=out/'manifest.json'
    if receipt.exists():
        data=checked_export(receipt)
        if any(data.get(k)!=v for k,v in input_key.items()):
            raise ValueError('Exporter changed; use a separate export directory')
        return dict(manifest=str(receipt),reused=True, **data)
    env=dict(os.environ,JAVA_HOME=str(root/'tools/ghidra'/installed['ghidra']['jdk']['directory']),
             GHIDRA_HEADLESS_MAXMEM=str(heap_gib)+'G',
             JAVA_TOOL_OPTIONS='"-Djdk.net.unixdomain.tmpdir='+str(tools/'tmp')+'"')
    extension=next((tools/'extension').glob('*/lib'))
    scripts=next((tools/'extension').glob('*/ghidra_scripts'))
    output=out/'program.BinExport'
    # Check the program's actual imported bytes before exporting, not its filename.
    argv=[root/'tools/ghidra'/installed['ghidra']['ghidra']['directory']/'support/analyzeHeadless.bat',
          project.parent,project.stem,'-process',program,'-noanalysis','-readOnly',
          '-scriptPath',str(script.parent)+';'+str(scripts),
          '-postScript','CheckedBinExport.java',sha,str(output)]
    # Ghidra loads extensions only from its registered extension directories.
    gh=root/'tools/ghidra'/installed['ghidra']['ghidra']['directory']
    registered=gh/'Ghidra/Extensions/BinExport'
    start=time.monotonic()
    with module('research-workflow').locked(root,'ghidra'):
        if project_inputs(project)!=inputs:raise ValueError('Project changed before export')
        if not registered.exists(): shutil.copytree(extension.parent,registered)
        verify_files(registered,files(extension.parent))
        if (out/'export.log').exists():
            shutil.copyfile(out/'export.log',out/('export-'+digest(out/'export.log')+'.log'))
        command(argv,out/'export.log',env)
    if not output.is_file() or output.stat().st_size==0: raise ValueError('No BinExport output')
    if digest(source)!=sha: raise ValueError('Source changed during export')
    if project_inputs(project)!=inputs: raise ValueError('Project changed during read-only export')
    data=dict(schema=1,source=str(source),source_sha256=sha,export=str(output),
              export_sha256=digest(output),project=str(project),program=program,
              install_sha256=digest(tools/'install.json'),tool_sha256=digest(__file__),
              script_sha256=digest(script),analysis='existing project; no new analysis',
              project_inputs=inputs,
              heap_gib=heap_gib,
              seconds=time.monotonic()-start,semantic_verification=False)
    save(receipt,data)
    return dict(manifest=str(receipt),reused=False,**data)


def candidates(database, address=None):
    with closing(sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        columns={r[1] for r in db.execute('PRAGMA table_info(function)')}
        if not {'address1','address2','similarity','confidence'}<=columns:
            raise ValueError('Unsupported BinDiff schema')
        query='SELECT address1,address2,similarity,confidence FROM function'
        args=()
        if address is not None: query+=' WHERE address1=?'; args=(int(address,16),)
        result=db.execute(query+' ORDER BY address1,address2 LIMIT 100001',args).fetchall()
        if len(result)>100000: raise ValueError('Candidate budget exceeded; select an address')
        return [dict(old_address=hex(a),new_address=hex(b),similarity=s,confidence=c,
                     state='candidate',semantic_verification=False) for a,b,s,c in result]


def compare(root, primary, secondary):
    tools,_=installation(root)
    old,new=checked_export(primary),checked_export(secondary)
    key=hashlib.sha256((digest(primary)+digest(secondary)+digest(tools/'install.json')+digest(__file__)).encode()).hexdigest()
    out=root/'binary-diff/comparisons'/key
    out.mkdir(parents=True,exist_ok=True)
    receipt=out/'manifest.json'
    if receipt.exists():
        data=checked_comparison(receipt)
        if Path(data['primary']).resolve()!=primary.resolve() or Path(data['secondary']).resolve()!=secondary.resolve():
            raise ValueError('Cached comparison inputs differ')
        return dict(manifest=str(receipt),reused=True,**data)
    start=time.monotonic()
    command([tools/'bindiff8/ProgramFiles/BinDiff/bin/bindiff.exe',
             '--primary='+old['export'],'--secondary='+new['export'],
             '--output_dir='+str(out),'--output_format=bin'],out/'compare.log')
    databases=list(out.glob('*.BinDiff'))
    if len(databases)!=1: raise ValueError('Ambiguous comparison output')
    if checked_export(primary)!=old or checked_export(secondary)!=new:
        raise ValueError('Comparison inputs changed during execution')
    candidates(databases[0],'0x0')  # Validate schema without loading every match.
    with closing(sqlite3.connect(databases[0].resolve().as_uri()+'?mode=ro',uri=True)) as db:
        count=db.execute('SELECT COUNT(*) FROM function').fetchone()[0]
    data=dict(schema=1,primary=str(primary),primary_sha256=digest(primary),
              secondary=str(secondary),secondary_sha256=digest(secondary),
              baseline_sha256=old['source_sha256'],source_sha256=new['source_sha256'],
              database=str(databases[0]),database_sha256=digest(databases[0]),
              install_sha256=digest(tools/'install.json'),seconds=time.monotonic()-start,
              candidate_count=count,semantic_verification=False,
              next_check='Verify unwind roots, declared callees/data/branches and contract tests')
    save(receipt,data)
    return dict(manifest=str(receipt),reused=False,**data)


def checked_comparison(path):
    data=json.loads(path.read_text('utf-8'))
    if digest(data['primary'])!=data['primary_sha256'] or digest(data['secondary'])!=data['secondary_sha256']:
        raise ValueError('Comparison export receipts changed')
    old=checked_export(Path(data['primary']));new=checked_export(Path(data['secondary']))
    if (data['baseline_sha256']!=old['source_sha256'] or data['source_sha256']!=new['source_sha256'] or
        digest(data['database'])!=data['database_sha256']):raise ValueError('Comparison changed')
    return data


def prepare_candidate(root, comparison, address, question):
    data=checked_comparison(comparison)
    matches=candidates(Path(data['database']),address)
    if len(matches)!=1:raise ValueError('Missing or ambiguous candidate; manual review required')
    result=subprocess.run([sys.executable,'-X','utf8',str(HERE/'knowledge-index.py'),
        '--root',str(root),'prepare','--question',question,'--function',matches[0]['new_address'],
        '--release',data['source_sha256'],'--reason',
        'BinDiff candidate only; baseline '+data['baseline_sha256']+' / '+address+
        '; comparison '+str(comparison.resolve())+' SHA256 '+digest(comparison)],capture_output=True,text=True,
        encoding='utf-8',check=True)
    return json.loads(result.stdout)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=ROOT)
    sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('install')
    e=sub.add_parser('export')
    e.add_argument('--source',type=Path,required=True)
    e.add_argument('--project',type=Path,required=True)
    e.add_argument('--program',required=True)
    e.add_argument('--heap-gib',type=int,choices=(2,4,8,16),default=4)
    c=sub.add_parser('compare')
    c.add_argument('--primary',type=Path,required=True)
    c.add_argument('--secondary',type=Path,required=True)
    q=sub.add_parser('candidates')
    q.add_argument('--comparison',type=Path,required=True)
    q.add_argument('--address')
    task=sub.add_parser('prepare')
    task.add_argument('--comparison',type=Path,required=True)
    task.add_argument('--address',required=True)
    task.add_argument('--question',required=True)
    args=p.parse_args()
    if args.action=='install':
        with module('research-workflow').locked(args.root,'binary-diff-install'):
            value=setup(args.root)
        result=dict(manifest=str(args.root/'tools/binary-diff/install.json'),
                    verified_files=len(value['files']),ghidra=value['ghidra']['ghidra']['version'])
    elif args.action=='export': result=export(args.root,args.source,args.project,args.program,args.heap_gib)
    elif args.action=='compare': result=compare(args.root,args.primary,args.secondary)
    elif args.action=='prepare':result=prepare_candidate(args.root,args.comparison,args.address,args.question)
    else:
        data=checked_comparison(args.comparison)
        result=dict(baseline_sha256=data['baseline_sha256'],source_sha256=data['source_sha256'],
                    comparison_sha256=digest(args.comparison),
                    matches=candidates(Path(data['database']),args.address))
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__': main()
