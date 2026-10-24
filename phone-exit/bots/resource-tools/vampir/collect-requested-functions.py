"""Create/reuse a source-specific no-analysis project for explicit unwind roots.

Called under the research workflow lock; never exports inferred callees or roles.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import uuid


def command_for(*, launcher, projects, source, script_path, context, output, references, addresses, reuse):
    return [str(launcher), str(projects), 'RequestedRelease',
        '-process' if reuse else '-import', str(source.name if reuse else source),
        '-noanalysis', '-max-cpu', '2', '-scriptPath', str(script_path),
        '-postScript', 'InspectVampirSdkProfile.java', str(context), str(output),
        str(references), ','.join(addresses)]


def reviewed_tail_calls(rows, explicit_roots):
    """Model only source E9 jumps to another explicitly requested root."""
    local = {row['address'] for row in rows}
    return [dict(address=hex(row['address']), target=hex(row['direct_target']), bytes=row['bytes'])
            for row in rows if row['mnemonic'] == 'jmp' and row['branch'] and not row['call']
            and row['direct_target'] not in local and row['direct_target'] in explicit_roots
            and len(bytes.fromhex(row['bytes'])) == 5 and row['bytes'].startswith('e9')]


def collect(index, args, request, addresses):
    workflow = index.extension('research-workflow')
    sha = request['source_sha256']
    source = Path(request['source'])
    if index.digest(source) != sha:
        raise ValueError('Source changed before requested export')
    if request.get('require_installed_match') and index.digest(index.INSTALL) != sha:
        raise ValueError('Installed client changed before requested export')
    if not 1 <= len(addresses) <= 32 or not set(addresses) <= {f['address'] for f in request['functions']}:
        raise ValueError('Only explicit request addresses may be exported')
    native = index.extension('build-native-entry-code')
    image = native.Image(source.read_bytes())
    function_ranges, tail_calls = {}, {}
    explicit_roots = set()
    for item in request['functions']:
        at = int(item['address'], 16)
        fragment = image.containing(at)
        if fragment is not None and image.pe.base + image.roots[fragment][0] == at:
            explicit_roots.add(at)
    for address in addresses:
        at = int(address, 16)
        fragment = image.containing(at)
        if fragment is None or image.pe.base + image.roots[fragment][0] != at:
            raise ValueError('Requested address is not an unwind root')
        ranges = [row for row, root in image.roots.items() if root == image.roots[fragment]]
        if len(ranges) > 32 or sum(end-begin for begin,end,_ in ranges) > 65536:
            raise ValueError('Requested unwind range budget exceeded')
        function_ranges[address] = [dict(begin=hex(image.pe.base+begin),end=hex(image.pe.base+end))
                                    for begin,end,_ in ranges]
        rows = [row for part in native.decode_ranges(image, {image.roots[fragment]}) for row in part['instructions']]
        tail_calls[address] = reviewed_tail_calls(rows, explicit_roots)
    lock_path = index.HERE / 'ghidra-tools.lock.json'
    lock = index.read_json(lock_path)
    tools = args.root / 'tools/ghidra'
    for name in ('ghidra', 'jdk'):
        if index.read_json(tools / lock[name]['directory'] / '.phoneexit-verified.json') != lock[name]:
            raise ValueError('Pinned Ghidra tooling required')
    script = index.HERE / 'InspectVampirSdkProfile.java'
    inputs = {str(path): index.digest(path) for path in (Path(__file__), script, lock_path, args.request)}
    project = args.root / 'ghidra/request-projects' / sha
    project.mkdir(parents=True, exist_ok=True)
    receipt_path = project / 'project.json'
    project_file = project / 'RequestedRelease.gpr'
    if project_file.exists() != receipt_path.exists():
        return dict(state='queued', addresses=addresses,
            reason='Incomplete requested project import; inspect preserved logs before another attempt')
    reuse = project_file.exists()
    if reuse:
        receipt = index.read_json(receipt_path)
        if receipt != dict(schema=1, source_sha256=sha, source=str(source), tools=lock, analysis='disabled'):
            raise ValueError('Requested project receipt differs')
    out = args.root / 'ghidra/request-exports' / sha / ('run-' + uuid.uuid4().hex[:12])
    out.mkdir(parents=True)
    context, references = out / 'source.json', out / 'references.json'
    context.write_bytes(workflow.canonical(dict(new_source_sha256=sha, requested_unwind_ranges=function_ranges,
                                              requested_tail_calls=tail_calls)))
    references.write_bytes(workflow.canonical(dict(source_sha256=sha,
        references=[dict(function=at, reason='Explicit request/unwind root; no role assigned') for at in addresses])))
    command = command_for(launcher=tools / lock['ghidra']['directory'] / 'support/analyzeHeadless.bat',
        projects=project, source=source, script_path=index.HERE, context=context, output=out,
        references=references, addresses=addresses, reuse=reuse)
    env = os.environ.copy()
    env['JAVA_HOME'] = str(tools / lock['jdk']['directory'])
    env['GHIDRA_HEADLESS_MAXMEM'] = '4G'
    home = index.HERE.parents[2] / '.tools/vampir-ghidra-home'
    home.mkdir(exist_ok=True)
    env['GHIDRA_HEADLESS_JAVA_OPTIONS'] = '-Duser.home=' + home.as_posix()
    (out / 'invocation.json').write_bytes(workflow.canonical(dict(inputs=inputs, tools=lock, command=command)))
    print(json.dumps(dict(output=str(out), reused_project=reuse)), flush=True)
    with workflow.locked(args.root, 'ghidra'):
        # Own the child JVM until terminal; do not abandon its project lock.
        with (out / 'headless.log').open('w', encoding='utf-8') as stream:
            completed = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if completed.returncode or not (out / 'details.json').is_file():
        raise ValueError('Requested functions were not exported; inspect ' + str(out / 'headless.log'))
    if index.digest(source) != sha or any(index.digest(Path(path)) != digest for path, digest in inputs.items()):
        raise ValueError('Requested export inputs changed')
    if request.get('require_installed_match') and index.digest(index.INSTALL) != sha:
        raise ValueError('Installed client changed during requested export')
    report = index.read_json(out / 'details.json')
    if report['new_source_sha256'] != sha or {index.address(f['address']) for f in report['functions']} != set(addresses):
        raise ValueError('Unexpected requested export source or functions')
    for function in report['functions']:
        size = sum(len(bytes.fromhex(row['bytes'])) for row in function.get('instructions', []))
        if not size or size > function.get('body_bytes', 0):
            raise ValueError('Requested export body/instruction coverage is incomplete')
        if function.get('block_coverage_complete') is not True:
            raise ValueError('Requested export decompiler block coverage is incomplete')
    saved = re.search(r'Save succeeded for(?: processed file)?:', (out / 'headless.log').read_text('utf-8'))
    if not project_file.is_file() or not saved:
        raise ValueError('Requested Ghidra project save not confirmed')
    workflow.atomic(receipt_path, workflow.canonical(dict(schema=1, source_sha256=sha,
        source=str(source), tools=lock, analysis='disabled')))
    files = {path.name: index.digest(path) for path in out.iterdir() if path.is_file()}
    (out / 'provenance.json').write_bytes(workflow.canonical(dict(inputs=inputs, files=files, tools=lock,
        command=command, source_sha256=sha, source=str(source), roles_transferred=False)))
    return dict(state='collected', addresses=addresses, queue=[], export=str(out / 'details.json'),
                project=str(project_file), reused_project=reuse)
