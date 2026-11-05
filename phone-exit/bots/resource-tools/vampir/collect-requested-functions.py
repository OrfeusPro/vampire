"""Create/reuse a source-specific no-analysis project for explicit unwind roots.

Called under the research workflow lock; never exports inferred callees or roles.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
import hashlib

# Reviewed source-specific leaves: no unwind entry of their own. This is an explicit
# source-specific analysis model, never permission to discover arbitrary callees.
REVIEWED_LEAF_TAILS = {
    '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f': {
        0x144aad2c0: '488d05f962bc04488901e921fcffff',
        0x141431fe0: 'e9fb100500',
    },
    'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c': {
        0x144552540: '890d9a5bc306c3',
        0x144ab13f0: '488b491033d2e9c51b0000',
    },
}


def declared_leaf_tails(native, image, sha, registry_path, root):
    """Load finite returning stores from a source-checked SDK transfer proof."""
    raw = Path(registry_path).read_bytes()
    registry = json.loads(raw)
    if len(raw) > 32768 or set(registry) != {'schema', 'models'} or registry['schema'] != 1 or len(registry['models']) > 16:
        raise ValueError('Requested leaf registry budget or schema differs')
    result = {}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    for model in registry['models']:
        if (set(model) != {'source_sha256', 'address', 'bytes', 'kind', 'proof'}
                or not re.fullmatch('[0-9a-f]{64}', model['source_sha256'])
                or model['kind'] != 'rip-u32-store-return'):
            raise ValueError('Unreviewed requested leaf declaration')
        if model['source_sha256'] != sha:
            continue
        proof = model['proof']
        path = Path(proof['path']).resolve()
        folder = (Path(root) / 'knowledge/sdk-batch-transfer-v1').resolve()
        if (set(proof) != {'path', 'sha256'} or not path.is_relative_to(folder)
                or path.name != 'manifest.json' or path.parent.name != proof['sha256']
                or path.stat().st_size > 16 * 1024 * 1024):
            raise ValueError('Requested leaf proof pointer differs')
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != proof['sha256']:
            raise ValueError('Requested leaf proof SHA differs')
        transfer = json.loads(payload)
        if (transfer.get('recipe') != 'sdk-batch-transfer-v1' or transfer.get('source_sha256') != sha
                or transfer.get('unresolved') != {} or transfer.get('semantic_verification') is not False):
            raise ValueError('Requested leaf transfer source or scope differs')
        at = int(model['address'], 16)
        data = bytes.fromhex(model['bytes'])
        leaves = [leaf for leaf in transfer['leaves'] if leaf['target'] == hex(at)
                  and leaf['target_bytes'] == data.hex() and leaf['size'] == len(data) and leaf['kind'] == 'leaf']
        if len(leaves) != 1 or len(data) != 7 or data[:2] != b'\x89\x0d' or data[-1:] != b'\xc3':
            raise ValueError('Requested leaf proof body differs')
        offset = image.offset(at - image.pe.base)
        rows = list(decoder.disasm(data, at))
        if (image.data[offset:offset + len(data)] != data or len(rows) != 2
                or [row.mnemonic for row in rows] != ['mov', 'ret']
                or rows[0].size != 6 or rows[1].size != 1):
            raise ValueError('Requested leaf source or returning-store shape differs')
        if at in result:
            raise ValueError('Duplicate requested leaf model')
        result[at] = data.hex()
    if Path(registry_path).read_bytes() != raw:
        raise ValueError('Requested leaf registry changed')
    return result


def checked_leaf_tails(native, image, sha, *, registry_path=None, root=None):
    result = {}
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    leaves = REVIEWED_LEAF_TAILS.get(sha, {})
    if len(leaves) > 4:raise ValueError('Reviewed tail leaf count budget')
    for at, encoded in leaves.items():
        reviewed_source = sha == 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
        setter_leaf = reviewed_source and at == 0x144552540 and encoded == '890d9a5bc306c3'
        terminal_jump = reviewed_source and at == 0x144ab13f0 and encoded == '488b491033d2e9c51b0000'
        archive_cleanup = (sha == '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
            and at == 0x144aad2c0 and encoded == '488d05f962bc04488901e921fcffff')
        sized_free = (sha == '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
            and at == 0x141431fe0 and encoded == 'e9fb100500')
        if not setter_leaf and not terminal_jump and not archive_cleanup and not sized_free:raise ValueError('Unreviewed tail leaf model')
        raw = bytes.fromhex(encoded)
        if not 1 <= len(raw) <= 16:
            raise ValueError('Reviewed tail leaf budget')
        off = image.offset(at - image.pe.base)
        if image.data[off:off + len(raw)] != raw:
            raise ValueError('Reviewed tail leaf source differs')
        rows = list(decoder.disasm(raw, at))
        if terminal_jump:
            # Exact finite model only. Its terminal target is observed, never
            # added as an inferred function or followed recursively.
            valid = ([(r.mnemonic, r.op_str) for r in rows] ==
                     [('mov', 'rcx, qword ptr [rcx + 0x10]'), ('xor', 'edx, edx'), ('jmp', '0x144ab2fc0')]
                     and rows[-1].address == at + 6 and rows[-1].size == 5
                     and rows[-1].operands[0].imm == 0x144ab2fc0)
        elif archive_cleanup:
            valid = ([(r.mnemonic, r.op_str) for r in rows] == [
                ('lea', 'rax, [rip + 0x4bc62f9]'), ('mov', 'qword ptr [rcx], rax'), ('jmp', '0x144aacef0')]
                and [r.size for r in rows] == [7, 3, 5]
                and rows[-1].address == at + 10
                and rows[0].address + rows[0].size + rows[0].operands[1].mem.disp == 0x1496735c0
                and rows[-1].operands[0].imm == 0x144aacef0)
        elif sized_free:
            valid = (len(rows) == 1 and rows[0].mnemonic == 'jmp'
                and rows[0].op_str == '0x1414830e0' and rows[0].address == at and rows[0].size == 5
                and len(rows[0].operands) == 1 and rows[0].operands[0].imm == 0x1414830e0)
        else:
            valid = (rows and rows[-1].mnemonic == 'ret'
                     and not any(row.mnemonic.startswith(('j', 'call', 'ret')) for row in rows[:-1]))
        if sum(row.size for row in rows) != len(raw) or not valid:
            raise ValueError('Reviewed tail leaf control flow differs')
        result[at] = encoded
    if registry_path is not None:
        additional = declared_leaf_tails(native, image, sha, registry_path, root)
        if set(additional) & set(result) or len(additional) + len(result) > 4:
            raise ValueError('Requested leaf declarations overlap or exceed budget')
        result.update(additional)
    return result


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


def scan_tail_calls(native,image,root,explicit_roots):
    """Linear scan is optional navigation; Ghidra block coverage remains mandatory.

    A PE unwind range can also contain switch data. Never model tails from its
    partially decoded prefix, and never suppress malformed-PE/budget errors.
    """
    try:
        rows=[row for part in native.decode_ranges(image,{root}) for row in part['instructions']]
    except ValueError as error:
        if str(error)!='Fragment not fully decoded':raise
        return [],dict(state='deferred_to_ghidra',reason='linear_fragment_not_fully_decoded',tail_models_applied=False)
    return reviewed_tail_calls(rows,explicit_roots),dict(state='complete')


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
    function_ranges, tail_calls, tail_scans = {}, {}, {}
    leaf_registry = index.HERE / 'knowledge/requested-leaf-models.json'
    leaf_registry_sha = index.digest(leaf_registry) if leaf_registry.is_file() else None
    leaf_targets = checked_leaf_tails(native, image, sha,
        registry_path=leaf_registry if leaf_registry.is_file() else None, root=args.root)
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
        tail_calls[address],tail_scans[address]=scan_tail_calls(native,image,image.roots[fragment],explicit_roots | set(leaf_targets))
    lock_path = index.HERE / 'ghidra-tools.lock.json'
    lock = index.read_json(lock_path)
    tools = args.root / 'tools/ghidra'
    for name in ('ghidra', 'jdk'):
        if index.read_json(tools / lock[name]['directory'] / '.phoneexit-verified.json') != lock[name]:
            raise ValueError('Pinned Ghidra tooling required')
    script = index.HERE / 'InspectVampirSdkProfile.java'
    inputs = {str(path): index.digest(path) for path in (Path(__file__), script, lock_path, args.request)}
    if leaf_registry.is_file():
        if index.digest(leaf_registry) != leaf_registry_sha:
            raise ValueError('Requested leaf registry changed before collection')
        inputs[str(leaf_registry)] = leaf_registry_sha
        for model in index.read_json(leaf_registry)['models']:
            if model['source_sha256'] == sha:
                inputs[model['proof']['path']] = model['proof']['sha256']
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
    used_leaves = {tail['target']: leaf_targets[int(tail['target'], 16)]
                   for tails in tail_calls.values() for tail in tails if int(tail['target'], 16) in leaf_targets}
    returning_stores = {}
    if leaf_registry.is_file():
        for model in index.read_json(leaf_registry)['models']:
            if model['source_sha256'] == sha and model['address'] in used_leaves:
                returning_stores[model['address']] = model['bytes']
    context.write_bytes(workflow.canonical(dict(new_source_sha256=sha, requested_unwind_ranges=function_ranges,
                                              requested_tail_calls=tail_calls,requested_tail_scans=tail_scans,
                                              requested_leaf_tail_targets=used_leaves,
                                              requested_leaf_returning_stores=returning_stores)))
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
        if function.get('direct_flow_coverage_complete') is not True or index.missing_conditional_fallthroughs(function.get('instructions', [])):
            raise ValueError('Requested export native direct-flow coverage is incomplete')
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
