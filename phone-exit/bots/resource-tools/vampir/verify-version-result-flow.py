"""Compose a proven VersionResult reader and result gate with its native handler."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


HERE = Path(__file__).resolve().parent
CODES = (0, 1, 42, 58, 708, 1304, 0xffffffff, 0x1197)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked(pointer):
    path = Path(pointer['path']).resolve()
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Version flow input exceeds budget')
    raw = path.read_bytes()
    if set(pointer) != {'path', 'sha256'} or hashlib.sha256(raw).hexdigest() != pointer['sha256']:
        raise ValueError('Version flow input pointer SHA differs')
    return json.loads(raw)


def dependency(root, context, name, scope):
    declaration = context[name]
    pointer = declaration['context']
    value = checked(pointer)
    report = checked(declaration['check'])
    if (value['source_sha256'] != context['source_sha256'] or report['source_sha256'] != context['source_sha256']
            or report.get('method') != 'bounded_native' or report.get('scope') != scope
            or report.get('context_sha256') != pointer['sha256'] or report.get('runtime_activated') is not False):
        raise ValueError('Version flow dependency source or scope differs')
    for item in (pointer, declaration['check']):
        if not Path(item['path']).resolve().is_relative_to((Path(root) / 'knowledge').resolve()):
            raise ValueError('Version flow dependency outside research library')
    return value


def static_links(context, root, h, gate, native_result):
    native = load('build-native-entry-code')
    normalizer = load('audit-launcher-shape-11318')
    gate_rules = load('result-gate-transfer-rules')
    gate_rules.export_coverage(root, gate, native, None, h.image)
    gate_code = gate_rules.rows(native, h.image, gate)
    handler = int(context['handler'], 16)
    function = next(part for part in h.fragments if int(part['address'], 16) == handler)
    normalized = normalizer.normalize_function(native, h.image, function)
    baseline = checked(context['baseline'])
    source = Path(root) / 'client-code-snapshots' / baseline['source_sha256'] / 'ProjectRED-Win64-Shipping.exe'
    raw_source = source.read_bytes()
    if hashlib.sha256(raw_source).hexdigest() != baseline['source_sha256']:
        raise ValueError('Version handler baseline source changed')
    old_image = native.Image(raw_source)
    old_handler = int(baseline['functions']['handler'], 16)
    old_functions = []
    for run, expected in baseline['exports'].items():
        path = Path(root) / 'ghidra/request-exports' / baseline['source_sha256'] / run / 'details.json'
        document = checked(dict(path=str(path), sha256=expected))
        old_functions.extend(row for row in document['functions'] if int(row['address'], 16) == old_handler)
    if len(old_functions) != 1 or normalized['shape'] != normalizer.normalize_function(native, old_image, old_functions[0])['shape']:
        raise ValueError('Version handler baseline whole shape differs')
    calls = {row['address']: row['references'][0] for row in function['instructions']
             if row['text'].startswith('CALL ') and len(row['references']) == 1}
    # The indirect packet ID call remains an actual instruction.
    if calls != context['direct_calls']:
        raise ValueError('Version handler direct call roles differ')
    table, getter, constructor = (int(native_result[name], 16) for name in ('packet_table', 'id_getter', 'constructor'))
    utility = load('update-native-contexts')
    read = lambda at, size: utility.image_bytes(h.image, at, size)
    if struct.unpack('<Q', read(table + 0x28, 8))[0] != getter or h.call(getter) != 2:
        raise ValueError('Version handler packet ID differs')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    window = context['registration']
    start, owner = int(window['address'], 16), int(window['owner'], 16)
    raw = bytes.fromhex(window['bytes'])
    if not 1 <= len(raw) <= 128 or read(start, len(raw)) != raw:
        raise ValueError('Version registration bytes differ')
    containing = h.image.containing(start)
    if containing is None or h.image.pe.base + h.image.roots[containing][0] != owner:
        raise ValueError('Version registration owner differs')
    instructions = list(decoder.disasm(raw, start))
    if sum(ins.size for ins in instructions) != len(raw):
        raise ValueError('Version registration instruction gap')
    before = baseline['registration_window']
    old_raw = bytes.fromhex(before['bytes'])
    if (len(old_raw) != len(raw) or hashlib.sha256(old_raw).hexdigest() != before['sha256']
            or utility.image_bytes(old_image, int(before['address'], 16), len(old_raw)) != old_raw):
        raise ValueError('Version registration baseline bytes differ')
    register_shape = load('update-native-contexts').signature
    def decoded(data, at):
        return [dict(address=ins.address, bytes=ins.bytes.hex(),
            call=ins.group(native.capstone.CS_GRP_CALL), branch=ins.group(native.capstone.CS_GRP_JUMP),
            direct_target=ins.operands[0].imm if ins.operands and ins.operands[0].type == native.X86_OP_IMM
                and (ins.group(native.capstone.CS_GRP_CALL) or ins.group(native.capstone.CS_GRP_JUMP)) else None,
            rip_references=[ins.address + ins.size + op.mem.disp for op in ins.operands
                if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP])
            for ins in decoder.disasm(data, at)]
    if register_shape(native, decoded(old_raw, int(before['address'], 16))) != register_shape(native, decoded(raw, start)):
        raise ValueError('Version registration whole instruction shape differs')
    vptr = int(window['handler_table'], 16)
    references = [ins.address + ins.size + op.mem.disp for ins in instructions
                  for op in ins.operands if op.type == native.X86_OP_MEM and op.mem.base == native.X86_REG_RIP]
    targets = [ins.operands[0].imm for ins in instructions if ins.mnemonic == 'call'
               and ins.operands[0].type == native.X86_OP_IMM]
    if vptr not in references or constructor not in targets or struct.unpack('<Q', read(vptr + 0x10, 8))[0] != handler:
        raise ValueError('Version handler registration linkage differs')
    tail = [ins for row in function['instructions']
            for ins in decoder.disasm(bytes.fromhex(row['bytes']), int(row['address'], 16))
            if ins.mnemonic == 'jmp' and ins.operands[0].type == native.X86_OP_IMM
            and ins.operands[0].imm == int(context['login_prepare'], 16)]
    if len(tail) != 1:
        raise ValueError('Version handler Login tail differs')
    return function, gate_code


def verify(context, root):
    if context.get('schema') != 1 or context.get('recipe') != 'version-result-flow-v1':
        raise ValueError('Version flow recipe differs')
    root = Path(root)
    gate = dependency(root, context, 'gate', 'bounded_native_result_gate')
    result = dependency(root, context, 'input', 'bounded_native_version_result_input')
    gate_report = checked(context['gate']['check'])
    input_report = checked(context['input']['check'])
    load('result-gate-case-contracts').validate_report(gate_report, gate)
    load('update-native-version-result').report_valid(input_report, result, context['input']['context']['sha256'])
    if context['helpers'] != gate['helpers'] or context['helpers'] != result['helpers']:
        raise ValueError('Version flow copy binding differs')
    runtime = load('update-native-harness').runtime_inputs()
    if gate_report['runtime'] != runtime or input_report['runtime'] != runtime:
        raise ValueError('Version flow dependency native runtime differs')
    load('verify-result-gate-context').admit(gate, root)
    roots = {int(context['handler'], 16), int(gate['function'], 16), int(result['reader'], 16)}
    roots.update(int(at, 16) for at in result['native_input']['functions'].values())
    leaves = {int(at, 16): item['bytes'] for value in (result, result['native_input']) for at, item in value['leaves'].items()}
    exports = {**context['exports'], **gate['exports'], **result['exports'], **result['native_input']['exports']}
    source = root / 'client-code-snapshots' / context['source_sha256'] / 'ProjectRED-Win64-Shipping.exe'
    harness_context = dict(source_sha256=context['source_sha256'], source=str(source), helpers=context['helpers'], function_budget=19)
    h = load('update-native-harness').make_harness(harness_context, exports, roots, leaves=leaves, root=root)
    static_links(context, root, h, gate, result)
    uc, x = h.uc, h.x
    packet, state, peer, archive = [h.scratch + at for at in (0x1000, 0x2000, 0x3000, 0x8000)]
    events, current, input_state = [], {}, {}
    fixtures = dict(context['fixtures'], **gate['fixtures'], login_prepare=context['login_prepare'])
    seed, position, _, input_check, construction = load('login-result-input-fixtures').install(
        load, h, result['native_input'], input_state, packet, archive, load('verify-version-result-context').ORDER)

    def require(value, message):
        if not value:
            raise ValueError(message)

    def reg(name):
        return uc.reg_read(getattr(x, 'UC_X86_REG_' + name))

    def fixture(machine, name):
        value = 0
        if name == 'string_init':
            require(h.scratch + 0x30000 <= reg('RCX') < h.scratch + 0x38000, 'Version flow temporary differs')
            uc.mem_write(reg('RCX'), bytes(16))
        elif name == 'free':
            require(reg('RCX') == 0, 'Version flow unexpected allocated string')
        elif name == 'gate_state':
            value = state
        elif name == 'gate_error':
            require((reg('RCX') & 0xffffffff, reg('RDX')) == (current['code'], 0), 'Version flow error arguments differ')
            events.append('error')
        elif name == 'peer':
            value = peer
            events.append('peer')
        elif name == 'login_prepare':
            require(reg('RCX') == peer and reg('RSP') == h.scratch + 0x38000, 'Version flow Login receiver or stack differs')
            events.append('login_prepare')
        elif name != 'log':
            raise ValueError('Undeclared Version flow fixture')
        h.finish(value)

    protected = roots | set(leaves)
    for name, text in fixtures.items():
        at = int(text, 16)
        require(at not in protected, 'Version flow fixture overlaps executed code')
        h.add_fixture(at, lambda machine, name=name: fixture(machine, name))
    import unicorn
    def gate_entered(machine, at, size, unused):
        if at == int(gate['function'], 16):
            require((reg('RCX') & 0xffffffff, reg('RDX'), reg('R9')) == (current['code'], 2, 0), 'Version flow gate arguments differ')
            require(bytes(uc.mem_read(reg('R8'), 24)) == bytes(24), 'Version flow gate temporary differs')
            events.append('gate')
    uc.hook_add(unicorn.UC_HOOK_CODE, gate_entered)
    abi = {name: 0x1234567800000000 + i for i, name in enumerate(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))}
    abi.update({'XMM' + str(i): 0x123456789abcdef0fedcba9876543210 + i for i in range(6, 16)})
    cases = []
    for code in CODES:
        for flag in (0, 1):
            current['code'] = code
            uc.mem_write(packet - 16, b'\xa5' * 16 + bytes(0x28) + b'\xa6' * 16)
            h.call(int(result['constructor'], 16), packet)
            body = struct.pack('<IIBII', code, 0x80000000, flag, 0xffffffff, 0x12345678)
            input_state.clear()
            input_state.update(body=body, operations=[], written=[], fail_at=None)
            seed(body, 0x55)
            uc.reg_write(x.UC_X86_REG_RDX, archive)
            require(h.call(int(result['reader'], 16), packet) & 255 == 1, 'Version flow reader failed')
            input_check()
            require(position() == len(body), 'Version flow input consumption differs')
            uc.mem_write(state + 8, bytes([flag]))
            before = bytes(uc.mem_read(packet - 16, 0x48))
            for name, value in abi.items():
                uc.reg_write(getattr(x, 'UC_X86_REG_' + name), value)
            events.clear()
            uc.reg_write(x.UC_X86_REG_R8, packet)
            h.call(int(context['handler'], 16), h.scratch + 0x4000)
            expected = ['gate'] + (['error'] if code != 0 and flag == 0 and code != 42 else [])
            if code == 0 or (code == 0x1197 and flag == 0):
                expected += ['peer', 'login_prepare']
            require(events == expected, 'Version flow success or error handoff differs')
            require(bytes(uc.mem_read(packet - 16, 0x48)) == before, 'Version flow packet/canaries changed')
            require(all(reg(name) == value for name, value in abi.items()) and reg('RSP') == h.scratch + 0x38008, 'Version flow Win64 ABI differs')
            cases.append(dict(code=code, flag=flag, events=events.copy(), consumed=position(), canaries_unchanged=True))
    return dict(schema=1, recipe='version-result-flow-v1', source_sha256=context['source_sha256'],
                method='bounded_native', cases=cases, input_construction_cases=construction,
                reused_dependencies=dict(gate=context['gate'], input=context['input']), evidence=h.evidence,
                native_handler=True, native_gate=True, native_input=True, login_prepare_captured=True,
                runtime_admitted=False, network_used=False, profile_activated=False,
                limits=['Registration is a static bounded window; the dispatcher is not executed.',
                        'Gate state, SDK/string/log/error services and peer are explicit fixtures.',
                        'Login preparation is captured at entry. No server or game session executes.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    raw = args.context.read_bytes()
    result = verify(json.loads(raw), args.root)
    if args.context.read_bytes() != raw:
        raise ValueError('Version flow context changed')
    result['context_sha256'] = hashlib.sha256(raw).hexdigest()
    path = load('research-workflow').snapshot(args.root, 'native-version-result-flow-checks', result)
    print(json.dumps(dict(report=str(path), cases=len(result['cases']))))
