"""Source-bound static launcher request audit. No auth, profile reads or HTTP."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE_SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
EXPORTS = (
    ('run-4f6c93310580', 'e184e1cb16b2f4e85dabe9bafec8099744bb82335dbb5955ca8ec044bef20a9a'),
    ('run-82294ab74cc0', '9c65601c33add974231d636a77bf0ce314cbf7a92f8030ee477c00338f435df8'),
    ('run-5f5b69ab5cf7', '8526f7380efb1838a063c0d6b5ec80c01e5df1b5f46def43104b6017f1ef3bf3'),
)


def load_native():
    spec = importlib.util.spec_from_file_location('launcher_contract_native', HERE / 'build-native-entry-code.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    return native


def audit(*, root=None):
    native = load_native()
    root = Path(root) if root is not None else native.ROOT
    source = root / 'client-code-snapshots' / SOURCE_SHA / 'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA:
        raise ValueError('Launcher source SHA changed')
    image = native.Image(raw)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    folder = root / 'ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/details'
    functions, evidence = {}, []
    for name, expected in EXPORTS:
        path = folder / name / 'details.json'
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError('Launcher export SHA changed')
        report = json.loads(payload)
        if report['new_source_sha256'] != SOURCE_SHA:
            raise ValueError('Launcher export source mismatch')
        evidence.append(dict(path=str(path), sha256=expected))
        for function in report['functions']:
            address = int(function['address'], 16)
            if address in functions or not function['decompilation_completed']:
                raise ValueError('Duplicate or incomplete launcher export')
            rows, references = [], set()
            for row in function['instructions']:
                at, data = int(row['address'], 16), bytes.fromhex(row['bytes'])
                offset = image.offset(at - image.pe.base)
                if raw[offset:offset + len(data)] != data:
                    raise ValueError('Launcher instruction bytes changed')
                instructions = list(decoder.disasm(data, at))
                if len(instructions) != 1 or instructions[0].size != len(data):
                    raise ValueError('Launcher instruction boundary rejected')
                ins = instructions[0]
                refs = []
                for operand in ins.operands:
                    if operand.type == native.X86_OP_IMM:
                        refs.append(operand.imm)
                    elif operand.type == native.X86_OP_MEM and operand.mem.base == native.X86_REG_RIP:
                        refs.append(ins.address + ins.size + operand.mem.disp)
                references.update(refs)
                rows.append(dict(address=hex(at), bytes=data.hex(), text=ins.mnemonic + ' ' + ins.op_str,
                                 references=[hex(v) for v in refs]))
            functions[address] = dict(instructions=rows, references=references,
                warning=function.get('message', ''))

    def require_reference(function, target):
        if target not in functions[function]['references']:
            raise ValueError('Required launcher reference absent')

    keys = []
    for function, global_address, literal, label in (
            (0x1411b0260, 0x14b564cb0, 0x14952d138, 'buildCode'),
            (0x1411b04d0, 0x14b564ca0, 0x14952d120, 'gameCode'),
            (0x1411b0590, 0x14b564cf0, 0x14952d1b8, 'launcherToken')):
        for target in (global_address, literal, 0x141426c10):
            require_reference(function, target)
        offset = image.offset(literal - image.pe.base)
        data = (label + '\0').encode('utf-16le')
        if raw[offset:offset + len(data)] != data:
            raise ValueError('Launcher key literal changed')
        keys.append(dict(function=hex(function), global_address=hex(global_address), key=label))

    requests = []
    for function, endpoint, literal, callback, target, transport in (
            (0x1444ef840, 'launcher/token', 0x149532da0, 0x1444dfc20, 0x1444cd020, 0x144523b00),
            (0x144504980, 'launcher/sign-in', 0x149532fb0, 0x1444dfd10, 0x1444d45a0, 0x144523c80)):
        globals_used = [0x14b564d10, 0x14b564d00, 0x14b564d70, 0x14b564d80]
        globals_used += [0x14b564ca0, 0x14b564cb0, 0x14b564d20] if endpoint.endswith('/token') else [0x14b564cf0]
        for ref in globals_used + [literal, callback, transport, 0x149530ed0]:
            require_reference(function, ref)
        offset = image.offset(literal - image.pe.base)
        data = (endpoint + '\0').encode('utf-16le')
        if raw[offset:offset + len(data)] != data:
            raise ValueError('Launcher endpoint literal changed')
        offset = image.offset(callback - image.pe.base)
        jump = list(decoder.disasm(raw[offset:offset + 5], callback))
        if len(jump) != 1 or jump[0].mnemonic != 'jmp' or jump[0].operands[0].imm != target:
            raise ValueError('Launcher callback thunk changed')
        requests.append(dict(function=hex(function), endpoint=endpoint, callback=hex(callback),
            callback_bytes=bytes(jump[0].bytes).hex(), callback_root=hex(target), transport=hex(transport)))
    responses = []
    for function, getter, dispatcher in (
            (0x1444cd020, 0x14447dfd0, 0x1444e6360),
            (0x1444d45a0, 0x14447dd80, 0x1444e7630)):
        for ref in (0x14b564da0, 0x14b564df0, getter, dispatcher):
            require_reference(function, ref)
        responses.append(dict(function=hex(function), result_getter=hex(getter), dispatcher=hex(dispatcher),
            direct_sign_up_reference=0x144506cf0 in functions[function]['references']))
    return dict(schema=1, source=str(source), source_sha256=SOURCE_SHA,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), evidence=evidence,
        keys=keys, requests=requests, responses=responses,
        functions=[dict(address=hex(at), instruction_count=len(value['instructions']),
                        instructions=value['instructions'], warning=value['warning'])
                   for at, value in sorted(functions.items())],
        method='static', network_requests=0,
        limits=['Source-bound instructions and literal/reference checks; no native execution.',
                'References alone do not establish call-argument semantics or server acceptance.',
                'Callback references checked statically; no execution of JSON, dispatcher or consumer.',
                'SDK 1203 cause and indirect SignUp paths are not established.',
                'No account credentials, installed profile, process memory or token contents read.'])


if __name__ == '__main__':
    result = audit()
    payload = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    sha = hashlib.sha256(payload).hexdigest()
    target = load_native().ROOT / 'code-clues/release-launcher-contract' / sha / 'manifest.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_bytes() != payload:
        raise ValueError('Immutable launcher audit collision')
    if not target.exists(): target.write_bytes(payload)
    print(json.dumps(dict(report=str(target), sha256=sha, source_sha256=SOURCE_SHA,
                          functions=len(result['functions']), network_requests=0)))
