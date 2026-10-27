"""Verify explicit ID 4 registration links against a full source SHA; no execution."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(context, root):
    root = Path(root)
    sha = context['source_sha256']
    index = load('knowledge-index').api()
    raw = load('update-bindings').source(index, root, sha)
    source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
    if Path(context['source']).resolve() != source.resolve():
        raise ValueError('Registration source path differs')
    native = load('build-native-entry-code')
    if native.capstone.__version__ != '5.0.6':
        raise ValueError('Pinned registration decoder required')
    image = native.Image(raw)

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def data(at, size):
        off = image.offset(at - image.pe.base)
        return raw[off:off + size]

    b = {name: int(value, 16) for name, value in context['bindings'].items()}
    at = int(context['window']['address'], 16)
    code = bytes.fromhex(context['window']['bytes'])
    require(len(code) <= 256 and data(at, len(code)) == code, 'Registration window differs')
    require(hashlib.sha256(code).hexdigest() == context['window']['sha256'], 'Registration window SHA differs')
    part = image.containing(at)
    require(part is not None and image.pe.base + image.roots[part][0] == b['owner'], 'Registration owner differs')
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    rows = list(decoder.disasm(code, at))
    require(sum(row.size for row in rows) == len(code), 'Registration instruction gap')
    # Allocation, table store, packet construction and the three registration arguments.
    shape = [(r.mnemonic, r.op_str) for r in rows]
    expected = [
        ('mov', 'ecx, 8'), ('call', hex(b['allocate'])), ('mov', 'rdi, rax'),
        ('test', 'rax, rax'), ('je', hex(at + 30)),
        ('lea', 'rax, [rip + ' + hex(rows[5].operands[1].mem.disp) + ']'), ('mov', 'qword ptr [rdi], rax'),
        ('jmp', hex(at + 33)), ('mov', 'rdi, rbx'), ('mov', 'ecx, 0x140'),
        ('call', hex(b['allocate'])), ('test', 'rax, rax'), ('je', hex(at + 58)),
        ('mov', 'rcx, rax'), ('call', hex(b['packet_constructor'])),
        ('jmp', hex(at + 61)), ('mov', 'rax, rbx'),
        ('mov', 'r8, rdi'), ('mov', 'rdx, rax'), ('mov', 'rcx, rsi'),
        ('call', hex(b['register'])),
    ]
    require(shape == expected, 'Registration argument/control-flow shape differs')
    lea = rows[5]
    require(lea.address + lea.size + lea.operands[1].mem.disp == b['handler_table'], 'Registration handler table link differs')
    require(struct.unpack('<Q', data(b['handler_table'] + 0x10, 8))[0] == b['handler'], 'Registration handler slot differs')
    require(struct.unpack('<Q', data(b['packet_table'] + 0x28, 8))[0] == b['id_getter'], 'Registration packet ID slot differs')
    require(data(b['id_getter'], 6) == b'\xb8\x04\x00\x00\x00\xc3', 'Registration ID getter differs')
    exports, functions = [], {}
    for run, digest in context['exports'].items():
        path = root / 'ghidra/request-exports' / sha / run / 'details.json'
        payload = path.read_bytes()
        require(hashlib.sha256(payload).hexdigest() == digest, 'Registration export SHA differs')
        report = json.loads(payload)
        require(report['new_source_sha256'] == sha, 'Registration export source differs')
        exports.append(dict(path=str(path), sha256=digest))
        for f in report['functions']:
            if int(f['address'], 16) in (b['handler'], b['register'], b['packet_constructor']):
                require(f['decompilation_completed'] and f['block_coverage_complete'], 'Registration export incomplete')
                for row in f['instructions']:
                    instruction = bytes.fromhex(row['bytes'])
                    require(data(int(row['address'], 16), len(instruction)) == instruction, 'Registration export instruction differs')
                functions[int(f['address'], 16)] = f
    require(set(functions) == {b['handler'], b['register'], b['packet_constructor']}, 'Registration export root missing')
    bindings = load('update-bindings')
    calls = {}
    for name in ('handler', 'register', 'packet_constructor'):
        calls[name] = {hex(r['address']): hex(r['direct_target']) if r['direct_target'] is not None else r['operands']
                       for r in bindings.rows(native, image, b[name]) if r['call']}
    require(calls == context['call_sites'], 'Registration callees differ')
    constructor = bindings.rows(native, image, b['packet_constructor'])
    require(any(b['packet_table'] in r['rip_references'] for r in constructor), 'Registration packet table constructor link differs')
    return dict(schema=1, source_sha256=sha, method='static', bindings=context['bindings'],
                window=context['window'], call_sites=calls, evidence=exports,
                network_used=False, native_execution=False, profile_activated=False,
                limits=['Exact registration window and table/ID links only; no allocation outcome or live dispatch proof.',
                        'Handler export/call inventory is not execution of success/error gates or state writes.',
                        'No whole oversized registration export, automatic call-tree expansion or runtime promotion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    args = parser.parse_args()
    result = verify(json.loads(args.context.read_text('utf-8')), args.root)
    result.update(context_sha256=hashlib.sha256(args.context.read_bytes()).hexdigest(),
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    path = load('research-workflow').snapshot(args.root, 'login-result-registration', result)
    print(json.dumps(dict(report=str(path), bindings=result['bindings'])))
