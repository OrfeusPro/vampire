"""Source-bound NID result routing/keys audit; no auth or runtime promotion."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
EXPORT = 'run-2493cfa0c5bc'
EXPORT_SHA = 'a530c6c39e49e29fea6593b3c0d0d12cf1628c441f7601a00b02240679450d5a'
KEYS = {0x14b5d5878:'result', 0x14b5d5918:'resultCode', 0x14b5d5928:'accessToken',
    0x14b5d5938:'refreshToken', 0x14b5d58d8:'channelKey', 0x14b5d5948:'netmarbleId',
    0x14b5d5958:'joinedCountryCode'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def audit(root=None):
    native = load('nid_result_source', HERE/'build-native-entry-code.py')
    root = Path(root) if root else native.ROOT
    source = root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA: raise ValueError('NID result source SHA changed')
    image = native.Image(raw)
    path = root/'ghidra/request-exports'/SHA/EXPORT/'details.json'
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != EXPORT_SHA: raise ValueError('NID result export SHA changed')
    report = json.loads(payload)
    if report['new_source_sha256'] != SHA: raise ValueError('NID result export source differs')
    functions = {int(f['address'],16):f for f in report['functions']}
    if set(functions) != {0x1450f2c80,0x1450f3e40}: raise ValueError('NID result roots differ')
    for f in functions.values():
        if not f['decompilation_completed'] or not f['block_coverage_complete']: raise ValueError('NID result export incomplete')
        for row in f['instructions']:
            data = bytes.fromhex(row['bytes']); offset = image.offset(int(row['address'],16)-image.pe.base)
            if raw[offset:offset+len(data)] != data: raise ValueError('NID result instruction bytes differ')
    def pinned(owner, at, data):
        rows = [r for r in functions[owner]['instructions'] if int(r['address'],16) == at]
        if len(rows) != 1 or rows[0]['bytes'] != data: raise ValueError('NID result route/gate differs')
        return rows[0]
    route = pinned(0x1450f2c80,0x1450f30bb,'e8800d0000')
    gate = pinned(0x1450f3e40,0x1450f43a1,'41f78750010000faffffff')
    # Resolve only tiny initializer roots with LEA destination references.
    refs = native.rip_candidates(image,set(KEYS))
    roots = set()
    for address,target in refs:
        containing = image.containing(address)
        if containing is not None:
            body = image.roots[containing]
            if body == containing and body[1]-body[0] <= 64: roots.add(body)
    if not 1 <= len(roots) <= 16: raise ValueError('NID result initializer root budget')
    fragments = native.decode_ranges(image,roots,functions=sorted(roots))
    bindings = []
    for fragment in fragments:
        rows = fragment['instructions']
        if len(rows) != 7: continue
        literal, destination, call = rows[1:4]
        if (literal['mnemonic'],destination['mnemonic'],call['mnemonic']) != ('lea','lea','call'): continue
        if not literal['operands'].startswith('rdx,') or not destination['operands'].startswith('rcx,'): continue
        if len(literal['rip_references']) != 1 or len(destination['rip_references']) != 1: continue
        address = destination['rip_references'][0]
        if address not in KEYS: continue
        if call['direct_target'] != 0x141426b30: raise ValueError('NID result initializer constructor differs')
        pointer = literal['rip_references'][0]; off = image.offset(pointer-image.pe.base)
        data = raw[off:off+128]
        end = next((n for n in range(0,128,2) if data[n:n+2] == bytes(2)),None)
        if end is None: raise ValueError('NID result key literal bound')
        text = data[:end].decode('utf-16le')
        if text != KEYS[address]: raise ValueError('NID result key binding differs')
        bindings.append(dict(global_address=hex(address),text=text,literal=hex(pointer),
            initializer=hex(fragment['root_begin_rva']+image.pe.base),instructions=rows))
    if len(bindings) != len(KEYS) or {int(r['global_address'],16) for r in bindings} != set(KEYS):
        raise ValueError('NID result key initializer missing/ambiguous')
    for address in KEYS:
        owners = [f for f in functions.values() if any(hex(address) in r['text'] for r in f['instructions'])]
        if not owners: raise ValueError('NID result descriptor unused')
    diagnostics = []
    for name,owner in (('OnDeepLink',0x1450f2c80),('OnResult',0x1450f3e40)):
        matches = []
        for row in functions[owner]['instructions']:
            data = bytes.fromhex(row['bytes']); at = int(row['address'],16)
            cs = native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64); cs.detail = True
            ins = next(cs.disasm(data,at))
            if ins.mnemonic != 'lea': continue
            for op in ins.operands:
                if op.type != native.X86_OP_MEM or op.mem.base != native.X86_REG_RIP: continue
                target = at+ins.size+op.mem.disp
                try: off = image.offset(target-image.pe.base)
                except ValueError: continue
                value = raw[off:off+256].split(b'\0')[0]
                expected = ('bool' if name=='OnDeepLink' else 'void')+' __cdecl Netmarble::Service::FNetmarbleIDContent::'+name+'(const class FString &)'
                if value == expected.encode('ascii'): matches.append(dict(address=hex(target),text=expected,instruction=row['address']))
        if not matches: raise ValueError('NID result diagnostic missing')
        diagnostics.append(dict(owner=hex(owner),matches=matches))
    return dict(schema=1,source=str(source),source_sha256=SHA,
        evidence=[dict(path=str(path),sha256=EXPORT_SHA)],diagnostics=diagnostics,bindings=bindings,
        route=route,auth_mode_gate=gate,instructions_checked=sum(len(f['instructions']) for f in functions.values()),
        initializer_roots=len(roots),native_execution=False,network_ready=False,runtime_enabled=False,
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('audit-nid-result-11316.py','build-native-entry-code.py','extract-native-enums.py')},
        limits=['Static source-bound routing CALL, auth mode mask, diagnostic signatures and seven key initializer bindings only.',
            'Whole validation behavior, missing/empty fields, integer/channel parsing, setters, callback delivery, persistence and authentication are not executed.'])


if __name__ == '__main__':
    report = audit(); snapshots = load('nid_result_save',HERE/'audit-client-release.py')
    path = snapshots.save_snapshot(Path('F:/PhoneExit Resources/Vampir/code-clues/nid-result-source-11316'),report)
    print(json.dumps(dict(report=str(path),instructions=report['instructions_checked'],bindings=len(report['bindings']))))
