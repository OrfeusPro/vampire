"""Native JSON string/number-string variant conversion linked to response gates."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('response_variant_gates', HERE / 'replay-sdk-sign-in-response-gates.py')
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)
native, x = gates.native, gates.x
TABLES = {2: 0x1489cf248, 3: 0x1489cf398}


class NumberText(str):
    """Fixture parser preserves JSON numeric spelling; not a Python float model."""


class Replay(gates.Replay):
    def __init__(self, raw, image, base_report, fragments, ctor, evidence, crt, fixture, extra):
        super().__init__(raw, image, base_report, fragments, ctor, evidence, crt, fixture)
        self.variant_events = []
        rows = [r for f in extra['fragments'] if f['root_begin_rva'] in (0x4476940, 0x15e48f0, 0x15ef250)
                for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (*TABLES.values(), 0x14143c260))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])

    def hook(self, uc, address, size, user):
        if address not in (0x14447fca0, 0x144476d50, 0x14143c260):
            return super().hook(uc, address, size, user)
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        if address == 0x14447fca0:
            try:
                value = json.loads(self.text(b), parse_int=NumberText, parse_float=NumberText)
            except ValueError:
                value = None
            self.objects[a] = value
            result = a
        elif address == 0x144476d50:
            value = self.objects[a][self.text(c)]
            tag = 3 if isinstance(value, NumberText) else 2
            if not isinstance(value, str):
                raise ValueError('Native variant replay supports JSON string/numeric fixtures only')
            pointer = self.allocate(32)
            uc.mem_write(pointer, struct.pack('<QI', TABLES[tag], tag))
            self.string(pointer + 0x10, value)
            uc.mem_write(b, struct.pack('<QQ', pointer, 0))
            self.variant_events.append(dict(tag=tag, text=str(value)))
            result = b
        else:
            self.string(a, self.text(b))
            result = a
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)


def build():
    root = native.ROOT
    gates_path = root / 'code-clues/sdk-sign-in-response-gates-replay.json'
    gate_report = json.loads(gates_path.read_text('utf-8'))
    prior_path = root / 'code-clues/sdk-sign-in-response-fields-replay.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256'] or gate_report['sha256'] != prior['sha256']:
        raise ValueError('SDK response variant EXE changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in
        (0x144476940, 0x1415e48f0, 0x1415ef250, 0x14446eed0, 0x14446eff0, 0x14446f2c0)})
    bindings = []
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    for tag, instruction in ((2,0x14446ef13), (3,0x14446f044)):
        table = TABLES[tag]
        if rows[instruction]['rip_references'] != [table]:
            raise ValueError('JSON value factory/vtable binding changed')
        offset = image.offset(table - image.pe.base)
        data = raw[offset:offset + 0x68]
        target = struct.unpack_from('<Q',data,0x58)[0]
        if target != 0x1415ef250:
            raise ValueError('JSON value TryGetString vtable slot changed')
        bindings.append(dict(tag=tag, source_instruction=instruction, table=table, file_offset=offset,
                             bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(), try_get_string=target))
    extra = dict(fragments=fragments, bindings=bindings)
    crt_path = Path(gate_report['evidence']['crt']['path'])
    if hashlib.sha256(crt_path.read_bytes()).hexdigest() != gate_report['evidence']['crt']['sha256']:
        raise ValueError('SDK response CRT changed')
    crt = gates.ctypes.CDLL(str(crt_path))
    crt._wtoi.argtypes = [gates.ctypes.c_wchar_p]
    crt._wtoi.restype = gates.ctypes.c_int
    cases = []
    for code_text in ('0','1','-1','0.1','1e3','-0','0e2','2147483648', '"0"','"oops"'):
        fixture = dict(name='numeric-'+code_text, field_4=0, field_20=0, status=200,
            json_text='{"errorCode":'+code_text+',"resultData":{"accessToken":"new-sdk-token-fixture",'
                      '"playerInfo":{"player":{"playerId":"player-fixture"}}}}')
        replay = Replay(raw, image, base_report, prior['fragments'], prior['constructor_leaf'],
                        gate_report['evidence'], crt, fixture, extra)
        result = replay.capture_gates()
        result['variant_events'] = replay.variant_events
        cases.append(result)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                gate_report_sha256=hashlib.sha256(gates_path.read_bytes()).hexdigest(),
                evidence=extra, cases=cases, native_execution=True, network_ready=False, limitations=[
                    'Native variant converter, AsString wrapper and real TryGetString vtable target execute before actual CRT _wtoi.',
                    'Numeric fixtures use source-bound tag3 number-string representation; real JSON parser selection is not executed.',
                    'Parser/variant objects and FString assignment are fixtures; factory/vtable/tag/layout source is exported statically.',
                    'Double-number fallback formatting and bool/null/array/object variants not executed.',
                    'Other JSON/settings/module captures and callback stop boundaries remain those of response gate replay.',
                    'No real HTTP, account tokens, profiles, registry or network accessed.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-response-variant-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
