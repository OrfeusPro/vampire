"""Native response predicates/JSON/errorCode gates linked to field traversal."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('response_gate_fields', HERE / 'replay-sdk-sign-in-response-fields.py')
fields = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fields)
native, x = fields.native, fields.x
EARLY_STOPS = {0x1444cc314: 'response_predicates_rejected', 0x1444cc46a: 'json_object_rejected',
               0x1444cc627: 'nonzero_errorCode'}
LEAVES = {0x14452b040: 8, 0x1416340b0: 5, 0x1418089f0: 5, 0x140bd6440: 5}


class Replay(fields.Replay):
    def __init__(self, raw, image, base_report, fragments, ctor, evidence, crt, fixture):
        super().__init__(raw, image, base_report, fragments, ctor, fixture)
        self.crt = crt
        self.numeric_calls = []
        rows = [r for f in fragments if f['root_begin_rva'] == 0x44cc1a0 for r in f['instructions']
                if 0x1444cc2e9 <= r['address'] < 0x1444cc725]
        self.allowed.update(r['address'] for r in rows)
        self.allowed.update(EARLY_STOPS)
        for leaf in evidence['leaves']:
            self.allowed.update(i['address'] for i in leaf['instructions'])
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (*LEAVES, 0x14447fca0, 0x144478480, 0x144476d50, 0x144476940))
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
                continue
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.http_object, self.shared = self.base + 0xc000, self.base + 0xd000
        self.uc.mem_write(self.shared, struct.pack('<Q', self.http_object))
        self.uc.mem_write(self.callback + 8, struct.pack('<Q', 1))
        self.uc.mem_write(self.http_object + 4, struct.pack('<I', fixture['field_4']))
        self.uc.mem_write(self.http_object + 0x20, bytes([fixture['field_20']]))
        self.uc.mem_write(self.http_object + 0x28, struct.pack('<Q', fixture['status']))
        self.string(self.http_object + 0x30, fixture['json_text'])
        self.string(0x14b4f0b20, 'errorCode')
        self.numeric_hook = self.base + 0x7b000
        self.uc.mem_write(evidence['numeric_import']['iat_address'], struct.pack('<Q', self.numeric_hook))

    def hook(self, uc, address, size, user):
        if address in EARLY_STOPS:
            uc.emu_stop()
            return
        if address in fields.STOPS:
            return super().hook(uc, address, size, user)
        if address in self.allowed:
            return
        a, b, c = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8)]
        result = 0
        if address == 0x14447fca0:
            try:
                value = json.loads(self.text(b))
            except ValueError:
                value = None
            self.objects[a] = value
            result = a
        elif address == 0x144478480:
            result = int(isinstance(self.objects.get(a), dict))
        elif address == 0x144476d50:
            value = self.objects[a][self.text(c)]
            if not isinstance(value, str):
                raise ValueError('ErrorCode JSON variant fixture supports string values only')
            self.objects[b] = value
            uc.mem_write(b, struct.pack('<QQ', 0, 0))
            result = b
        elif address == 0x144476940:
            self.string(b, self.objects[a])
            result = b
        elif address == self.numeric_hook:
            value = self.wide(a)
            result = self.crt._wtoi(value)
            self.numeric_calls.append(dict(input=value, result=result))
            result &= 0xffffffff
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture_gates(self):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(x.UC_X86_REG_RCX, self.auth)
        self.uc.emu_start(0x1444bc380, self.stop, count=1024)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('SDK response constructor budget exceeded')
        rbp = self.stack + 0x100
        self.uc.mem_write(rbp + 0x308, struct.pack('<Q', self.shared))
        for register, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RBP, rbp),
                                (x.UC_X86_REG_RDI, self.callback), (x.UC_X86_REG_RDX, self.shared),
                                (x.UC_X86_REG_R13, self.shared), (x.UC_X86_REG_RBX, 0),
                                (x.UC_X86_REG_R15, 0), (x.UC_X86_REG_R14, 0xffffffff)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(0x1444cc2e9, fields.END, count=16384)
        rip = self.uc.reg_read(x.UC_X86_REG_RIP)
        stops = {**fields.STOPS, **EARLY_STOPS}
        if rip != fields.END and rip not in stops:
            raise ValueError('SDK response gate slice budget exceeded at ' + hex(rip))
        return dict(fixture=self.response_fixture, stage=stops.get(rip, 'player_fields_processed'),
                    numeric_calls=self.numeric_calls, sdk_access_token=self.text(self.module + 0x78),
                    game_region=self.text(self.module + 0x68), events=self.response_events)


def build():
    root = native.ROOT
    prior_path = root / 'code-clues/sdk-sign-in-response-fields-replay.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    base_report = json.loads((root / 'code-clues/headless-device-identity.json').read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('SDK response gate EXE changed')
    image = native.Image(raw)
    cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    leaves = []
    for address, size in LEAVES.items():
        offset = image.offset(address - image.pe.base)
        data = raw[offset:offset + size]
        instructions = list(cs.disasm(data, address))
        if sum(i.size for i in instructions) != size or instructions[-1].mnemonic != 'ret':
            raise ValueError('Response predicate/getter leaf changed')
        leaves.append(dict(address=address, file_offset=offset, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest(),
                           instructions=[dict(address=i.address, mnemonic=i.mnemonic, operands=i.op_str) for i in instructions]))
    imp_spec = importlib.util.spec_from_file_location('response_gate_imports', HERE / 'build-object-zero-init-code.py')
    imports = importlib.util.module_from_spec(imp_spec)
    imp_spec.loader.exec_module(imports)
    numeric_import = imports.import_at(raw, image, 0x148945bb0)
    if numeric_import['name'] != '_wtoi':
        raise ValueError('SDK response numeric import changed')
    crt_path = Path('C:/WINDOWS/System32/ucrtbase.dll')
    crt = ctypes.CDLL(str(crt_path))
    crt._wtoi.argtypes = [ctypes.c_wchar_p]
    crt._wtoi.restype = ctypes.c_int
    evidence = dict(leaves=leaves, numeric_import=numeric_import,
                    variant_conversion_static=native.decode_ranges(image, {image.roots[image.containing(0x144476940)]}),
                    crt=dict(path=str(crt_path), sha256=hashlib.sha256(crt_path.read_bytes()).hexdigest()))
    full = dict(resultData=dict(accessToken='new-sdk-token-fixture', playerInfo=dict(player=dict(playerId='player-fixture'))))
    fixtures = []
    for field_4 in (0, 1):
        for field_20 in (0, 1):
            fixtures.append(dict(name='predicates-'+str(field_4)+str(field_20), field_4=field_4, field_20=field_20,
                                 status=200, json_text=json.dumps(full)))
    for text in ('not-json', '[]', 'null'):
        fixtures.append(dict(name='non-object-'+text, field_4=0, field_20=0, status=200, json_text=text))
    for code in ('0', '0abc', '', 'oops', '1', '-1', '200', ' 0'):
        body = dict(full, errorCode=code)
        fixtures.append(dict(name='errorCode-'+repr(code), field_4=0, field_20=0, status=200, json_text=json.dumps(body)))
    for status in (199, 206, 207):
        fixtures.append(dict(name='status-'+str(status), field_4=0, field_20=0, status=status, json_text=json.dumps(full)))
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                source_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                evidence=evidence, cases=[Replay(raw, image, base_report, prior['fragments'], prior['constructor_leaf'],
                                                evidence, crt, fixture).capture_gates() for fixture in fixtures],
                native_execution=True, network_ready=False, limitations=[
                    'Native response field4/field20 predicates, status/body getters, callback gates, and prior player field slices execute.',
                    'JSON parse/object/variant/string conversion are explicit fixtures; errorCode JSON string domain only.',
                    'Numeric conversion calls verified local Windows CRT _wtoi; no silent locale/platform emulation.',
                    'Native predicate raw fields are fixtures; semantic labels beyond the tested truth table are not established.',
                    'Early error construction/dispatch and final success callback are stopped, not executed; owner/lifetime gates before entry omitted.',
                    'No live HTTP, accounts, tokens, registry, Saved or process memory used.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-sign-in-response-gates-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
