"""Real local endpoint getter -> connection callback -> Version, with Winsock fixtures."""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

version = module('address_version', 'replay-connected-version-packet.py')
native, x = version.native, version.x
ENDPOINT = 0x1445e7680
SYSCALLS = {'getsockname': 0x30000400, 'inet_ntoa': 0x30000410, 'ntohs': 0x30000420}


class Replay(version.Replay):
    def __init__(self, *args, body_fragments, local_fragments, imports, fixture):
        super().__init__(*args, body_fragments=body_fragments, fixture=fixture)
        rows = [r for f in local_fragments for r in f['instructions']]
        self.local_allowed = {r['address'] for r in rows}
        self.allowed.update(self.local_allowed)
        self.local_hooks = {*SYSCALLS.values(), 0x1421e1620, 0x1445ddd10,
                            0x141446940, 0x141440ba0, 0x141421dd0}
        pages = {a & ~4095 for r in rows for a in
                 (r['address'], r['address'] + len(bytes.fromhex(r['bytes'])) - 1, *r['rip_references'])}
        pages.update(a & ~4095 for a in self.local_hooks)
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()): continue
            self.uc.mem_map(page, 4096)
            try: off = args[1].offset(page - self.image_base)
            except ValueError: continue
            self.uc.mem_write(page, args[0][off:off + 4096])
        for info in imports:
            self.uc.mem_write(info['iat'], struct.pack('<Q', SYSCALLS[info['export']['name']]))
        self.ip_text = self.allocate(32)
        self.uc.mem_write(self.ip_text, fixture['endpoint_ip'].encode('ascii') + b'\0')

    def hook(self, uc, address, size, user):
        if address in self.local_allowed: return
        if address not in self.local_hooks: return super().hook(uc, address, size, user)
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == SYSCALLS['getsockname']:
            if a != self.fixture['handle'] or int.from_bytes(uc.mem_read(c, 4), 'little') != 16:
                raise ValueError('Local socket handle/address length changed')
            result = self.fixture['sockname_return']
            if result == 0:
                uc.mem_write(b, struct.pack('<H', 2) + struct.pack('>H', 23456)
                             + ipaddress.IPv4Address(self.fixture['endpoint_ip']).packed + b'\0' * 8)
            self.events.append(dict(action='getsockname_fixture', returned=result))
        elif address == SYSCALLS['inet_ntoa']:
            if a != int.from_bytes(ipaddress.IPv4Address(self.fixture['endpoint_ip']).packed, 'little'):
                raise ValueError('Native local IPv4 argument changed')
            result = self.ip_text
        elif address == SYSCALLS['ntohs']:
            result = int.from_bytes((a & 0xffff).to_bytes(2, 'little'), 'big')
        elif address == 0x1421e1620:
            if c > 15: raise ValueError('Only bounded IPv4 SSO constructor fixture')
            uc.mem_write(a, bytes(uc.mem_read(b, c)) + b'\0' * (16 - c) + struct.pack('<QQ', c, 15))
            result = a
        elif address == 0x1445ddd10:
            if c > 15: raise ValueError('Only bounded IPv4 SSO assignment fixture')
            uc.mem_write(a, bytes(uc.mem_read(b, c)) + b'\0' * (16 - c) + struct.pack('<QQ', c, 15))
            result = a
        elif address == 0x141446940:
            data = bytes(uc.mem_read(b, c))
            if not data.isascii(): raise ValueError('Only ASCII IPv4 length fixture')
            result = len(data)
        elif address == 0x141440ba0:
            data = bytes(uc.mem_read(c, d))
            if not data.endswith(b'\0') or not data.isascii(): raise ValueError('Only terminated ASCII IPv4 decode fixture')
            uc.mem_write(a, data.decode('ascii').encode('utf-16le'))
        elif address == 0x141421dd0:
            data = bytearray()
            for n in range(32):
                unit = bytes(uc.mem_read(b + n * 2, 2))
                if unit == b'\0\0': break
                data.extend(unit)
            else: raise ValueError('IPv4 FString bound')
            self.fwrite(a, data.decode('utf-16le'))
            result = a
        uc.reg_write(x.UC_X86_REG_RAX, result & 0xffffffffffffffff)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = int.from_bytes(uc.mem_read(rsp, 8), 'little')
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)


def build():
    names = ('connected-version-packet-replay.json', 'transport-connected-delegate-replay.json',
             'socket-ready-notification-replay.json', 'socket-readiness-job-replay.json', 'socket-error-option-replay.json')
    paths = [native.ROOT / 'code-clues' / n for n in names]
    prior, delegate, notify, ready, opt = [json.loads(p.read_text('utf-8')) for p in paths]
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']: raise ValueError('Client changed')
    image = native.Image(raw)
    local = native.decode_ranges(image, {image.roots[image.containing(ENDPOINT)]})
    off = image.offset(0x141408910 - image.pe.base)
    data = raw[off:off + 5]
    if data.hex() != '488d4108c3': raise ValueError('Endpoint string accessor changed')
    local.append(dict(address=0x141408910, file_offset=off, bytes=data.hex(), instructions=[
        dict(address=0x141408910, bytes='488d4108', mnemonic='lea', operands='rax, [rcx + 8]', rip_references=[]),
        dict(address=0x141408914, bytes='c3', mnemonic='ret', operands='', rip_references=[])]))
    imp = module('address_imports', 'build-headless-send-drain.py')
    dll = Path(opt['winsock_dll']['path'])
    dllraw = dll.read_bytes()
    if hashlib.sha256(dllraw).hexdigest() != opt['winsock_dll']['sha256']: raise ValueError('Winsock DLL changed')
    imports = []
    for r in local[0]['instructions']:
        if r['mnemonic'] == 'call' and r['rip_references']:
            iat = r['rip_references'][0]
            try: info = imp.ordinal_import(raw, image, iat)
            except ValueError: continue  # Other imports include the CRT invalid-parameter guard.
            export = version.delegate.notification.option.ready.connect.export_name(dllraw, native.Image(dllraw), info)
            if export['name'] in SYSCALLS: imports.append(dict(iat=iat, import_info=info, export=export))
    if {r['export']['name'] for r in imports} != set(SYSCALLS): raise ValueError('Local endpoint imports changed')
    args = (raw, image, ready['fragments'], ready['completion_leaf'], ready['handle_leaf'], opt['option_body'],
            notify['fragments'], notify['leaves'], delegate['fragments'], delegate['leaves'])
    fixtures = [dict(prior['cases'][0]['fixture'], name='local-' + ip, endpoint_ip=ip, sockname_return=0)
                for ip in ('127.0.0.1', '10.20.30.40', '203.0.113.8', '0.0.0.0')]
    fixtures.append(dict(fixtures[0], name='local-unavailable', sockname_return=-1))
    cases = []
    for f in fixtures:
        result = Replay(*args, body_fragments=prior['fragments'], local_fragments=local, imports=imports, fixture=f).capture()
        expected = f['endpoint_ip'] if f['sockname_return'] == 0 else ''
        if result['packet']['strings']['0x58'] != expected: raise ValueError('Native connected address did not reach Version')
        cases.append(result)
    return dict(source=prior['source'], source_sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        upstream={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
        fragments=local, imports=imports, winsock_dll=opt['winsock_dll'], cases=cases,
        limitations=['Actual local endpoint getter, transport callback, delegate, Version preparation and constructor execute.',
                     'Winsock, SSO/FString memory and ASCII-only conversions are bounded fixtures; socket error path preserves empty callback text.',
                     'Inherited readiness/scheduler/owner fixtures remain; Version sender captured, no network or server policy proof.',
                     'Synthetic addresses only; no game launch, process memory, profile or credentials.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/connected-local-address-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
