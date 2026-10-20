"""Native ChannelManager routing to launcher or ordinary SDK auth; no HTTP."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('routing_ping', HERE / 'build-headless-ping-codec.py')
ping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ping)
ROOT, BASE = ping.native.ROOT, 0x140000000
SIGN_IN, TOKEN = 0x1444fc5f0, 0x1444e5560
EXPORT = 'export-c7552efd2125/run-b8564958f914'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Replay:
    def __init__(self, raw, image, fragments, fixture):
        self.fixture, self.x = fixture, ping.x
        self.uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
        rows = [r for f in fragments if f['root_begin_rva'] + BASE in (SIGN_IN, TOKEN) for r in f['instructions']]
        self.allowed = {r['address'] for r in rows}
        hooks = {0x1444ba4f0, 0x144523ff0, 0x144525630, 0x1445209e0, 0x141dc1250,
                 0x1444e8130, 0x1444fd270, 0x1444fb730, 0x1444dd8a0,
                 0x1444bb4b0, 0x144521af0, 0x144517ef0, 0x1444aacb0, 0x144524d80,
                 0x1468e4100}
        pages = {a & ~4095 for a in self.allowed | hooks}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - BASE)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.base, self.stack, self.stop = 0x20000000, 0x20070000, 0x2007f000
        self.uc.mem_map(self.base, 0x80000)
        self.owner, self.service, self.auth_wrapper = (self.base + n for n in (0x1000, 0x2000, 0x3000))
        self.auth, self.credential, self.callback = (self.base + n for n in (0x4000, 0x5000, 0x6000))
        entries = self.base + 0x8000
        self.uc.mem_write(self.auth_wrapper, struct.pack('<Q', self.auth))
        self.uc.mem_write(self.owner + 0x20, struct.pack('<Q', entries))
        self.uc.mem_write(self.owner + 0x28, struct.pack('<I', int(fixture['credential_present'])))
        self.uc.mem_write(self.owner + 0x58, struct.pack('<i', 0))
        self.uc.mem_write(self.owner + 0x68, struct.pack('<I', 1))
        self.uc.mem_write(entries, bytes([fixture['channel']]))
        self.uc.mem_write(entries + 8, struct.pack('<QQ', self.credential, 0))
        self.uc.mem_write(entries + 0x18, struct.pack('<i', -1))
        self.uc.mem_write(self.credential + 0x50, bytes([fixture['channel']]))
        self.uc.mem_write(0x14b4f2060, b'\0')
        self.events, self.result = [], None
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)

    def text(self, address):
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(address, 16)))
        if count == 0:
            return ''
        if not 1 <= count <= capacity <= 128 or not self.base <= pointer < self.base + 0x80000 - count * 2:
            raise ValueError('Invalid routing FString fixture')
        payload = bytes(self.uc.mem_read(pointer, count * 2))
        if payload[-2:] != b'\0\0':
            raise ValueError('Unterminated routing FString fixture')
        return payload[:-2].decode('utf-16le')

    def string(self, address, text):
        pointer = self.base + 0x10000
        payload = (text + '\0').encode('utf-16le')
        self.uc.mem_write(pointer, payload)
        self.uc.mem_write(address, struct.pack('<QII', pointer, len(payload) // 2, len(payload) // 2))

    def finish(self, boundary, **values):
        self.result = dict(boundary=boundary, **values)
        self.uc.emu_stop()

    def hook(self, uc, address, size, user):
        if address in self.allowed:
            return
        x = self.x
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x1444ba4f0:
            self.events.append(dict(action='bind_callback_capture', owner_offset=hex(a - self.owner)))
        elif address == 0x144523ff0:
            result = self.base + 0xa000
            uc.mem_write(result, struct.pack('<Q', self.service if self.fixture['service_present'] else 0))
        elif address == 0x144525630:
            uc.mem_write(a, struct.pack('<QQ', b, 0))
            result = a
        elif address == 0x1445209e0:
            if a != self.service:
                raise ValueError('Routing lost service fixture')
            result = self.auth_wrapper
        elif address == 0x141dc1250:
            uc.mem_write(a, b'\0' * 64)
            result = a
        elif address == 0x1444bb4b0:
            result = self.base + 0xb000
        elif address == 0x144521af0:
            result = self.fixture['prior_channel']
        elif address == 0x144517ef0:
            result = int(self.fixture['supported'])
        elif address == 0x1444aacb0:
            result = self.base + 0xc000
            uc.mem_write(result + 0x110, struct.pack('<Q', self.base + 0xd000))
        elif address == 0x144524d80:
            self.string(b, self.fixture['saved_player'])
            result = b
        elif address == 0x1444dd8a0:
            self.finish('create_launcher_credential', owner_matches=a == self.owner)
            return
        elif address == 0x1468e4100:
            self.finish('before_error_allocation', size=a)
            return
        elif address in (0x1444e8130, 0x1444fd270):
            credential, control = struct.unpack('<QQ', bytes(uc.mem_read(b, 16)))
            self.finish('launcher_token' if address == 0x1444e8130 else 'launcher_sign_in',
                        auth_matches=a == self.auth, credential_matches=credential == self.credential,
                        credential_control_null=control == 0)
            return
        elif address == 0x1444fb730:
            credential, control = struct.unpack('<QQ', bytes(uc.mem_read(c, 16)))
            self.finish('ordinary_sign_in', auth_wrapper_matches=a == self.auth_wrapper,
                        player=self.text(b), credential_matches=credential == self.credential,
                        credential_null=credential == 0)
            return
        else:
            raise ValueError('Unreviewed routing target ' + hex(address))
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture(self):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for name, value in dict(rsp=self.stack, rcx=self.owner, rdx=self.fixture['channel'], r8=self.callback).items():
            self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name.upper()), value)
        self.uc.emu_start(SIGN_IN if self.fixture['operation'] == 'sign_in' else TOKEN, self.stop, count=8192)
        if self.result is None:
            raise ValueError('Routing failed to reach a reviewed handoff')
        return dict(fixture=self.fixture, result=self.result, events=self.events)


def build():
    prior_path = ROOT / 'code-clues/headless-auth-index.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Routing source changed')
    image = ping.native.Image(raw)
    fragments = ping.native.decode_ranges(image, {image.roots[image.containing(a)] for a in (SIGN_IN, TOKEN, 0x1444dec50)})
    fixtures = []
    for operation in ('sign_in', 'token'):
        for channel in (20, 33, 200, 255):
            for present in (False, True):
                fixtures.append(dict(operation=operation, channel=channel, credential_present=present,
                                     service_present=True, prior_channel=33, supported=True, saved_player=''))
        fixtures.append(dict(operation=operation, channel=33, credential_present=True,
                             service_present=False, prior_channel=33, supported=True, saved_player=''))
    for channel in (33, 100):
        for supported in (False, True):
            for saved in ('', 'saved-player-fixture'):
                fixtures.append(dict(operation='sign_in', channel=channel, credential_present=True,
                                     service_present=True, prior_channel=100, supported=supported, saved_player=saved))
    cases = [Replay(raw, image, fragments, f).capture() for f in fixtures]
    literal_helper_path = HERE / 'build-headless-sdk-config.py'
    spec = importlib.util.spec_from_file_location('routing_literals', literal_helper_path)
    literal_helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(literal_helper)
    diagnostics = [literal_helper.read_literal(raw, image, a) for a in (0x1494db400, 0x1494db7f0, 0x1494d9c00)]
    if any(value is None for value in diagnostics):
        raise ValueError('Routing diagnostic literal missing')
    output = ROOT / 'ghidra' / EXPORT
    provenance = json.loads((output / 'provenance.json').read_text('utf-8'))
    report_path = output / 'functions.json'
    if digest(report_path) != provenance['files']['functions.json']:
        raise ValueError('Routing Ghidra report changed')
    report = json.loads(report_path.read_text('utf-8'))
    functions = [f for f in report['functions'] if int(f['address'], 16) in (SIGN_IN, TOKEN, 0x1444dec50)]
    if len(functions) != 3 or report['source_sha256'] != prior['sha256']:
        raise ValueError('Routing Ghidra inventory/source mismatch')
    if any(not f['completed'] or digest(output / f['pseudocode_file']) != provenance['files'][f['pseudocode_file']] for f in functions):
        raise ValueError('Routing Ghidra pseudocode changed')
    return dict(source=prior['source'], source_sha256=prior['sha256'], tool_sha256=digest(Path(__file__)),
                upstream_sha256=digest(prior_path), fragments=fragments, cases=cases,
                diagnostic_literals=diagnostics, literal_helper_sha256=digest(literal_helper_path),
                ghidra_output=str(output), ghidra_report_sha256=digest(report_path),
                pseudocode_sha256={f['name']: digest(output / f['pseudocode_file']) for f in functions},
                network_used=False, limitations=[
                    'Native caller entry, channel branches and credential map lookups execute until reviewed handoff.',
                    'Service/SDK state, callback binding/copy, GetAuth and saved player are fixtures.',
                    'Callbacks are unbound; credential map has one item and no control block.',
                    'Stops before backend auth, credential creation or error allocation; no HTTP or SDK success.',
                    'Token dispatcher is static evidence only; actual consumer and official launch mode remain unknown.'])


if __name__ == '__main__':
    report = build()
    path = ROOT / 'code-clues/launcher-channel-routing-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=digest(path), cases=len(report['cases']))))
