"""Execute launcherToken key/header preparation and the response channel slice."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('launcher_token_ping', HERE / 'build-headless-ping-codec.py')
ping = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ping)
ROOT = ping.native.ROOT
BASE = 0x140000000
INITIALIZE, KEY = 0x1411b0460, 0x14b4f0a70
HEADER = (0x1444fd4c0, 0x1444fd4f7)
CHANNEL = (0x1444cd8e0, 0x1444cd8f4)
FUNCTIONS = (INITIALIZE, 0x1444c5910, 0x1444cce90, 0x1444fd270)
GHIDRA_EXPORT = 'export-c7552efd2125/run-a32e792f4d73'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def caller_candidates(raw, image):
    helper_path = HERE / 'build-entry-window-code.py'
    spec = importlib.util.spec_from_file_location('launcher_direct_calls', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    targets = {0x1444e8130, 0x1444fd270}
    candidates = []
    for section in image.pe.sections:
        if section['name'] == '.text':
            candidates.extend(helper.direct_call_candidates(raw, section['raw'], section['raw_size'], image.pe.address, targets))
    roots = {image.roots[c] for a, _ in candidates if (c := image.containing(a)) is not None}
    fragments = helper.native.decode_ranges(image, roots)
    rows = {r['address']: r for f in fragments for r in f['instructions']}
    calls = [dict(instruction=rows[a], target=hex(t), root=hex(BASE + image.roots[image.containing(a)][0]))
             for a, t in candidates if helper.checked_call(rows.get(a), t)]
    unresolved = [dict(address=hex(a), target=hex(t)) for a, t in candidates if not helper.checked_call(rows.get(a), t)]
    return dict(helper_sha256=digest(helper_path), calls=calls, unresolved=unresolved, fragments=fragments,
                limits='Direct calls only; not exhaustive for wrappers, tail jumps or virtual dispatch. Caller role unverified.')


class Replay:
    def __init__(self, raw, image, fragments):
        self.raw, self.image, self.x = raw, image, ping.x
        self.uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
        self.base, self.stack, self.stop = 0x20000000, 0x20030000, 0x2003f000
        self.uc.mem_map(self.base, 0x40000)
        selected = [r for f in fragments for r in f['instructions']
                    if f['root_begin_rva'] + BASE == INITIALIZE
                    or HEADER[0] <= r['address'] < HEADER[1]
                    or CHANNEL[0] <= r['address'] < CHANNEL[1]]
        self.allowed = {r['address'] for r in selected}
        hooks = {0x141421150, 0x1487964ac, 0x143bf76c0}
        pages = {a & ~4095 for a in self.allowed | hooks | {KEY}}
        pages.update(a & ~4095 for r in selected for a in r['rip_references'])
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
            try:
                offset = image.offset(page - BASE)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.cursor, self.events, self.header = self.base + 0x10000, [], None
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)

    def string(self, address, value):
        payload = (value + '\0').encode('utf-16le')
        if len(payload) > 1024 or self.cursor + len(payload) >= self.base + 0x20000:
            raise ValueError('Launcher string fixture budget exceeded')
        self.uc.mem_write(self.cursor, payload)
        self.uc.mem_write(address, struct.pack('<QII', self.cursor, len(payload) // 2, len(payload) // 2))
        self.cursor += (len(payload) + 15) & ~15

    def text(self, address):
        pointer, count, capacity = struct.unpack('<QII', bytes(self.uc.mem_read(address, 16)))
        if not 1 <= count <= capacity <= 512 or not self.base <= pointer < self.base + 0x20000 - count * 2:
            raise ValueError('Invalid launcher FString fixture')
        payload = bytes(self.uc.mem_read(pointer, count * 2))
        if payload[-2:] != b'\0\0':
            raise ValueError('Unterminated launcher FString fixture')
        return payload[:-2].decode('utf-16le')

    def hook(self, uc, address, size, user):
        if address in self.allowed:
            return
        x = self.x
        a, b = (uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX))
        if address == 0x141421150:
            offset = self.image.offset(b - BASE)
            end = next(n for n in range(0, 256, 2) if self.raw[offset + n:offset + n + 2] == b'\0\0')
            self.string(a, self.raw[offset:offset + end].decode('utf-16le'))
            uc.reg_write(x.UC_X86_REG_RAX, a)
            self.events.append(dict(kind='FString_constructor_fixture', destination=hex(a)))
        elif address == 0x1487964ac:
            self.events.append(dict(kind='atexit_capture', callback=hex(a)))
            uc.reg_write(x.UC_X86_REG_RAX, 0)
        elif address == 0x143bf76c0:
            begin, end = struct.unpack('<QQ', bytes(uc.mem_read(b, 16)))
            if end - begin != 16:
                raise ValueError('Unexpected launcher header pair count')
            key, value = struct.unpack('<QQ', bytes(uc.mem_read(begin, 16)))
            self.header = (self.text(key), self.text(value))
            self.events.append(dict(kind='header_map_capture', key=self.header[0]))
            uc.reg_write(x.UC_X86_REG_RAX, a)
        else:
            raise ValueError('Unreviewed launcher token target ' + hex(address))
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def run(self, begin, end, **registers):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(self.x.UC_X86_REG_RSP, self.stack)
        for name, value in registers.items():
            self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name.upper()), value)
        self.uc.emu_start(begin, end, count=1024)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP) != end:
            raise ValueError('Launcher token instruction budget exceeded')

    def initialize_and_header(self, token):
        self.run(INITIALIZE, self.stop)
        pair, credential = self.base + 0x1000, self.base + 0x2000
        self.uc.mem_write(pair, struct.pack('<Q', credential))
        self.string(credential + 0x58, token)
        self.run(*HEADER, r12=pair, rbp=self.stack + 0x100)
        return dict(token_fixture=token, key=self.text(KEY), header=list(self.header), events=list(self.events))

    def channel(self, *, present, raw_channel, prior_channel):
        closure, credential, module = (self.base + n for n in (0x1000, 0x2000, 0x3000))
        self.uc.mem_write(closure + 0x20, struct.pack('<Q', credential if present else 0))
        self.uc.mem_write(credential + 0x50, bytes([200]))
        self.uc.mem_write(credential + 0x68, bytes([raw_channel]))
        self.uc.mem_write(module + 0x88, bytes([prior_channel]))
        self.run(*CHANNEL, rdi=closure, r15=module)
        return dict(credential_present=present, credential_channel_code=200, credential_channel_68=raw_channel,
                    prior_module_channel=prior_channel, module_channel=self.uc.mem_read(module + 0x88, 1)[0])


def build():
    prior_path = ROOT / 'code-clues/headless-auth-index.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Launcher token source changed')
    image = ping.native.Image(raw)
    fragments = ping.native.decode_ranges(image, {image.roots[image.containing(a)] for a in FUNCTIONS})
    cs = ping.native.capstone.Cs(ping.native.capstone.CS_ARCH_X86, ping.native.capstone.CS_MODE_64)
    thunks = []
    for address, target in ((0x1444d8510, 0x1444c5910), (0x1444d8600, 0x1444cce90)):
        offset = image.offset(address - BASE)
        instruction = next(cs.disasm(raw[offset:offset + 16], address))
        if instruction.mnemonic != 'jmp' or instruction.op_str != hex(target):
            raise ValueError('Launcher callback thunk changed')
        data = bytes(instruction.bytes)
        thunks.append(dict(address=hex(address), target=hex(target), file_offset=offset,
                           bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest()))
    headers = [Replay(raw, image, fragments).initialize_and_header(v) for v in ('', 'launcher-token-fixture', 'a.+/=_-')]
    channels = [Replay(raw, image, fragments).channel(present=present, raw_channel=channel, prior_channel=prior)
                for present in (False, True) for channel in (0, 20, 33, 200, 255) for prior in (7,)]
    output = ROOT / 'ghidra' / GHIDRA_EXPORT
    report_path = output / 'functions.json'
    provenance = json.loads((output / 'provenance.json').read_text('utf-8'))
    if digest(report_path) != provenance['files']['functions.json']:
        raise ValueError('Launcher token Ghidra report changed')
    ghidra = json.loads(report_path.read_text('utf-8'))
    functions = [f for f in ghidra['functions'] if int(f['address'], 16) in FUNCTIONS]
    if ghidra['source_sha256'] != prior['sha256'] or len(functions) != len(FUNCTIONS):
        raise ValueError('Launcher token Ghidra source/inventory mismatch')
    if any(not f['completed'] or digest(output / f['pseudocode_file']) != provenance['files'][f['pseudocode_file']] for f in functions):
        raise ValueError('Launcher token Ghidra pseudocode mismatch')
    return dict(source=prior['source'], source_sha256=prior['sha256'], tool_sha256=digest(Path(__file__)),
                upstream_sha256=digest(prior_path), fragments=fragments, callback_thunks=thunks,
                headers=headers, channels=channels, callers=caller_candidates(raw, image), ghidra_output=str(output),
                ghidra_report_sha256=digest(report_path),
                pseudocode_sha256={f['name']: digest(output / f['pseudocode_file']) for f in functions},
                network_used=False, limitations=[
                    'Only key initializer, custom-header preparation and response channel assignment execute.',
                    'FString constructor and header map are explicit fixtures/captures; atexit captured.',
                    'Channel/credential/module and token are synthetic fixtures, not active game values.',
                    'HTTP response gates, JSON traversal, callbacks and SDK lifecycle are static evidence only.',
                    'No actual launcher token acquisition or successful game Login established.'])


if __name__ == '__main__':
    result = build()
    path = ROOT / 'code-clues/launcher-token-context-replay.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=digest(path), headers=len(result['headers']), channels=len(result['channels']))))
