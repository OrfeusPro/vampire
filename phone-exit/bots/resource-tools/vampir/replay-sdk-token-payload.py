"""Native token container/padding/JSON-object gates with explicit split/decode fixtures."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('token_payload_lifecycle', HERE / 'replay-device-key-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
native, x = lifecycle.guid.source.config.native, lifecycle.x
PARSER = 0x144537b20


class Replay(lifecycle.Replay):
    def __init__(self, raw, image, base_report, fragments, fixture):
        super().__init__(raw, image, base_report, {})
        self.parser_fixture = fixture
        self.objects = {}
        self.decode_calls = []
        rows = [r for f in fragments if f['root_begin_rva'] == PARSER - image.pe.base for r in f['instructions']]
        self.allowed.update(r['address'] for r in rows)
        pages = {r['address'] & ~4095 for r in rows}
        pages.update(a & ~4095 for r in rows for a in r['rip_references'])
        pages.update(a & ~4095 for a in (0x14142c810, 0x141424430, 0x14451d4e0, 0x14447fca0,
                                        0x14444b5e0, 0x14446fa60, 0x144478480, 0x1413ff0e0))
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
        if address in self.allowed:
            return
        a, b, c, d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8, x.UC_X86_REG_R9)]
        result = 0
        if address == 0x14142c810:
            segments = self.parser_fixture['segments']
            pointer = self.allocate(max(16, len(segments) * 16))
            for n, value in enumerate(segments):
                self.string(pointer + n * 16, value)
            uc.mem_write(b, struct.pack('<QII', pointer, len(segments), len(segments)))
            self.events.append(dict(action='split_fixture', cull_empty_argument=bool(d)))
        elif address == 0x141424430:
            text = bytes(uc.mem_read(b, c * 2)).decode('utf-16le') if c else ''
            self.string(a, self.text(a) + text)
            result = a
        elif address == 0x14451d4e0:
            encoded = self.text(b)
            try:
                decoded = base64.b64decode(encoded.replace('-', '+').replace('_', '/'), validate=True).decode('utf-8')
                self.string(c, decoded)
                result = 1
            except (ValueError, UnicodeError):
                self.string(c, '')
            self.decode_calls.append(dict(encoded=encoded, returned=bool(result)))
        elif address == 0x14447fca0:
            try:
                value = json.loads(self.text(b))
            except ValueError:
                value = None
            self.objects[a] = value
            result = a
        elif address == 0x14444b5e0:
            self.objects[a] = self.objects.get(b)
            result = a
        elif address == 0x144478480:
            result = int(isinstance(self.objects.get(a), dict))
        elif address in (0x14446fa60, 0x1413ff0e0):
            pass
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(x.UC_X86_REG_RAX, result)
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        target = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, target)

    def capture(self):
        desc = self.base + 0x6000
        self.string(desc, '.'.join(self.parser_fixture['segments']))
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for register, value in ((x.UC_X86_REG_RSP, self.stack), (x.UC_X86_REG_RCX, self.output), (x.UC_X86_REG_RDX, desc)):
            self.uc.reg_write(register, value)
        self.uc.emu_start(PARSER, self.stop, count=8192)
        if self.uc.reg_read(x.UC_X86_REG_RIP) != self.stop:
            raise ValueError('Token payload caller instruction budget exceeded')
        return dict(fixture=self.parser_fixture, accepted=bool(self.uc.reg_read(x.UC_X86_REG_RAX) & 255),
                    decode_calls=self.decode_calls, header=self.objects.get(self.output),
                    payload=self.objects.get(self.output + 0x38), events=self.events)


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode('utf-8')).decode('ascii').rstrip('=')


def build():
    root = native.ROOT
    base_path = root / 'code-clues/headless-device-identity.json'
    prior = json.loads(base_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('Token payload source changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in
                                           (PARSER, 0x14451d4e0, 0x144478480, 0x14454c7a0, 0x1411b31c0)})
    literals = []
    for f in fragments:
        for row in f['instructions']:
            if row['mnemonic'] == 'lea':
                for ref in row['rip_references']:
                    if lit := lifecycle.guid.source.config.read_literal(raw, image, ref):
                        literals.append(dict(instruction=row['address'], **lit))
    header, payload = encode({'alg': 'fixture'}), encode({'sub': 'B' * 32})
    fixtures = [dict(name='objects', segments=[header, payload, 'AAAA']),
                dict(name='no-alg-check', segments=[encode({'alg': 'none'}), payload, 'AAAA']),
                dict(name='non-base64-signature', segments=[header, payload, '!?!?']),
                dict(name='two-segments', segments=[header, payload]),
                dict(name='four-segments', segments=[header, payload, 'AAAA', 'AAAA']),
                dict(name='bad-header-length', segments=['A', payload, 'AAAA']),
                dict(name='bad-payload-length', segments=[header, 'A', 'AAAA']),
                dict(name='bad-signature-length', segments=[header, payload, 'A']),
                dict(name='header-not-object', segments=[encode([]), payload, 'AAAA']),
                dict(name='payload-not-object', segments=[header, encode([]), 'AAAA']),
                dict(name='bad-header-base64', segments=['!!!!', payload, 'AAAA']),
                dict(name='bad-header-json', segments=['YWJj', payload, 'AAAA']),
                dict(name='missing-sub', segments=[header, encode({}), 'AAAA'])]
    for size in range(3):
        fixtures.append(dict(name='padding-' + str(size), segments=[encode({'a': 'b' * size}), payload, 'AA']))
    cases = [Replay(raw, image, prior, fragments, fixture).capture() for fixture in fixtures]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=fragments, literals=literals, cases=cases, native_execution=True, network_ready=False,
                limitations=[
                    'Full native caller executes segment-count/padding/object-gate sequencing on explicit split/decode/JSON fixtures.',
                    'Split output is a fixture; native empty-segment/cull semantics not executed.',
                    'Base64url-to-UTF8 decode and JSON parsing/assignment/IsObject are fixtures; their helper source exported separately.',
                    'Third segment only participates in length/padding gates here; no signature/alg/expiry/issuer/sub validation proved.',
                    'Acceptance is this local caller outcome only, not SDK/server acceptance or active auth session.',
                    'No real tokens, command line, identities, profiles, registry or network accessed.'])


if __name__ == '__main__':
    report = build()
    path = native.ROOT / 'code-clues/sdk-token-payload-replay.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), cases=len(report['cases']))))
