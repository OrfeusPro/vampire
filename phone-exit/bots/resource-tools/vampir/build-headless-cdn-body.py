"""Execute native CDN body/BOM helper on bounded synthetic response buffers."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('body_head', HERE / 'build-headless-cdn-response-head.py')
head = importlib.util.module_from_spec(spec)
spec.loader.exec_module(head)
BODY, WIDE_CTOR, WIDE_CONVERT, UNIT_CONVERT = 0x1445e6fc0, 0x144416f20, 0x1445eb700, 0x1445eb7f0
CALLBACK, STATUS_REJECT, STATUS_ACCEPT = 0x145642a30, 0x145642a6d, 0x145642a7b


class BodyEmulator(head.ResponseHeadEmulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        addresses = [BODY, WIDE_CTOR, WIDE_CONVERT, UNIT_CONVERT, 0x1421e1620,
                     0x1445ddc80, 0x1445d8310]
        roots = {image.roots[image.containing(a)][0] for a in addresses}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        extra.append((CALLBACK, STATUS_ACCEPT))
        self.allowed.extend(extra)
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        for f in fragments:
            for row in f['instructions']:
                if any(lo <= row['address'] < hi for lo, hi in extra):
                    pages.update(a & ~4095 for a in row['rip_references'])
        regions = list(self.uc.mem_regions())
        for page in sorted(pages):
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            try:
                off = image.offset(page - image.pe.base)
            except ValueError:
                continue
            self.uc.mem_write(page, raw[off:off + 4096])
        self.body_bounds = None
        self.wide_requests = []
        self.status_stop = None

    def hook(self, machine, address, size, user):
        if address in (STATUS_ACCEPT, STATUS_REJECT):
            self.status_stop = address
            machine.emu_stop()
            return
        if address == WIDE_CTOR:
            pointer = machine.reg_read(self.x.UC_X86_REG_RDX)
            units = machine.reg_read(self.x.UC_X86_REG_R8)
            if self.body_bounds is None or not self.body_bounds[0] <= pointer <= self.body_bounds[1]:
                raise ValueError('Unexpected wide-body source')
            available = self.body_bounds[1] - pointer
            self.wide_requests.append(dict(units=units, bytes_requested=2 * units,
                                           source_bytes_remaining=available,
                                           beyond_body_bytes=max(0, 2 * units - available)))
        return super().hook(machine, address, size, user)

    def status_gate(self, status):
        if type(status) is not int or not 0 <= status <= 0xffffffff:
            raise ValueError('Invalid status fixture')
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        for name, value in dict(rsp=self.stack, rcx=self.scratch + 0x1000,
                                rdx=self.scratch + 0x2000, r8=status).items():
            self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name.upper()), value)
        self.uc.emu_start(CALLBACK, self.stop, count=32768)
        if self.status_stop not in (STATUS_ACCEPT, STATUS_REJECT):
            raise ValueError('Callback status gate did not reach a reviewed boundary')
        return dict(status=status, stopped_at=self.status_stop,
                    enters_body_branch=self.status_stop == STATUS_ACCEPT,
                    callback_prefix_only=True)

    def string_bytes(self, address):
        length, capacity = struct.unpack('<QQ', bytes(self.uc.mem_read(address + 16, 16)))
        pointer = struct.unpack('<Q', bytes(self.uc.mem_read(address, 8)))[0] if capacity > 15 else address
        self.bounded(pointer, length + 1)
        result = bytes(self.uc.mem_read(pointer, length + 1))
        if not result.endswith(b'\0'):
            raise ValueError('Native body string lacks a terminator')
        return result[:-1]

    def probe(self, body, guard=b'\0'):
        if not isinstance(body, bytes) or len(body) > 256 or guard not in (b'\0', b'Z'):
            raise ValueError('Body fixture exceeds local bounds')
        prefix = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        payload = prefix + body
        obj, data, output = self.scratch + 0x1000, self.scratch + 0x10000, self.scratch + 0x6000
        # Explicit readable guard, outside the declared buffer. This is not game memory.
        self.uc.mem_write(data, payload + b'\0' + guard * 1024)
        self.uc.mem_write(obj + 0x18, struct.pack('<QQ', data, data + len(payload)))
        self.body_bounds = (data + len(prefix), data + len(payload))
        self.run(BODY, rcx=obj, rdx=output)
        result = self.string_bytes(output)
        return dict(body_hex=body.hex(), guard_byte_hex=guard.hex(), header_hex=prefix.hex(),
                    output_hex=result.hex(), output_length=len(result), wide_requests=self.wide_requests,
                    calls=list(self.calls), contiguous_nul_terminated_fixture=True,
                    bytes_after_declared_buffer_are_explicit_fixture=True)


def build():
    native = head.headers.uri.http.preparation.url.settings.config.native
    prior_path = native.ROOT / 'code-clues/headless-cdn-response-head.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = native.Image(raw)
    addresses = [head.HEAD_SIZE, head.STATUS, head.AVAILABLE, head.SCAN, BODY, WIDE_CTOR,
                 WIDE_CONVERT, UNIT_CONVERT, 0x1421e1620, 0x1445ddc80, 0x1445d8310, CALLBACK]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    bodies = [b'', b'{}', b'{"ok":true}', 'Привет'.encode(), b'a\0b', b'\xff', b'\xef', b'\xef\xbb',
              b'\xef\xbb\xbf', b'\xef\xbb\xbf{}', b'\xef\xbb\xbf' + 'Привет'.encode(),
              b'\xef\xbb\xbf\xef\xbb\xbf{}', b'\xef\xbb\x00{}', b'\xff\xfe', b'\xfe\xff\x00{\x00}',
              b'x' * 15, b'x' * 16, b'x' * 180]
    bodies += [b'\xff\xfe' + text.encode('utf-16le') for text in ['A', '{}', 'Привет', '\u07ff\u0800', '😀', 'x' * 18]]
    bodies += [b'\xff\xfe\x41', b'\xff\xfe\x00\xd8', b'\xff\xfe\x00\xdc']
    cases = [BodyEmulator(raw, image, fragments).probe(body) for body in bodies]
    guard_cases = [BodyEmulator(raw, image, fragments).probe(body, b'Z')
                   for body in [b'\xff\xfeA\0', b'\xff\xfe{\0}\0', b'{}', b'\xef\xbb\xbf{}']]
    status_cases = [BodyEmulator(raw, image, fragments).status_gate(status)
                    for status in [0, 199, 200, 204, 206, 299, 300, 404, 0xffffffff]]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                head_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, cases=cases, guard_cases=guard_cases,
                status_gate_cases=status_cases, network_ready=False,
                limitations=[
                    'Whole native body helper and wide constructors/unit conversion execute on explicit synthetic contiguous NUL-terminated buffers.',
                    'Bounded memory/search/allocator/cookie shims; no Content-Encoding/chunked/EOF/decompression/JSON or live receive lifecycle.',
                    'Guard bytes beyond declared payload are deliberate fixtures, never game/process/account memory.',
                    'Wide constructor requests are recorded independently of declared body size; native output may include guard bytes.',
                    'UTF-16 code units are encoded individually; surrogate semantics are observations, not validated Unicode.',
                    'CDN callback status prefix only executed; remaining callback instructions are static evidence, including NUL scan before UTF-8 conversion.'])


if __name__ == '__main__':
    report = build()
    target = head.headers.uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-body.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases']) + len(report['guard_cases']),
                          status_gate_cases=len(report['status_gate_cases'])), indent=2))
