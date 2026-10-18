"""Native response field lookup, length conversion and receive comparison slices."""
import ctypes
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('length_head', HERE / 'build-headless-cdn-response-head.py')
head = importlib.util.module_from_spec(spec)
spec.loader.exec_module(head)
LOOKUP, PARSE = 0x1445ea4a0, 0x1445edb30
STRNCPY_CALL, STRNICMP_CALL, ATOI_CALL = 0x1445ea5a2, 0x1445ea666, 0x1445edf36
COMPARE_START, READY, WAIT = 0x1445e968c, 0x1445e96dd, 0x1445e9cb5


class LengthEmulator(head.ResponseHeadEmulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        addresses = [LOOKUP, PARSE, 0x1445dbe60, 0x1445dbef0, 0x1445dc0f0,
                     0x1445ddd10, 0x1421e1620, 0x1445d8310]
        roots = {image.roots[image.containing(a)][0] for a in addresses}
        extra = [(image.pe.base + f['begin_rva'], image.pe.base + f['end_rva'])
                 for f in fragments if f['root_begin_rva'] in roots]
        extra += [(COMPARE_START, READY)]
        self.allowed.extend(extra)
        pages = {a & ~4095 for lo, hi in extra for a in range(lo, hi + 4095, 4096)}
        pages.update(a & ~4095 for a in [READY, WAIT, 0x1445dc650, 0x1445dec90])
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
        self.crt._strnicmp.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        self.crt._strnicmp.restype = ctypes.c_int
        self.crt.atoi.argtypes = [ctypes.c_char_p]
        self.crt.atoi.restype = ctypes.c_int
        self.compare_stop = None

    def return_from_shim(self, result, kind):
        x, uc = self.x, self.uc
        rsp = uc.reg_read(x.UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX, result & 0xffffffffffffffff)
        uc.reg_write(x.UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(x.UC_X86_REG_RIP, ret)
        self.calls.append(dict(kind=kind))

    def hook(self, machine, address, size, user):
        x = self.x
        if address in (READY, WAIT):
            self.compare_stop = address
            machine.emu_stop()
            return
        a, b, c = [machine.reg_read(reg) for reg in [x.UC_X86_REG_RCX, x.UC_X86_REG_RDX, x.UC_X86_REG_R8]]
        if address == head.STRSTR:
            needle = self.cstring(b, 8)
            if needle not in (b'\r\n', b'\r\n\r\n'):
                raise ValueError('Unexpected response field delimiter')
            self.bounded(a, 1)
            offset = self.cstring(a, 4096).find(needle)
            self.return_from_shim(a + offset if offset >= 0 else 0, 'bounded_strstr')
            return
        if address == 0x1487a2e25:
            self.bounded(a, c)
            machine.mem_write(a, bytes([b & 255]) * c)
            self.return_from_shim(a, 'bounded_memset')
            return
        if address in (STRNCPY_CALL, STRNICMP_CALL):
            self.bounded(a, c)
            self.bounded(b, c)
            left, right = bytes(machine.mem_read(a, c)), bytes(machine.mem_read(b, c))
            if address == STRNCPY_CALL:
                source = right.split(b'\0', 1)[0]
                machine.mem_write(a, source.ljust(c, b'\0'))
                result, kind = a, 'bounded_strncpy'
            else:
                result = self.crt._strnicmp(left, right, c)
                kind = 'actual_system_crt_strnicmp'
            machine.reg_write(x.UC_X86_REG_RAX, result & 0xffffffff if address == STRNICMP_CALL else result)
            machine.reg_write(x.UC_X86_REG_RIP, address + 6)
            self.calls.append(dict(kind=kind))
            return
        if address == ATOI_CALL:
            self.bounded(a, 1)
            result = self.crt.atoi(self.cstring(a, 512))
            machine.reg_write(x.UC_X86_REG_RAX, result & 0xffffffff)
            machine.reg_write(x.UC_X86_REG_RIP, address + 6)
            self.calls.append(dict(kind='actual_system_crt_atoi', result=result))
            return
        if address in (0x1445dc650, 0x1445dec90):
            self.return_from_shim(machine.reg_read(x.UC_X86_REG_RAX),
                                  'log_capture' if address == 0x1445dc650 else 'progress_capture')
            return
        return super().hook(machine, address, size, user)

    def probe(self, payload, initial_length=0, expect_lookup_budget=False):
        if not isinstance(payload, bytes) or len(payload) > 2048 or not -(1 << 31) <= initial_length < (1 << 31):
            raise ValueError('Response length fixture exceeds local bounds')
        owner, data = self.scratch + 0x1000, self.scratch + 0x10000
        self.uc.mem_write(data, payload + b'\0')
        self.uc.mem_write(owner + 0x488, struct.pack('<QQ', data, data + len(payload)))
        self.uc.mem_write(owner + 0x4d0, struct.pack('<qQ', initial_length, len(payload)))
        # Prefix executes both actual literal lookups, stopping before range diagnostics.
        try:
            self.run(PARSE, stop=0x1445edc9b, rcx=owner)
        except ValueError as error:
            if not expect_lookup_budget or str(error) != 'Preparation instruction budget exceeded':
                raise
            return dict(payload_hex=payload.hex(), initial_length_fixture=initial_length,
                        instruction_budget_exhausted=True,
                        stopped_at=self.uc.reg_read(self.x.UC_X86_REG_RIP),
                        instruction_budget=32768, calls_count=len(self.calls),
                        last_calls=self.calls[-8:], nul_terminated_fixture=True)
        if expect_lookup_budget:
            raise ValueError('Expected folded fixture budget exhaustion did not occur')
        rsp = self.uc.reg_read(self.x.UC_X86_REG_RSP)
        length_text, range_text = self.text(rsp + 0x70), self.text(rsp + 0x50)
        self.put(self.stack + 0x70, length_text)
        self.run(0x1445edf20, stop=0x1445edf46, rsi=owner, r15=0, rbp=self.stack + 0x100)
        declared = struct.unpack('<q', bytes(self.uc.mem_read(owner + 0x4d0, 8)))[0]
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(self.x.UC_X86_REG_RSP, self.stack)
        self.uc.reg_write(self.x.UC_X86_REG_RSI, owner + 0x38)
        self.uc.emu_start(COMPARE_START, self.stop, count=32768)
        if self.compare_stop not in (READY, WAIT):
            raise ValueError('Native receive comparison did not reach a reviewed boundary')
        return dict(payload_hex=payload.hex(), initial_length_fixture=initial_length,
                    length_text=length_text, range_text=range_text, declared_length=declared,
                    receive_ready=self.compare_stop == READY, compare_stop=self.compare_stop,
                    calls=list(self.calls), nul_terminated_fixture=True)


def build():
    native = head.headers.uri.http.preparation.url.settings.config.native
    root = native.ROOT
    prior_path = root / 'code-clues/headless-cdn-response-head.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = native.Image(raw)
    addresses = [head.HEAD_SIZE, head.STATUS, head.AVAILABLE, head.SCAN,
                 LOOKUP, PARSE, 0x1445dbe60, 0x1445dbef0, 0x1445dc0f0, 0x1445ddd10,
                 0x1421e1620, 0x1445d8310, 0x1445e95f0]
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in addresses})
    rows = {i['address']: i for f in fragments for i in f['instructions']}
    imports_module = head.headers.uri.http.preparation.url.settings.load('length_imports', HERE / 'build-object-zero-init-code.py')
    imports = []
    for address, expected in [(STRNCPY_CALL, 'strncpy'), (STRNICMP_CALL, '_strnicmp'), (ATOI_CALL, 'atoi')]:
        imported = imports_module.import_at(raw, image, rows[address]['rip_references'][0])
        if imported['name'] != expected:
            raise ValueError('Response length import changed')
        imports.append(dict(instruction=address, **imported))
    config = head.headers.uri.http.preparation.url.settings.config
    literals = []
    for fragment in fragments:
        if fragment['root_begin_rva'] != PARSE - image.pe.base:
            continue
        for row in fragment['instructions']:
            for address in row['rip_references']:
                literal = config.read_literal(raw, image, address)
                if literal:
                    literals.append(dict(instruction=row['address'], **literal))
    values = ['0', '1', '2', '3', '0002', ' 2 ', '\t2\t', '+2', '-1', '2junk', 'nope', '',
              '2147483647', '2147483648', '4294967295']
    payloads = [(b'HTTP/1.1 200 OK\r\nContent-Length: ' + v.encode('ascii') + b'\r\n\r\n{}', 0) for v in values]
    payloads += [(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n' + body, 0) for body in (b'', b'{', b'{}', b'{}x')]
    payloads += [(b'HTTP/1.1 200 OK\r\n' + fields + b'\r\n{}', initial) for fields, initial in [
        (b'content-length: 2\r\n', 0), (b'CONTENT-LENGTH=2\r\n', 0),
        (b'Content-Length: 2\r\nContent-Length: 9\r\n', 0),
        (b'Content-Length: 9\r\nContent-Length: 2\r\n', 0),
        (b'X-Content-Length: 2\r\n', 0),
        (b'Content-Length : 2\r\n', 0), (b'Transfer-Encoding: chunked\r\n', 0),
        (b'Content-Range: bytes 0-1/2\r\nContent-Length: 2\r\n', 0),
        (b'', 0), (b'', 7), (b'Content-Length:\r\n', 7)]]
    cases = [LengthEmulator(raw, image, fragments).probe(payload, initial) for payload, initial in payloads]
    folded = LengthEmulator(raw, image, fragments).probe(
        b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n 3\r\n\r\n{}', expect_lookup_budget=True)
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                head_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, literals=literals, imports=imports, system_crt=prior['system_crt'], cases=cases,
                bounded_abort_cases=[folded],
                network_ready=False, limitations=[
                    'Parser prefix executes both header lookups and native whitespace trimming; explicit NUL-terminated contiguous fixtures.',
                    'Range validation/diagnostics middle is skipped, not a whole parser or receive-loop execution.',
                    'Native conversion/write and unsigned receive comparison slices execute; log/progress capture shims.',
                    'strstr/strncpy/memory/allocator bounded shims; _strnicmp/atoi use actual recorded Windows CRT.',
                    'Initial content length is a fixture; constructor lifecycle, EOF/chunked/body decode/JSON/TLS remain unproven.'])


if __name__ == '__main__':
    report = build()
    target = head.headers.uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-response-length.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_cases=len(report['cases'])), indent=2))
