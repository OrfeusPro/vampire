"""Native CDN parser-result/ReadJson branch slices with explicit return fixtures."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('json_body', HERE / 'build-headless-cdn-body.py')
body = importlib.util.module_from_spec(spec)
spec.loader.exec_module(body)
PARSED, FALLBACK, READ_ENTRY = 0x145642c79, 0x145642c88, 0x145643107
READ, VALIDATE, ERROR, NEXT = 0x14565a5d0, 0x145661a70, 0x145643146, 0x145643213


class JsonFlowEmulator(body.BodyEmulator):
    def __init__(self, raw, image, fragments):
        super().__init__(raw, image, fragments)
        extra = [(PARSED, FALLBACK), (READ_ENTRY, ERROR)]
        self.allowed.extend(extra)
        rows = {i['address']: i for f in fragments for i in f['instructions']}
        self.flag_global = rows[0x14564312f]['rip_references'][0]
        pages = {a & ~4095 for a in [PARSED, FALLBACK, READ_ENTRY, READ, VALIDATE, ERROR, NEXT, self.flag_global]}
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
        self.boundary = None
        self.mode = None
        self.read_fixture, self.validate_fixture = False, False

    def hook(self, machine, address, size, user):
        if ((self.mode == 'parser' and address in (FALLBACK, READ_ENTRY)) or
                (self.mode == 'read' and address in (ERROR, NEXT))):
            self.boundary = address
            machine.emu_stop()
            return
        if address in (READ, VALIDATE):
            x = self.x
            if (machine.reg_read(x.UC_X86_REG_RCX), machine.reg_read(x.UC_X86_REG_RDX)) != (
                    self.scratch + 0x1000, self.stack + 0x20):
                raise ValueError('Unexpected CDN JSON result context')
            result = self.read_fixture if address == READ else self.validate_fixture
            rsp = machine.reg_read(x.UC_X86_REG_RSP)
            ret = struct.unpack('<Q', bytes(machine.mem_read(rsp, 8)))[0]
            machine.reg_write(x.UC_X86_REG_RAX, int(result))
            machine.reg_write(x.UC_X86_REG_RSP, rsp + 8)
            machine.reg_write(x.UC_X86_REG_RIP, ret)
            self.calls.append(dict(kind='readjson_return_fixture' if address == READ else 'validation_return_fixture'))
            return
        return super().hook(machine, address, size, user)

    def execute(self, start, **registers):
        self.uc.mem_write(self.stack, struct.pack('<Q', self.stop))
        self.uc.reg_write(self.x.UC_X86_REG_RSP, self.stack)
        for name, value in registers.items():
            self.uc.reg_write(getattr(self.x, 'UC_X86_REG_' + name.upper()), value)
        self.uc.emu_start(start, self.stop, count=32768)
        if self.boundary is None:
            raise ValueError('JSON branch fixture exceeded reviewed bounds')

    def parser_result(self, success, object_present):
        self.mode = 'parser'
        self.uc.mem_write(self.stack + 0x20, struct.pack('<Q', self.scratch + 0x5000 if object_present else 0))
        self.execute(PARSED, rax=int(success), rdi=0)
        return dict(parser_success_fixture=success, object_present_fixture=object_present,
                    stopped_at=self.boundary, goes_to_readjson=self.boundary == READ_ENTRY,
                    parser_executed=False)

    def read_result(self, read_success, validate_success, flag):
        self.mode = 'read'
        self.read_fixture, self.validate_fixture = read_success, validate_success
        self.uc.mem_write(self.scratch + 0x11a1, bytes([flag]))
        self.uc.mem_write(self.flag_global, b'\xa5')
        self.execute(READ_ENTRY, r13=self.scratch + 0x1008, r12=1)
        return dict(read_success_fixture=read_success, validate_success_fixture=validate_success,
                    source_flag_fixture=flag, stopped_at=self.boundary,
                    reaches_next_branch=self.boundary == NEXT,
                    result_flag=self.uc.reg_read(self.x.UC_X86_REG_R12B),
                    global_flag=bytes(self.uc.mem_read(self.flag_global, 1))[0], calls=list(self.calls),
                    readjson_and_validation_executed=False)


def build():
    native = body.head.headers.uri.http.preparation.url.settings.config.native
    prior_path = native.ROOT / 'code-clues/headless-cdn-fallback.json'
    prior = json.loads(prior_path.read_text('utf-8'))
    raw = Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != prior['sha256']:
        raise ValueError('EXE changed')
    image = native.Image(raw)
    fragments = native.decode_ranges(image, {image.roots[image.containing(a)] for a in [body.CALLBACK, READ, VALIDATE]})
    parser_cases = [JsonFlowEmulator(raw, image, fragments).parser_result(success, present)
                    for success in (False, True) for present in (False, True)]
    read_cases = [JsonFlowEmulator(raw, image, fragments).read_result(read, validate, flag)
                  for read in (False, True) for validate in (False, True) for flag in (0, 1)]
    return dict(schema_version=1, source=prior['source'], sha256=prior['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fallback_report_sha256=hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                fragments=fragments, parser_cases=parser_cases, read_cases=read_cases, network_ready=False,
                limitations=['Actual native branches/call arguments/global flag copy execute with explicit parser/object/read/validation return fixtures.',
                             'JSON parser, whole ReadJson, validation and full callback are not executed; static roots preserved only.',
                             'Reaching next branch is not full callback acceptance: later platform/request-state/lifecycle branches remain.',
                             'No actual CDN data, network, process or account files used.'])


if __name__ == '__main__':
    report = build()
    target = body.head.headers.uri.http.preparation.url.settings.config.native.ROOT / 'code-clues/headless-cdn-json-flow.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                          native_branch_cases=len(report['parser_cases']) + len(report['read_cases'])), indent=2))
