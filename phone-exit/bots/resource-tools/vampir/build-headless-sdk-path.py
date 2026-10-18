"""Execute native SDK path append; preserve auth caller and value-conversion code."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('path_map', HERE/'build-headless-sdk-map.py')
maps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(maps)
APPEND = 0x14142c9d0


class SDKPathEmulator(maps.SDKMapEmulator):
    def __init__(self):
        super().__init__()
        native = self.config.native
        self.fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)]
                for a in [APPEND, 0x1450e2640, 0x1450e2f50, 0x144476940]})
        self.base.ranges += [(self.image.pe.base+f['begin_rva'], self.image.pe.base+f['end_rva']) for f in self.fragments]
        pages = {a & ~4095 for begin, end in self.base.ranges for a in range(begin, end+4095, 4096)}
        regions = list(self.uc.mem_regions())
        for page in pages:
            if any(lo <= page <= hi for lo, hi, _ in regions):
                continue
            self.uc.mem_map(page, 4096)
            off = self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page, self.raw[off:off+4096])

    def append(self, base, segment, empty_count=0):
        self.reset()
        b = self.base.scratch
        left, right = base.encode('utf-16le', 'surrogatepass'), segment.encode('utf-16le', 'surrogatepass')
        if len(left) > 240 or len(right) > 240 or empty_count not in (0, 1):
            raise ValueError('Native path fixture exceeds bounds')
        pointer = self.allocate(4096)
        self.uc.mem_write(pointer, left+b'\0\0')
        count = len(left)//2+1 if left else empty_count
        self.uc.mem_write(b+0x1000, struct.pack('<QII', pointer, count, 2048))
        self.uc.mem_write(b+0x4000, right+b'\0\0')
        self.base.call(APPEND, b+0x1000, b+0x4000, len(right)//2)
        if any(kind in self.calls for kind in ['0x1414313d0']):
            raise ValueError('Unexpected path allocation')
        return dict(base=base, segment=segment, empty_count=empty_count, result=self.text(b+0x1000))


def main():
    emulator = SDKPathEmulator()
    cases = []
    for base in ['', 'https://auth.invalid', 'https://auth.invalid/', 'https://auth.invalid\\',
                 '/', 'a//', 'a', 'a?x=1', 'база😀']:
        for segment in ['v2/access-token', '/v2/access-token', '\\v2/access-token', '', '/', '//x', 'часть😀']:
            for empty_count in ([0, 1] if not base else [0]):
                case = emulator.append(base, segment, empty_count)
                if not segment:
                    expected = base if not base or base.endswith(('/', '\\')) else base+'/'
                elif base and not base.endswith(('/', '\\')) and not segment.startswith('/'):
                    expected = base+'/'+segment
                else:
                    expected = base+segment
                if case['result'] != expected:
                    raise ValueError('Native path append differs')
                cases.append(case)
    constants = []
    for f in emulator.fragments:
        for row in f['instructions']:
            for target in row['rip_references']:
                literal = emulator.config.read_literal(emulator.raw, emulator.image, target)
                if literal:
                    constants.append(dict(**literal, instruction=row))
    report = dict(schema_version=1, source=emulator.base.bindings['source'], sha256=emulator.base.bindings['sha256'],
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), fragments=emulator.fragments,
                  constants=constants, cases=cases, statistics=dict(native_path_cases=len(cases)), network_ready=False,
                  limitations=['Actual path append executed with preallocated capacity; no string growth branch.',
                      'External memcpy uses bounded existing shim; Unicode is UTF16 units, not URL encoding.',
                      'Auth callers/value conversion are static evidence only; no requests or response acquisition.',
                      'Path concatenation is not URL validity, normalization or server compatibility.'])
    path = emulator.base.bindings_path.parent/'headless-sdk-path.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', 'utf-8')
    print(json.dumps(dict(output=str(path), **report['statistics'])))


if __name__ == '__main__':
    main()
