"""Replay three bounded client arithmetic blocks, not whole-character battle power."""
import csv
import hashlib
import importlib.util
import json
import math
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
import unicorn
from unicorn import x86_const as x

ROOT = Path('F:/PhoneExit Resources/Vampir')
BLOCKS = [(0x145d2dc54, 0x145d2dc79), (0x145d2dd06, 0x145d2dd2c), (0x145d2ddde, 0x145d2de04)]


def f32(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def reference(value, weight, accumulator=0):
    product = f32(f32(value)*f32(weight))
    rounded = math.floor(product)
    converted = rounded if -(2**31) <= rounded < 2**31 else -(2**31)
    result = (accumulator+converted) & 0xffffffff
    return result if result < 2**31 else result-2**32


class WeightEmulator:
    def __init__(self, root=ROOT):
        spec = importlib.util.spec_from_file_location('weight_native', HERE/'build-native-entry-code.py')
        self.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.native)
        self.meta = json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
        self.raw = Path(self.meta['source']).read_bytes()
        if hashlib.sha256(self.raw).hexdigest() != self.meta['sha256']:
            raise ValueError('Changed native client')
        self.image = self.native.Image(self.raw)
        self.fragments = self.native.decode_ranges(self.image, {self.image.roots[self.image.containing(a)]
            for a in [0x145af0430, 0x145d2da30, 0x145ad69f0, 0x145b03700]})
        rows = {r['address']: r for f in self.fragments for r in f['instructions']}
        self.blocks = []
        for lo, hi in BLOCKS:
            selected = [r for a, r in sorted(rows.items()) if lo <= a < hi]
            if not selected or sum(len(bytes.fromhex(r['bytes'])) for r in selected) != hi-lo:
                raise ValueError('Block does not end on an instruction boundary')
            if [r['mnemonic'] for r in selected][-4:] != ['mulss', 'roundps', 'cvttss2si', 'add']:
                raise ValueError('Changed arithmetic')
            self.blocks.append(dict(start=lo, end=hi, instructions=selected))
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        page = BLOCKS[0][0] & ~4095
        self.uc.mem_map(page, 4096, unicorn.UC_PROT_ALL)
        self.uc.mem_write(page, self.raw[self.image.offset(page-self.image.pe.base):self.image.offset(page-self.image.pe.base)+4096])
        self.uc.mem_protect(page, 4096, unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.scratch = 0x20000000
        self.uc.mem_map(self.scratch, 4096)

    def execute(self, index, value, weight, accumulator=0):
        if not -(2**31) <= value < 2**31 or not -32768 <= weight <= 32767:
            raise ValueError('Expected signed int32 value and signed int16 weight')
        uc = self.uc
        memory = bytearray(4096)
        struct.pack_into('<h', memory, 0x8a, weight)
        struct.pack_into('<i', memory, 0x210, value)
        struct.pack_into('<i', memory, 0x324, value)
        uc.mem_write(self.scratch, bytes(memory))
        for reg in [x.UC_X86_REG_XMM0, x.UC_X86_REG_XMM2]:
            uc.reg_write(reg, 0)
        uc.reg_write(x.UC_X86_REG_MXCSR, 0x1f80)
        uc.reg_write(x.UC_X86_REG_RAX, self.scratch)
        uc.reg_write(x.UC_X86_REG_RBX, value & 0xffffffff if index==0 else self.scratch+0x200)
        uc.reg_write(x.UC_X86_REG_RDI, self.scratch+0x300)
        uc.reg_write(x.UC_X86_REG_RSI, accumulator & 0xffffffff)
        lo, hi = BLOCKS[index]
        uc.emu_start(lo, hi, count=32)
        if uc.reg_read(x.UC_X86_REG_RIP) != hi or bytes(uc.mem_read(self.scratch, 4096)) != bytes(memory):
            raise ValueError('Native block boundary or unexpected write')
        result = uc.reg_read(x.UC_X86_REG_ESI)
        return result if result < 2**31 else result-2**32


def main(root=ROOT):
    emulator = WeightEmulator(root)
    metadata = json.loads((root/'table-study/index-pakchunk1-Windows.json').read_text('utf-8-sig'))
    meta = next(t for t in metadata['tables'] if t['entry']==1427)
    path = root/'table-study'/meta['file']
    if hashlib.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Changed weight table')
    with path.open(encoding='utf-8-sig', newline='') as stream:
        rows = list(csv.DictReader(stream))
    cases = []
    for i, row in enumerate(rows):
        if row['CombatPowerWeight']=='':
            continue
        for value in [-7, -1, 0, 1, 25]:
            cases.append(dict(operation_id=row['OperationType'], csv_record=i+2, value=value,
                              weight=int(row['CombatPowerWeight']), accumulator=0))
    for value, weight, accumulator in [(16777217,1,0),(-16777217,1,0),(1000000,8000,0),
                                     (7,-3,13),(-7,3,-11),(1,1,2147483647)]:
        cases.append(dict(value=value,weight=weight,accumulator=accumulator,synthetic=True))
    for case in cases:
        results = [emulator.execute(i, case['value'], case['weight'], case['accumulator']) for i in range(3)]
        expected = reference(case['value'], case['weight'], case['accumulator'])
        if results != [expected]*3:
            raise ValueError('Native weight mismatch '+str(case))
        case.update(results=results, expected=expected)
    all_rows = {r['address']: r for f in emulator.fragments for r in f['instructions']}
    anchor_addresses = [0x145af0509,0x145af0517,0x145af05cd,0x145af05e4,0x145af064e,
                        0x145af088b,0x145af0891,0x145af08ad,0x145af0cfb,0x145af0d0b,
                        0x145d2dc29,0x145d2dc5b,0x145d2dd0e,0x145d2dde6,
                        0x145d2de2e,0x145d2de30]
    # Explicit selected anchors must exist; all surrounding bytes are retained in fragments.
    anchors = [all_rows[a] for a in anchor_addresses]
    report = dict(source=emulator.meta['source'], sha256=emulator.meta['sha256'],
        csv=dict(entry=1427,file=meta['file'],sha256=meta['sha256']), anchors=anchors,
        fragments=emulator.fragments, blocks=emulator.blocks, cases=cases,
        statistics=dict(case_count=len(cases), native_executions=len(cases)*3,
            explicit_weights=sum(r['CombatPowerWeight']!='' for r in rows),
            blank_weights=sum(r['CombatPowerWeight']=='' for r in rows)),
        scope='Bounded weighted-contribution blocks; real parser+consumer disassembly, synthetic input memory',
        formula='int32_wrap(accumulator + cvtt_int32(floor(float32(float32(value) * float32(int16(weight)))))))',
        verified=True, total_character_power_verified=False, stat_to_stat_formula_verified=False,
        limitations=['No OS calls, game execution or live process access; three math blocks only.',
                    'No CSV parser, object lookup, full loops, cache selection or caller context executed.',
                    'Caller owns cached result at +0xf0/+0xf4; actor/item identity and total battle-power meaning not proven here.',
                    'CVTTSS2SI outside int32 returns integer-indefinite INT_MIN; UI calculator rejects this range.',
                    'Blank CSV weights are not treated as zero; no edge to CombatPower is inferred.'])
    out = root/'code-clues/attribute-weight-evidence.json'
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), 'utf-8')
    print(json.dumps(report['statistics']))
    return report


if __name__ == '__main__':
    main()
