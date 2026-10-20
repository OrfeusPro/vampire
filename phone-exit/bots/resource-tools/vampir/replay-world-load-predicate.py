"""Native load predicate -> actual World lookup/LevelPath getter/comparison.

Registry allocation, record template copy and FString storage retain the
documented bounded fixtures. No server or live registry is used.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('load_predicate_world', HERE / 'replay-world-state-label.py')
world = importlib.util.module_from_spec(spec)
spec.loader.exec_module(world)
native, x = world.native, world.x
PREDICATE, COMPARE, LABEL = 0x145dc0830, 0x1414596e0, 0x145dc3f30


class Emulator(world.Emulator):
    def __init__(self):
        super().__init__()
        manifest_raw = (native.ROOT / 'ghidra/entry-manifest.json').read_bytes()
        self.manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        manifest = json.loads(manifest_raw)
        names = {'WorldMoveStart_LoadPredicate', 'WorldMoveStart_CompareLevelPath'}
        self.predicate_ranges = [r for f in manifest['functions'] if f['name'] in names for r in f['ranges']]
        if len(self.predicate_ranges) != 2:
            raise ValueError('Missing predicate/comparison Ghidra sources')
        for r in self.predicate_ranges:
            lo, hi = int(r['start'], 16), int(r['end_exclusive'], 16)
            off = r['file_offset']
            if hashlib.sha256(self.raw[off:off + hi - lo]).hexdigest() != r['sha256']:
                raise ValueError('Predicate source changed')
            self.ranges.append((lo, hi))
            for page in range(lo & ~4095, (hi + 4095) & ~4095, 4096):
                self.map_page(page)
        off = self.image.offset(0x1499f11f0 - self.image.pe.base)
        table = self.raw[off:off + 0xd0]
        if (struct.unpack_from('<Q', table, 0xa8)[0], struct.unpack_from('<Q', table, 0xc8)[0]) != (PREDICATE, LABEL):
            raise ValueError('Predicate/label table slots changed')
        self.service_table = table.hex()
        self.map_page(0x1499f11f0 & ~4095)
        fragments = native.decode_ranges(self.image, {self.image.roots[self.image.containing(PREDICATE)]})
        # The reviewed comparator leaf has an ASCII folding table, not CRT IO.
        cs = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
        cs.detail = True
        off = self.image.offset(COMPARE - self.image.pe.base)
        self.compare_instructions = []
        for ins in cs.disasm(self.raw[off:off + 71], COMPARE):
            refs = [ins.address + ins.size + op.mem.disp for op in ins.operands
                    if op.type == native.capstone.x86_const.X86_OP_MEM and op.mem.base == native.capstone.x86_const.X86_REG_RIP]
            for ref in refs:
                self.map_page(ref & ~4095)
            self.compare_instructions.append(dict(address=ins.address, bytes=bytes(ins.bytes).hex(),
                                                   mnemonic=ins.mnemonic, operands=ins.op_str, rip_references=refs))
        refs = [a for r in self.compare_instructions for a in r['rip_references']]
        if len(refs) != 1:
            raise ValueError('Expected one ASCII comparison table')
        off = self.image.offset(refs[0] - self.image.pe.base)
        self.fold_table = dict(address=refs[0], file_offset=off, bytes=self.raw[off:off + 128].hex())
        self.predicate_fragments = fragments
        self.compare_calls = 0

    def map_page(self, page):
        if any(lo <= page <= hi for lo, hi, _ in self.uc.mem_regions()):
            return
        off = self.image.offset(page - self.image.pe.base)
        self.uc.mem_map(page, 4096)
        self.uc.mem_write(page, self.raw[off:off + 4096])

    def hook(self, uc, address, size, user):
        if address == COMPARE:
            self.compare_calls += 1
        if address == 0x141420cc0:
            a, b = uc.reg_read(x.UC_X86_REG_RCX), uc.reg_read(x.UC_X86_REG_RDX)
            pointer, count, capacity = struct.unpack('<QII', uc.mem_read(b, 16))
            # Keep the allocated-empty FString representation (Num=1) intact;
            # reconstructing it from Python '' would silently turn it into Num=0.
            if count == 1:
                if not pointer or count > capacity or bytes(uc.mem_read(pointer, 2)) != b'\0\0':
                    raise ValueError('Invalid allocated-empty FString fixture')
                output = self.alloc(2)
                uc.mem_write(output, b'\0\0')
                uc.mem_write(a, struct.pack('<QII', output, 1, 1))
                self.finish(a)
                return
        return super().hook(uc, address, size, user)

    def evaluate(self, rows, current, target, allocated_empty=False):
        # Reuse actual record construction, CSV field storage instructions,
        # registry lookup, native World virtual getter and label caller.
        self.execute_table(rows)
        if allocated_empty:
            for i, row in enumerate(rows):
                if row['LevelPath'] == '':
                    pointer = self.alloc(2)
                    self.uc.mem_write(pointer, b'\0\0')
                    self.uc.mem_write(self.scratch + 0x6000 + i * 0x150 + 8 + 0x48,
                                      struct.pack('<QII', pointer, 1, 1))
        self.compare_calls = 0
        service = self.ctx + 0x8000
        self.uc.mem_write(service, bytes(0x100))
        self.uc.mem_write(service, struct.pack('<Q', 0x1499f11f0))
        self.uc.mem_write(service + 0x40, struct.pack('<II', current, target))
        self.run(PREDICATE, service)
        result = self.uc.reg_read(x.UC_X86_REG_AL)
        by_id = {int(r['Id']): r['LevelPath'] for r in rows}
        return dict(current=current, target=target, current_path=by_id.get(current, ''),
                    target_path=by_id.get(target, ''), allocated_empty=allocated_empty,
                    result=result, compare_calls=self.compare_calls)


def compose_pipeline(predicate, rows):
    spec = importlib.util.spec_from_file_location('load_predicate_pipeline', HERE / 'replay-world-move-start-pipeline.py')
    pipeline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pipeline)

    class Composed(pipeline.Emulator):
        def hook(self, uc, address, size, user):
            if self.handler_phase and address == PREDICATE:
                # Explicit two-emulator composition: copy actual current/target
                # fields after ID204 application into the independently
                # executed native lookup/predicate. Never substitute a bool.
                current, target = struct.unpack('<II', uc.mem_read(self.context + 0x5040, 8))
                result = predicate.evaluate(rows, current, target)
                self.events.append(dict(action='native_level_predicate_composed', **result))
                self.finish(result['result'])
                return
            return super().hook(uc, address, size, user)

    em = Composed()
    cases = [em.execute_pipeline(current_world=current, target_world=target, new_kind=3, status=2)
             for current, target in ((10, 10), (10, 11), (10, 12), (10, 99), (99, 98))]
    cases.append(em.execute_pipeline(current_world=10, target_world=12, code=1, status=2))
    for case in cases:
        actions = [e['action'] for e in case['events']]
        predicates = [e for e in case['events'] if e['action'] == 'native_level_predicate_composed']
        if case['input']['code']:
            if predicates:
                raise ValueError('Rejected ID204 reached load predicate')
            continue
        if len(predicates) != 1:
            raise ValueError('Expected one actual load predicate')
        different = predicates[0]['result']
        same_id = case['input']['current_world'] == case['input']['target_world']
        if (actions.count('load_state_capture'), actions.count('finish_packet_capture'),
                actions.count('load_callback_capture')) != (
                    different, int(not different and same_id), int(not different and not same_id)):
            raise ValueError('Actual LevelPath predicate did not choose expected service branch')
    return cases


def build():
    em = Emulator()
    paths = ('', 'x', 'X', 'Level/A', 'level/a', 'Level/B', 'Ж', 'ж')
    rows = [dict(Id=str(i + 10), LevelPath=path) for i, path in enumerate(paths)]
    synthetic = [em.evaluate(rows, a, b) for a in range(9, 18) for b in range(9, 18)]
    allocated = [em.evaluate(rows, a, b, True) for a, b in ((9, 10), (10, 9), (10, 10), (10, 11))]
    for case in synthetic + allocated:
        # ASCII-only folding is proved by the actual comparator table/loop;
        # non-ASCII code units compare directly, including case differences.
        fold = lambda text: ''.join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in text)
        expected = int(fold(case['current_path']) != fold(case['target_path']))
        if case['result'] != expected:
            raise ValueError('Native level-path predicate mismatch')
    # Revalidate the existing source-bound World table evidence, including
    # current archive SHA, rather than promote historical rows to live data.
    source_tables = world.build()
    real = []
    for table in source_tables['tables']:
        for current, target in ((1, 1), (1, 2), (2, 1), (2, 2), (2, 3)):
            real.append(dict(index_sha256=table['index_sha256'],
                             case=em.evaluate(table['rows'], current, target)))
    if any(r['case']['result'] != int(r['case']['current_path'] != r['case']['target_path']) for r in real):
        raise ValueError('Source World paths predicate mismatch')
    composed = compose_pipeline(em, [dict(Id='10', LevelPath='Level/A'),
                                     dict(Id='11', LevelPath='level/a'), dict(Id='12', LevelPath='Level/B')])
    return dict(source=em.bindings['source'], sha256=em.bindings['sha256'],
                manifest_sha256=em.manifest_sha256, ranges=em.predicate_ranges,
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                dependency_sha256=hashlib.sha256((HERE / 'replay-world-state-label.py').read_bytes()).hexdigest(),
                pipeline_dependency_sha256=hashlib.sha256((HERE / 'replay-world-move-start-pipeline.py').read_bytes()).hexdigest(),
                service_table=em.service_table, comparison=em.compare_instructions, fold_table=em.fold_table,
                synthetic_rows=rows, synthetic=synthetic, allocated_empty=allocated,
                source_tables=source_tables, real=real, composed=composed,
                network_ready=False, live_registry_verified=False,
                limitations=['Actual predicate, World lookup/hash/accessor/LevelPath getter and ASCII folding comparator execute.',
                             'Registry allocation/getter, template copy and FString operations are bounded fixtures inherited from World evidence.',
                             'ID204 and LevelPath predicates are composed across two emulators by copying actual service fields; no shared live registry.',
                             'Source World rows are revalidated offline; mount priority/live values/session/loader are not proved.'])


if __name__ == '__main__':
    report = build()
    output = native.ROOT / 'code-clues/world-load-predicate-replay.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    print(json.dumps(dict(output=str(output), synthetic=len(report['synthetic']), real=len(report['real']),
                          sha256=hashlib.sha256(output.read_bytes()).hexdigest())))
