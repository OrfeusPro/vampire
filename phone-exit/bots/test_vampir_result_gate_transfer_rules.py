"""Synthetic typed result-gate code/data and export contract regressions."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load

RULES = load('result-gate-transfer-rules')
NATIVE = load('build-native-entry-code')
HERE = Path(__file__).parent / 'resource-tools/vampir/knowledge/native-contexts'
BASE = 0x140000000


def context(): return json.loads((HERE / 'result-gate-11320.json').read_text('utf-8'))


class ScopeTests(unittest.TestCase):
    def test_one_root_and_original_context_untouched(self):
        c = context(); original = copy.deepcopy(c)
        self.assertEqual(RULES.roots(c), {int(c['function'], 16)}); self.assertEqual(c, original)

    def test_extra_native_scope_and_unchecked_export_rejected(self):
        c = context(); c['native_handler'] = {}
        with self.assertRaisesRegex(ValueError, 'fields'): RULES.roots(c)
        c = context(); c['verify_whole_exports'] = False
        with self.assertRaisesRegex(ValueError, 'scope'): RULES.roots(c)

    def test_optional_generated_metadata_is_accepted(self):
        c = context(); c.update(family='result-gate', layout={}, transfer_proof={'path': 'unused'}, release_id='11322')
        self.assertEqual(len(RULES.roots(c)), 1)

    def test_exact_partition_and_fixed_input_range(self):
        for key in RULES.OFFSETS:
            c = context(); c['switch'][key] = hex(int(c['switch'][key], 16) + 1)
            with self.assertRaisesRegex(ValueError, 'partition'): RULES.roots(c)
        for key, value in (('input_first', 1306), ('input_count', 228), ('input_first', True)):
            c = context(); c['switch'][key] = value
            with self.assertRaisesRegex(ValueError, 'layout'): RULES.roots(c)

    def test_inline_tables_and_dispatch_have_bounded_width(self):
        for key in ('table_bytes', 'index_bytes', 'dispatch_bytes'):
            c = context(); c['switch'][key] += '00'
            with self.assertRaisesRegex(ValueError, 'byte scope'): RULES.roots(c)
        c = context(); c['switch']['index_bytes'] = '04' + c['switch']['index_bytes'][2:]
        with self.assertRaisesRegex(ValueError, 'byte scope'): RULES.roots(c)

    def test_fixture_scope_and_aliases_rejected(self):
        c = context(); c['fixtures']['log'] = c['helpers']['memcpy']
        with self.assertRaisesRegex(ValueError, 'fixture roles'): RULES.roots(c)
        c = context(); c['fixtures']['gate_state'] = c['function']
        with self.assertRaisesRegex(ValueError, 'alias'): RULES.roots(c)
        c = context(); c['fixtures']['gate_state'] = c['fixtures']['gate_error']
        with self.assertRaisesRegex(ValueError, 'alias'): RULES.roots(c)

    def test_calls_must_be_direct_explicit_addresses(self):
        c = context(); c['call_sites'][next(iter(c['call_sites']))] = 'qword ptr [rip + 0x20]'
        with self.assertRaisesRegex(ValueError, 'direct call'): RULES.roots(c)

    def test_historical_evidence_is_immutable_scope_pointer(self):
        p = context()['provenance']
        self.assertEqual(p['tool_name'], 'version-gate-switch-11320.py')
        self.assertEqual(p['reviewed_report']['sha256'], '03ea1910d28b20615dfd14c90b5575655f599cae93584b3cfba4839c705b9003')
        self.assertNotIn('tool_path', p)


class SyntheticImage:
    def __init__(self, entry):
        self.entry = entry; self.pe = SimpleNamespace(base=BASE, sections=[]); self.memory = {}
        span = (entry - BASE, entry - BASE + 1291, 0); self.roots = {span: span}; self.span = span
    def containing(self, at): return self.span if self.entry <= at < self.entry + 1291 else None
    def read(self, at, size):
        for start, raw in self.memory.items():
            if start <= at and at + size <= start + len(raw): return bytes(raw[at - start:at - start + size])
        raise ValueError('Synthetic file range missing')


NOP = {1: b'\x90', 2: bytes.fromhex('6690'), 3: bytes.fromhex('0f1f00'), 4: bytes.fromhex('0f1f4000'),
       5: bytes.fromhex('0f1f440000'), 6: bytes.fromhex('660f1f440000'), 7: bytes.fromhex('0f1f8000000000'),
       8: bytes.fromhex('0f1f840000000000'), 9: bytes.fromhex('660f1f840000000000')}


def synthetic(entry=BASE + 0x10000):
    c = context(); c['function'] = hex(entry); c['helpers'] = {'memcpy': hex(entry + 0x100000)}
    c['fixtures'] = {'gate_state': hex(entry + 0x200000), 'gate_error': hex(entry + 0x300000)}
    for key, offset in RULES.OFFSETS.items(): c['switch'][key] = hex(entry + offset)
    image = SyntheticImage(entry); c['switch']['dispatch_bytes'] = RULES.dispatch_bytes(image, c).hex()
    targets = [entry, entry + 36, entry + 142, entry]
    c['switch']['table_bytes'] = struct.pack('<4I', *(at - BASE for at in targets)).hex()
    c['switch']['index_bytes'] = bytes(index % 4 for index in range(227)).hex()
    parts = {497: bytes.fromhex(c['switch']['dispatch_bytes']), 997: b'\x90', 1046: b'\xc3'}
    for offset in sorted(RULES.CALL_OFFSETS):
        target = int(c['fixtures']['gate_state'], 16) if offset == 36 else int(c['fixtures']['gate_error'], 16) if offset in (961, 1001) else entry + 0x400000 + offset * 16
        parts[offset] = b'\xe8' + struct.pack('<i', target - entry - offset - 5)
    for offset in sorted(RULES.RIP_OFFSETS - {514}):
        target = entry + 0x500000 + offset * 16
        parts[offset] = bytes.fromhex('488d15') + struct.pack('<i', target - entry - offset - 7)
    # Fill uninteresting gaps with whole NOP instructions. The oracle preserves
    # exact251instructions without embedding code from the proprietary EXE.
    decoder = NATIVE.capstone.Cs(NATIVE.capstone.CS_ARCH_X86, NATIVE.capstone.CS_MODE_64)
    fixed_count = sum(len(list(decoder.disasm(raw, entry + offset))) for offset, raw in parts.items())
    gaps, end = [], 0
    for offset, raw in sorted(parts.items()):
        if offset < end: raise AssertionError('Synthetic fixed parts overlap')
        if offset > end: gaps.append((end, offset - end))
        end = offset + len(raw)
    counts = [((size + 8) // 9) for _, size in gaps]; additional = 251 - fixed_count - sum(counts)
    for index, (_, size) in enumerate(gaps):
        take = min(additional, size - counts[index]); counts[index] += take; additional -= take
    if additional: raise AssertionError('Synthetic instruction count not attainable')
    raw = bytearray(1047)
    for offset, data in parts.items(): raw[offset:offset + len(data)] = data
    for (offset, size), count in zip(gaps, counts):
        cursor, remaining = offset, size
        for position in range(count):
            width = min(9, remaining - (count - position - 1)); raw[cursor:cursor + width] = NOP[width]
            cursor += width; remaining -= width
        if remaining: raise AssertionError('Synthetic NOP gap')
    image.memory[entry] = raw
    image.memory[entry + 1047] = bytearray(b'\x90' + bytes.fromhex(c['switch']['table_bytes']) + bytes.fromhex(c['switch']['index_bytes']))
    decoded = list(decoder.disasm(raw, entry))
    c['call_sites'] = {hex(row.address): row.op_str for row in decoded if row.mnemonic == 'call'}
    return c, image


class GateRowsTests(unittest.TestCase):
    def setUp(self):
        utility = load('version-system-transfer-rules'); original = RULES.load
        patch.object(RULES, 'load', side_effect=lambda name: utility if name == 'version-system-transfer-rules' else original(name)).start()
        patch.object(utility, 'image_bytes', side_effect=lambda image, at, size: image.read(at, size)).start()
        self.addCleanup(patch.stopall)

    def test_exact_typed_code_and_inline_data_layout(self):
        c, image = synthetic(); code = RULES.rows(NATIVE, image, c)
        self.assertEqual(len(code), 251); self.assertEqual(code[-1]['mnemonic'], 'ret')
        self.assertTrue(all(row['address'] < int(c['switch']['code_end'], 16) for row in code))

    def test_image_base_is_part_of_reviewed_abi(self):
        c, image = synthetic(); image.pe.base += 0x1000
        with self.assertRaisesRegex(ValueError, 'image-base ABI'): RULES.dispatch_bytes(image, c)

    def test_indexed_displacements_relocate_without_masking_other_instructions(self):
        a, before = synthetic(); z, after = synthetic(BASE + 0x11000)
        old, new = RULES.rows(NATIVE, before, a), RULES.rows(NATIVE, after, z)
        mapping = {}; RULES.pair_rows(NATIVE, old, new, mapping)
        self.assertEqual(mapping[int(a['function'], 16)], int(z['function'], 16))
        changed = copy.deepcopy(new); changed[0]['bytes'] = '6690'
        with self.assertRaises(ValueError): RULES.pair_rows(NATIVE, old, changed, {})

    def test_no_unknown_indirect_call_or_external_branch(self):
        for changed, message in ((bytes.fromhex('ff1500000000'), 'indirect call'), (bytes.fromhex('e900000001'), 'branch leaves')):
            c, image = synthetic(); entry = int(c['function'], 16)
            # Keep instruction count/layout guard isolated to prove the control
            # check rejects the unsafe edge even with exactly251decoded rows.
            original_cs = NATIVE.capstone.Cs
            real = original_cs(NATIVE.capstone.CS_ARCH_X86, NATIVE.capstone.CS_MODE_64); real.detail = True
            instructions = list(real.disasm(image.read(entry, 1047), entry))
            instructions[0] = next(real.disasm(changed, entry))
            missing = 1047 - sum(row.size for row in instructions)
            if missing:
                # Fake the byte count through a wrapper, retaining all semantic
                # fields of a real decoded instruction for this isolated guard.
                original_last = instructions[-2]
                class Sized:
                    def __getattr__(self, key): return getattr(original_last, key)
                    size = original_last.size + missing
                instructions[-2] = Sized()
            fake = SimpleNamespace(detail=True, disasm=lambda raw, at: iter(instructions))
            with patch.object(NATIVE.capstone, 'Cs', return_value=fake):
                with self.assertRaisesRegex(ValueError, message): RULES.rows(NATIVE, image, c)

    def test_code_count_and_complete_decode_cannot_widen(self):
        c, image = synthetic(); image.memory[int(c['function'], 16)][0] = 0xcc
        # The first NOP staysoneinstruction; changing it invalidates the exact
        # transfer signature rather than inventing extra behavior admission.
        a, old = synthetic(); oldrows = RULES.rows(NATIVE, old, a); newrows = RULES.rows(NATIVE, image, c)
        with self.assertRaisesRegex(ValueError, 'shape changed'): RULES.pair_rows(NATIVE, oldrows, newrows, {})

    def test_code_data_alignment_and_index_bounds_are_checked(self):
        c, image = synthetic(); image.memory[int(c['switch']['code_end'], 16)][0] = 0
        with self.assertRaisesRegex(ValueError, 'alignment'): RULES.rows(NATIVE, image, c)
        c, image = synthetic(); c['switch']['index_bytes'] = '04' + c['switch']['index_bytes'][2:]
        with self.assertRaisesRegex(ValueError, 'byte scope'): RULES.rows(NATIVE, image, c)
        c, image = synthetic(); image.span = (image.span[0], image.span[1] + 1, 0); image.roots = {image.span: image.span}
        with self.assertRaisesRegex(ValueError, 'unwind range'): RULES.rows(NATIVE, image, c)

    def test_table_targets_must_be_instruction_boundaries_with_exact_alias_partition(self):
        for targets in ((0, 36, 142, 36), (0, 36, 37, 0)):
            c, image = synthetic(); entry = int(c['function'], 16)
            data = struct.pack('<4I', *(entry + offset - BASE for offset in targets))
            c['switch']['table_bytes'] = data.hex(); image.memory[entry + 1047][1:17] = data
            with self.assertRaisesRegex(ValueError, 'target boundary/alias'): RULES.rows(NATIVE, image, c)

    def test_indexed_opcode_and_range_guard_are_exact_not_generic_displacement_masks(self):
        c, image = synthetic(); entry = int(c['function'], 16); data = image.memory[entry]
        data[497 + 7] = 0xe3
        c['switch']['dispatch_bytes'] = bytes(data[497:543]).hex()
        with self.assertRaisesRegex(ValueError, 'dispatch'): RULES.rows(NATIVE, image, c)

    def test_callsite_and_fixture_callee_declarations_are_enforced(self):
        c, image = synthetic(); c['call_sites'][next(iter(c['call_sites']))] = '0x1234'
        with self.assertRaisesRegex(ValueError, 'call-site declaration'): RULES.rows(NATIVE, image, c)
        c, image = synthetic(); c['fixtures']['gate_error'] = '0x1234'
        with self.assertRaisesRegex(ValueError, 'fixture callee'): RULES.rows(NATIVE, image, c)

    def test_zero_or_multiple_complete_candidates_cannot_be_selected(self):
        c, before = synthetic(); _, after = synthetic(BASE + 0x11000)
        p = (0x12000, 0x12000 + 1291, 0); after.roots[p] = p
        # Candidate discovery does not itself grant a binding. Require one
        # complete typed match, retaining ambiguity even when shapes agree.
        candidate = RULES.functional(c); fake = [dict(address=int(c['function'], 16), bytes='c3')]
        with patch.object(RULES, 'rows', return_value=fake), patch.object(RULES, 'target_context', return_value=candidate), \
             patch.object(RULES, 'pair_rows', return_value=None):
            with self.assertRaisesRegex(ValueError, 'ambiguous'): RULES.resolve(NATIVE, None, before, after, c, {})
        with patch.object(RULES, 'rows', return_value=fake), patch.object(RULES, 'target_context', side_effect=ValueError('changed')):
            with self.assertRaisesRegex(ValueError, 'Missing'): RULES.resolve(NATIVE, None, before, after, c, {})


class TransferReceiptTests(unittest.TestCase):
    def test_relocation_receipt_survives_json_roundtrip_without_type_drift(self):
        baseline, before = synthetic(); current, after = synthetic()
        mapping = {int(baseline['helpers']['memcpy'], 16): int(current['helpers']['memcpy'], 16)}
        original = RULES.load
        utility = SimpleNamespace(address=original('version-system-transfer-rules').address,
            import_thunk=lambda *args: dict(identity='memcpy'))
        with patch.object(RULES, 'resolve', return_value=(current, [], [])), \
                patch.object(RULES, 'typed_inputs', return_value=([], [])), \
                patch.object(RULES, 'rows', return_value=[]), \
                patch.object(RULES, 'load', side_effect=lambda name: utility if name == 'version-system-transfer-rules' else original(name)):
            _, receipt = RULES.transfer(NATIVE, None, before, after, baseline, mapping)
        self.assertEqual(receipt, json.loads(json.dumps(receipt)))
        self.assertEqual(receipt['indexed_displacements'], {'523': ['index', 4, 4], '531': ['table', 3, 4]})


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.root = Path(self.directory.name); self.addCleanup(self.directory.cleanup)
        self.context, self.image = synthetic(); self.context['source_sha256'] = 'a' * 64
        self.context['exports'] = {}; self.fake_rows = [dict(address=0x1000, bytes='c3')]
        patch.object(RULES, 'rows', return_value=self.fake_rows).start(); self.addCleanup(patch.stopall)

    def report(self, run='run-synthetic', **overrides):
        function = dict(address=self.context['function'], decompilation_completed=True, block_coverage_complete=True,
                        direct_flow_coverage_complete=True, instructions=[dict(address='0x1000', bytes='c3')])
        function.update(overrides)
        report = dict(new_source_sha256=self.context['source_sha256'], functions=[function])
        p = self.root / 'ghidra/request-exports' / self.context['source_sha256'] / run / 'details.json'
        p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(report), encoding='utf-8')
        self.context['exports'][run] = hashlib.sha256(p.read_bytes()).hexdigest(); return p

    def test_exact_complete_code_export_is_required(self):
        self.report(); RULES.export_coverage(self.root, self.context, NATIVE, None, self.image)
        self.context['exports'] = {}
        with self.assertRaisesRegex(ValueError, 'missing'): RULES.export_coverage(self.root, self.context, NATIVE, None, self.image)

    def test_extra_inline_data_and_duplicate_rows_not_accepted_as_code(self):
        for rows in ([dict(address='0x1000', bytes='c3'), dict(address='0x1001', bytes='90')], [dict(address='0x1000', bytes='c3')] * 2):
            self.report(instructions=rows)
            with self.assertRaises(ValueError): RULES.export_coverage(self.root, self.context, NATIVE, None, self.image)

    def test_incomplete_flow_or_wrong_hash_fail_closed(self):
        self.report(direct_flow_coverage_complete=False)
        with self.assertRaisesRegex(ValueError, 'coverage incomplete'): RULES.export_coverage(self.root, self.context, NATIVE, None, self.image)
        p = self.report(); p.write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'export changed'): RULES.export_coverage(self.root, self.context, NATIVE, None, self.image)

    def test_wrong_source_and_export_path_escape_rejected(self):
        p = self.report(); report = json.loads(p.read_text()); report['new_source_sha256'] = 'b' * 64
        p.write_text(json.dumps(report), encoding='utf-8'); self.context['exports']['run-synthetic'] = hashlib.sha256(p.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'source differs'): RULES.export_coverage(self.root, self.context, NATIVE, None, self.image)
        self.context['exports'] = {'../run-other': 'a' * 64}
        with self.assertRaisesRegex(ValueError, 'export name'): RULES.export_coverage(self.root, self.context, NATIVE, None, self.image)


if __name__ == '__main__': unittest.main()
