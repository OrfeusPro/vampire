"""Quest1810 matrix and independent OUTPUT/raw-failure engine regressions.

The small executable fixtures exercise guard code; they do not establish any
client address or replace the separately source-bound current-client scenarios.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_vampir_update_contracts import load

CASES = load('quest-wire-cases-v1')
HARNESS = load('quest-wire-harness-v1')
NATIVE = load('build-native-entry-code')


class WireMatrixTests(unittest.TestCase):
    def test_matrix_preserves_every_prefix_and_each_writer_failure(self):
        cases = CASES.expected_cases()
        self.assertEqual({key: len(rows) for key, rows in cases.items()},
                         dict(valid=81, prefixes=29, trailing=1, failures=6))
        self.assertEqual(sum(map(len, cases.values())), 117)
        self.assertEqual(cases['prefixes'], [dict(size=i, accepted=False, consumed=i) for i in range(29)])
        self.assertEqual(cases['trailing'], [dict(size=31, accepted=True, consumed=29)])
        self.assertEqual([row['widths'] for row in cases['failures']],
                         [[4, 4, 4, 8, 8, 1][:i + 1] for i in range(6)])

    def test_float32_wire_projects_to_float64_mirror_without_losing_scalar_bytes(self):
        cases = CASES.expected_cases()['valid']
        for index, row in enumerate(cases):
            body, mirror = bytes.fromhex(row['body_hex']), bytes.fromhex(row['mirror_hex'])
            self.assertEqual(row['index'], index)
            self.assertEqual((len(body), len(mirror)), (29, 41))
            self.assertEqual(struct.unpack('<fffQQB', body), struct.unpack('<dddQQB', mirror))
            self.assertEqual(body[12:], mirror[24:])
        # Signed zero is byte-sensitive although Python equality merges +/-0.
        negative_zero = next(row for row in cases if row['body_hex'].startswith('00000080'))
        self.assertTrue(negative_zero['mirror_hex'].startswith('0000000000000080'))
        self.assertEqual(struct.unpack('<QQB', bytes.fromhex(cases[-1]['body_hex'])[12:]), (0, 110120, 0))

    def test_matrix_covers_both_high_bit_keys_and_noncanonical_boolean_bytes(self):
        rows = [struct.unpack('<fffQQB', bytes.fromhex(row['body_hex'])) for row in CASES.expected_cases()['valid']]
        self.assertEqual({row[3] for row in rows}, {0, 1, 110120, 1 << 63, (1 << 64) - 1})
        self.assertEqual({row[-1] for row in rows}, {0, 1, 2, 255})
        self.assertEqual(len({tuple(row[:3]) for row in rows}), 4)

    def test_native_call_accounting_matches_combined_case_scope(self):
        cases = CASES.expected_cases()
        # Two ctor/ID pairs, OUTPUT ctor/writer, INPUT ctor/reader per valid case.
        self.assertEqual(8 * len(cases['valid']) + 4 * (len(cases['prefixes']) + len(cases['trailing'])), 768)
        self.assertEqual(4 * len(cases['failures']), 24)


class WireConstructorSelectionTests(unittest.TestCase):
    def context(self, *, duplicate=False, omit=False):
        packet_table, input_table = 0x140003000, 0x140004000
        packet_ctor, input_base = 0x140001200, 0x140001100
        def leaf(address, target, size):
            return (b'\x48\x8d\x05' + struct.pack('<i', target - address - 7)
                    + b'\x90' * (size - 7)).hex()
        leaves = {hex(input_base): leaf(input_base, input_table, 34)}
        if not omit:
            leaves[hex(packet_ctor)] = leaf(packet_ctor, packet_table, 31)
        if duplicate:
            leaves[hex(packet_ctor + 0x80)] = leaf(packet_ctor + 0x80, packet_table, 34)
        functions = {('output_raw' if i == 0 else 'root_' + str(i)): hex(0x140005000 + i * 0x100)
                     for i in range(14)}
        context = dict(functions=functions, leaves=leaves, packet_table=hex(packet_table),
            input_table=hex(input_table), output_table=hex(0x140006000), fixtures={},
            bindings=[[hex(packet_table), '0x28', hex(0x140001400)]], exports={'run-fixture': 'a' * 64})
        return context, packet_ctor

    def test_short_packet_constructor_is_selected_by_its_table_not_leaf_length(self):
        context, packet_ctor = self.context()
        class SelectionObserved(Exception):
            pass
        machine = SimpleNamespace(scratch=HARNESS.SCRATCH, available_fixtures=set(),
            uc=SimpleNamespace(mem_write=Mock()), reset_regions=Mock(), allow_write=Mock(),
            call=Mock(side_effect=SelectionObserved))
        harness = SimpleNamespace(make_harness=Mock(return_value=machine))
        with self.assertRaises(SelectionObserved):
            CASES.verify(harness, context, Path('.'), object())
        self.assertEqual(machine.call.call_args.args[0], packet_ctor)
        call = harness.make_harness.call_args
        self.assertEqual(call.args[0]['execution_scope'], 'whole_io')
        self.assertEqual(call.args[2], {int(at, 16) for at in context['functions'].values()})
        self.assertEqual(len(call.args[2]), 14)
        self.assertEqual(call.args[3], {int(at, 16): body for at, body in context['leaves'].items()})

    def test_absent_or_ambiguous_packet_table_reference_prevents_harness_creation(self):
        for flags in (dict(omit=True), dict(duplicate=True)):
            with self.subTest(flags=flags):
                context, _ = self.context(**flags)
                harness = SimpleNamespace(make_harness=Mock())
                with self.assertRaisesRegex(ValueError, 'constructor leaf is missing or ambiguous'):
                    CASES.verify(harness, context, Path('.'), object())
                harness.make_harness.assert_not_called()


class WireAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.functions = {('output_raw' if i == 0 else 'root_' + str(i)): hex(0x140001000 + i * 0x100) for i in range(14)}
        self.sha = 'a' * 64
        self.base = dict(source_sha256=self.sha,
                         source=str(self.root / 'client-code-snapshots' / self.sha / 'ProjectRED-Win64-Shipping.exe'),
                         functions=copy.deepcopy(self.functions), leaves={})
        self.exports = {'run-fixture': 'b' * 64}
        self.pointer = dict(path='not-opened', sha256='c' * 64)
        self.context = dict(self.base, schema=1, family='quest-update-wire', exports=self.exports,
                            transfer_proof=self.pointer, verify_whole_exports=True, execution_scope='whole_io')
        self.proof = dict(schema=1, recipe='quest-action-transfer-v1', method='static',
            inputs={}, package=dict(target_contexts={'quest-update-wire': copy.deepcopy(self.base)}),
            native_consumer_verified=False, runtime_activated=False, profile_activated=False, limits=['fixture limits'])
        self.rules = SimpleNamespace(validate_package=Mock())
        self.bindings = SimpleNamespace()
        self.wrapper = SimpleNamespace(LIMITS=['fixture limits'])
        self.store = SimpleNamespace(root=self.root, index=object())

    def admit(self, roots=None):
        modules = {'update-bindings': self.bindings, 'quest-action-transfer-v1': self.wrapper,
                   'quest-action-transfer-rules-v1': self.rules}
        with patch.object(HARNESS, 'pointer_document', return_value=self.proof), \
                patch.object(HARNESS, 'load', side_effect=lambda name: modules[name]):
            return HARNESS.admit(self.context, self.root,
                                {int(at, 16) for at in self.functions.values()} if roots is None else roots,
                                {}, self.exports, source_store=self.store)

    def test_unknown_scope_cannot_select_a_less_restrictive_execution(self):
        self.context['execution_scope'] = 'unchecked'
        with self.assertRaisesRegex(ValueError, 'execution scope'):
            self.admit()

    def test_raw_failure_requires_output_raw_to_be_excluded_from_executed_roots(self):
        self.context['execution_scope'] = 'raw_failure'
        with self.assertRaisesRegex(ValueError, 'executed root/leaf scope'):
            self.admit()

    def test_whole_scope_requires_all_fourteen_distinct_roots(self):
        roots = {int(at, 16) for at in self.functions.values()}
        roots.remove(int(self.functions['output_raw'], 16))
        with self.assertRaisesRegex(ValueError, 'executed root/leaf scope'):
            self.admit(roots)

    def test_added_context_field_is_not_silently_ignored(self):
        self.context['unchecked_growth'] = True
        with self.assertRaisesRegex(ValueError, 'exact proof projection'):
            self.admit()

    def test_boolean_schema_and_unverified_exports_are_rejected(self):
        for field, value in (('schema', True), ('verify_whole_exports', False)):
            with self.subTest(field=field):
                prior = self.context[field]
                self.context[field] = value
                with self.assertRaisesRegex(ValueError, 'context/family/export'):
                    self.admit()
                self.context[field] = prior

    def test_proof_for_another_recipe_is_rejected_before_any_execution(self):
        self.proof['recipe'] = 'quest-reader-transfer-v1'
        with self.assertRaisesRegex(ValueError, 'static receipt scope'):
            self.admit()

    def test_mutable_or_foreign_proof_pointer_is_rejected(self):
        category = self.root / 'knowledge/quest-action-transfer-proofs-v1'
        payload = b'{"fixture":true}'
        sha = hashlib.sha256(payload).hexdigest()
        path = category / sha / 'manifest.json'
        path.parent.mkdir(parents=True)
        path.write_bytes(payload)
        pointer = dict(path=str(path), sha256=sha)
        self.assertEqual(HARNESS.pointer_document(pointer, category), dict(fixture=True))
        path.write_bytes(b'{"fixture":false}')
        with self.assertRaisesRegex(ValueError, 'proof changed'):
            HARNESS.pointer_document(pointer, category)
        with self.assertRaisesRegex(ValueError, 'category'):
            HARNESS.pointer_document(pointer, category / 'other')


class WireEngineTests(unittest.TestCase):
    """Execute tiny native functions with an intentionally mocked proof admission."""
    def make(self, code, *, raw_writer=False, scope='whole_io'):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        base = 0x140000000
        entry, copy_root, copy_thunk, raw_root, table = [base + i for i in (0x1000, 0x1100, 0x2000, 0x2100, 0x3000)]
        helper = b'\x48\x83\xec\x28\xe8' + struct.pack('<i', copy_thunk - (copy_root + 9)) + b'\x48\x83\xc4\x28\xc3'
        if callable(code):
            code = code(entry, copy_thunk)
        if raw_writer:
            code = bytes.fromhex('4883ec28488b02ff90880000004883c428c3')
        bodies = {entry: code, copy_root: helper}
        if raw_writer:
            bodies[raw_root] = bytes.fromhex('b801000000c3')
        raw = bytearray(0x5000)
        for at, body in bodies.items():
            raw[at - base:at - base + len(body)] = body
        if raw_writer:
            struct.pack_into('<Q', raw, table - base + 0x88, raw_root)
        raw = bytes(raw)
        sha = hashlib.sha256(raw).hexdigest()
        decoder = NATIVE.capstone.Cs(NATIVE.capstone.CS_ARCH_X86, NATIVE.capstone.CS_MODE_64)
        decoder.detail = True
        def rows(at, body):
            result = []
            for ins in decoder.disasm(body, at):
                call = ins.group(NATIVE.capstone.CS_GRP_CALL)
                branch = ins.group(NATIVE.capstone.CS_GRP_JUMP)
                target = ins.operands[0].imm if (call or branch) and ins.operands[0].type == NATIVE.X86_OP_IMM else None
                result.append(dict(address=ins.address, bytes=ins.bytes.hex(), mnemonic=ins.mnemonic,
                    operands=ins.op_str, call=call, branch=branch, direct_target=target, rip_references=[]))
            return result
        instructions = {at: rows(at, body) for at, body in bodies.items()}
        report = dict(new_source_sha256=sha, functions=[dict(address=hex(at), decompilation_completed=True,
            instructions=[dict(address=hex(row['address']), bytes=row['bytes']) for row in items])
            for at, items in instructions.items()])
        payload = json.dumps(report).encode()
        export = root / 'ghidra/request-exports' / sha / 'run-fixture' / 'details.json'
        export.parent.mkdir(parents=True)
        export.write_bytes(payload)
        functions = dict(entry=hex(entry), copy=hex(copy_root))
        if raw_writer:
            functions['output_raw'] = hex(raw_root)
        context = dict(source_sha256=sha, source=str(root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
            family='quest-update-wire', functions=functions, leaves={}, bindings=[], fixtures={}, execution_scope=scope)
        image = SimpleNamespace(offset=lambda rva: rva, pe=SimpleNamespace(base=base))
        store = SimpleNamespace(source=lambda identity: raw, image=lambda native, identity: image)
        tables = [dict(target=hex(table), bytes=raw[table - base:table - base + 0x90].hex())] if raw_writer else []
        admission = SimpleNamespace(source_sha256=sha, store=store, proof=dict(package=dict(relation=dict(tables=tables,
            boundaries=[dict(consumer='shared-input', role='memcpy', target=hex(copy_thunk))]))))
        original = HARNESS.load
        def extension(name):
            if name == 'update-bindings':
                return SimpleNamespace(rows=lambda native, image, at: instructions[at])
            return original(name)
        roots = set(instructions)
        if raw_writer and scope == 'raw_failure':
            roots.remove(raw_root)
        with patch.object(HARNESS, 'admit', return_value=admission), patch.object(HARNESS, 'load', side_effect=extension):
            h = HARNESS.make_harness(context, {'run-fixture': hashlib.sha256(payload).hexdigest()}, roots, root=root)
        return SimpleNamespace(h=h, entry=entry, raw=raw_root, table=table, copy=copy_root, thunk=copy_thunk)

    def test_output_scalar_can_copy_from_native_stack_into_declared_buffer(self):
        def body(entry, thunk):
            prefix = bytes.fromhex('4883ec28c744242044434241488d54242041b804000000e8')
            return prefix + struct.pack('<i', thunk - (entry + len(prefix) + 4)) + bytes.fromhex('4883c428c3')
        f = self.make(body)
        dest = f.h.scratch + 0x1000
        f.h.allow_write(dest, 4)
        self.assertEqual(f.h.call(f.entry, dest), dest)
        self.assertEqual(bytes(f.h.uc.mem_read(dest, 4)), b'DCBA')
        self.assertEqual(f.h.fixture_calls, 1)
        self.assertEqual(f.h.abi_checks, 1)

    def test_input_scalar_can_copy_into_native_stack_and_return_value(self):
        def body(entry, thunk):
            prefix = bytes.fromhex('4883ec284889ca488d4c242041b804000000e8')
            return prefix + struct.pack('<i', thunk - (entry + len(prefix) + 4)) + bytes.fromhex('8b4424204883c428c3')
        f = self.make(body)
        source = f.h.scratch + 0x1000
        f.h.allow_read(source, 4)
        f.h.uc.mem_write(source, b'WXYZ')
        self.assertEqual(f.h.call(f.entry, source), int.from_bytes(b'WXYZ', 'little'))

    def test_declared_empty_input_permits_zero_byte_copy_to_native_stack(self):
        def body(entry, thunk):
            prefix = bytes.fromhex('4883ec284889ca488d4c24204531c0e8')
            return prefix + struct.pack('<i', thunk - (entry + len(prefix) + 4)) + bytes.fromhex('4883c428c3')
        f = self.make(body)
        source = f.h.scratch + 0x1000
        f.h.allow_read(source, 0)
        self.assertEqual(f.h.call(f.entry, source), HARNESS.STACK_ENTRY - 8)
        self.assertEqual(f.h.fixture_calls, 1)
        self.assertEqual(f.h.abi_checks, 1)

    def test_zero_extent_grants_no_undeclared_pointer_or_positive_read(self):
        f = self.make(bytes.fromhex('8a01c3'))
        source, dest = f.h.scratch + 0x1000, f.h.scratch + 0x2000
        f.h.allow_write(dest, 4)
        with self.assertRaisesRegex(ValueError, 'memcpy input/output bound'):
            f.h.call(f.copy, dest, rdx=source, r8=0)
        f.h.allow_read(source, 0)
        with self.assertRaisesRegex(ValueError, 'memcpy input/output bound'):
            f.h.call(f.copy, dest, rdx=source + 1, r8=0)
        with self.assertRaisesRegex(ValueError, 'memcpy input/output bound'):
            f.h.call(f.copy, dest, rdx=source, r8=1)
        with self.assertRaisesRegex(ValueError, 'read outside declared input'):
            f.h.call(f.entry, source)

    def test_stack_copy_does_not_relax_destination_permissions_or_size_limit(self):
        f = self.make(b'\xc3')
        source, dest = f.h.scratch + 0x1000, f.h.scratch + 0x2000
        f.h.allow_read(source, 16)
        f.h.allow_write(dest, 16)
        with self.assertRaisesRegex(ValueError, 'memcpy input/output bound'):
            f.h.call(f.copy, dest, rdx=source, r8=9)
        f.h.reset_regions()
        f.h.allow_read(source, 4)
        with self.assertRaisesRegex(ValueError, 'memcpy input/output bound'):
            f.h.call(f.copy, dest, rdx=source, r8=4)

    def test_memcpy_overlap_is_rejected(self):
        f = self.make(b'\xc3')
        data = f.h.scratch + 0x1000
        f.h.allow_write(data, 8)
        with self.assertRaisesRegex(ValueError, 'ranges overlap'):
            f.h.call(f.copy, data + 1, rdx=data, r8=4)

    def test_changed_float_control_mode_is_rejected(self):
        f = self.make(bytes.fromhex('4883ec28c7442420803f00000fae5424204883c428c3'))
        with self.assertRaisesRegex(ValueError, 'floating-point control mode'):
            f.h.call(f.entry)

    def test_float_exception_status_bits_may_change_without_changing_control(self):
        f = self.make(bytes.fromhex('4883ec28c7442420811f00000fae5424204883c428c3'))
        f.h.call(f.entry)
        self.assertEqual(f.h.abi_checks, 1)

    def test_raw_failure_scope_executes_caller_and_excludes_native_raw_body(self):
        f = self.make(b'', raw_writer=True, scope='raw_failure')
        archive = f.h.scratch + 0x1000
        f.h.uc.mem_write(archive, struct.pack('<Q', f.table))
        f.h.allow_read(archive, 8)
        self.assertIn(f.raw, f.h.available_fixtures)
        f.h.add_fixture(f.raw, lambda machine: f.h.finish(0))
        self.assertEqual(f.h.call(f.entry, rdx=archive), 0)
        self.assertEqual(f.h.entry_counts[f.raw], 1)
        self.assertEqual(f.h.fixture_calls, 1)
        with self.assertRaisesRegex(ValueError, 'outside exact root/leaf scope'):
            f.h.call(f.raw)

    def test_whole_scope_does_not_allow_raw_function_to_be_shadowed(self):
        f = self.make(b'', raw_writer=True)
        archive = f.h.scratch + 0x1000
        f.h.uc.mem_write(archive, struct.pack('<Q', f.table))
        f.h.allow_read(archive, 8)
        self.assertNotIn(f.raw, f.h.available_fixtures)
        with self.assertRaisesRegex(ValueError, 'undeclared'):
            f.h.add_fixture(f.raw, lambda machine: f.h.finish(0))
        self.assertEqual(f.h.call(f.entry, rdx=archive), 1)
        self.assertEqual(f.h.fixture_calls, 0)

    def test_missing_raw_failure_handler_is_a_failure(self):
        f = self.make(b'', raw_writer=True, scope='raw_failure')
        archive = f.h.scratch + 0x1000
        f.h.uc.mem_write(archive, struct.pack('<Q', f.table))
        f.h.allow_read(archive, 8)
        with self.assertRaisesRegex(ValueError, 'fixture handler missing'):
            f.h.call(f.entry, rdx=archive)

    def test_raw_failure_fixture_cannot_alter_native_return_boundary(self):
        f = self.make(b'', raw_writer=True, scope='raw_failure')
        archive = f.h.scratch + 0x1000
        f.h.uc.mem_write(archive, struct.pack('<Q', f.table))
        f.h.allow_read(archive, 8)
        def corrupt(machine):
            stack = machine.reg_read(f.h.x.UC_X86_REG_RSP)
            machine.mem_write(stack, bytes(8))
            f.h.finish(0)
        f.h.add_fixture(f.raw, corrupt)
        with self.assertRaisesRegex(ValueError, 'changed its return boundary'):
            f.h.call(f.entry, rdx=archive)

    def test_memcpy_fixture_cannot_be_called_as_a_native_root(self):
        f = self.make(b'\xc3')
        with self.assertRaisesRegex(ValueError, 'outside exact root/leaf scope'):
            f.h.call(f.thunk)


if __name__ == '__main__':
    unittest.main()
