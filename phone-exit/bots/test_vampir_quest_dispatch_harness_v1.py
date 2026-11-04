"""Executable fixture provenance and memory boundaries for the dispatch harness."""
import hashlib
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from test_vampir_update_contracts import load


HARNESS = load('quest-dispatch-harness-v1')
NATIVE = load('build-native-entry-code')
RULES = load('quest-action-transfer-rules-v1')
LEAVES = load('login-input-transfer-rules')
BASE = 0x140000000
ENTRY, OTHER, LEAF, FIXTURE, GLOBAL = (BASE + offset for offset in (0x1000, 0x1100, 0x1200, 0x2fff, 0x4080))
ENTER_CALL = bytes.fromhex('4883ec28')
LEAVE_CALL = bytes.fromhex('4883c428c3')
CALL_RCX = b'\xff\xd1'


def relative(opcode, address, target):
    return opcode + struct.pack('<i', target - address - len(opcode) - 4)


def machine(code, *, other=None, fixture=FIXTURE, indirect=()):
    bodies = {ENTRY: code}
    if other is not None:
        bodies[OTHER] = other
    raw = bytearray(0x5000)
    for address, body in {**bodies, LEAF: b'\xc3'}.items():
        raw[address - BASE:address - BASE + len(body)] = body
    raw = bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    sections = [dict(name='.text', rva=0x1000, size=0x3000, raw_size=0x3000),
                dict(name='.data', rva=0x4000, size=0x1000, raw_size=0x1000)]
    image = SimpleNamespace(data=raw, offset=lambda rva: rva,
                            pe=SimpleNamespace(base=BASE, sections=sections))
    store = SimpleNamespace(root=Path(__file__).resolve().parent,
                            source=lambda identity: raw, image=lambda native, identity: image)
    instructions = {at: RULES.decode(NATIVE, image, at, len(body)) for at, body in bodies.items()}
    exports = [dict(new_source_sha256=sha, functions=[dict(address=hex(at), decompilation_completed=True,
        instructions=[dict(address=hex(row['address']), bytes=row['bytes']) for row in rows])
        for at, rows in instructions.items()])]
    context = dict(source_sha256=sha, source=str(store.root / 'client-code-snapshots' / sha /
        'ProjectRED-Win64-Shipping.exe'), functions={str(n): hex(at) for n, at in enumerate(bodies)},
        leaves={hex(LEAF): 'c3'}, handler_global=hex(GLOBAL), fixtures={'fixture': hex(fixture)},
        indirect_fixtures=indirect)
    modules = {'build-native-entry-code': NATIVE, 'login-input-transfer-rules': LEAVES,
               'update-bindings': SimpleNamespace(rows=lambda native, image, at: instructions[at])}
    return HARNESS.make_harness(SimpleNamespace(extension=modules.__getitem__), store, context, exports, {})


class DispatchHarnessBoundaryTests(unittest.TestCase):
    def test_typed_top_level_tail_preserves_return_boundary_and_abi(self):
        h = machine(relative(b'\xe9', ENTRY, FIXTURE))
        observed = []

        def fixture(uc):
            observed.append(uc.reg_read(h.x.UC_X86_REG_RSP))
            h.finish(0x1234)

        h.add_fixture(FIXTURE, fixture)
        self.assertEqual(h.call(ENTRY), 0x1234)
        self.assertEqual(observed, [HARNESS.STACK_ENTRY])
        metrics = h.validate()
        self.assertEqual((metrics['abi_checks'], metrics['fixture_calls']), (1, 1))

    def test_typed_tail_rejects_a_different_stack_even_with_stop_return(self):
        # Reserve a new aligned frame, then install the same sentinel on it.
        fake_frame = bytes.fromhex('4883ec1048b8') + struct.pack('<Q', HARNESS.STOP) + bytes.fromhex('48890424')
        h = machine(fake_frame + relative(b'\xe9', ENTRY + len(fake_frame), FIXTURE))
        h.add_fixture(FIXTURE, lambda uc: self.fail('Unreviewed tail stack reached fixture'))
        with self.assertRaisesRegex(ValueError, 'caller/return boundary'):
            h.call(ENTRY)

    def test_indirect_fixture_requires_exact_call_site_at_execution(self):
        body = ENTER_CALL + CALL_RCX + LEAVE_CALL
        target = HARNESS.INDIRECT_FIXTURE
        h = machine(body, other=body, fixture=target,
                    indirect=[(hex(ENTRY + len(ENTER_CALL)), 'rcx', hex(target))])
        h.add_fixture(target, lambda uc: h.finish(0x4321))
        self.assertEqual(h.call(ENTRY, target), 0x4321)
        with self.assertRaisesRegex(ValueError, 'caller/return boundary'):
            h.call(OTHER, target)

    def test_indirect_fixture_declaration_requires_exact_operand_and_instruction(self):
        body = ENTER_CALL + CALL_RCX + LEAVE_CALL
        target = HARNESS.INDIRECT_FIXTURE
        for site, operand in ((ENTRY + len(ENTER_CALL), 'rdx'), (ENTRY, 'rcx')):
            with self.subTest(site=hex(site), operand=operand):
                with self.assertRaisesRegex(ValueError, 'indirect fixture scope'):
                    machine(body, fixture=target, indirect=[(hex(site), operand, hex(target))])

    def test_global_shadow_grants_only_the_exact_readable_eight_bytes(self):
        h = machine(relative(bytes.fromhex('488b05'), ENTRY, GLOBAL) + b'\xc3',
                    other=relative(bytes.fromhex('488b05'), OTHER, GLOBAL + 1) + b'\xc3')
        value = h.scratch + 0x100
        h.set_global(value)
        self.assertEqual(h.call(ENTRY), value)
        with self.assertRaisesRegex(ValueError, 'native read outside declared input'):
            h.call(OTHER)
        writer = machine(relative(bytes.fromhex('48890d'), ENTRY, GLOBAL) + b'\xc3')
        writer.set_global(value)
        with self.assertRaisesRegex(ValueError, 'write-protected memory'):
            writer.call(ENTRY, value + 8)
        self.assertEqual(bytes(writer.uc.mem_read(GLOBAL, 8)), struct.pack('<Q', value))

    def test_call_fixture_at_page_end_returns_without_reading_unmapped_code(self):
        h = machine(ENTER_CALL + relative(b'\xe8', ENTRY + len(ENTER_CALL), FIXTURE) + LEAVE_CALL)
        h.add_fixture(FIXTURE, lambda uc: h.finish(0x5678))
        self.assertEqual(h.call(ENTRY), 0x5678)


if __name__ == '__main__':
    unittest.main()
