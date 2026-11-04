"""Live native call-frame and optional-global guards for Tutorial state replay."""
import hashlib
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from test_vampir_update_contracts import load


HARNESS = load('quest-tutorial-state-harness-v1')
NATIVE = load('build-native-entry-code')
RULES = load('quest-action-transfer-rules-v1')
LEAVES = load('login-input-transfer-rules')
BASE = 0x140000000
ENTRY, OTHER, FIXTURE, GLOBAL = (BASE + offset for offset in (0x1000, 0x1100, 0x2FFF, 0x4080))
ALLOCATE_FRAME = bytes.fromhex('4883ec28')
RELEASE_FRAME = bytes.fromhex('4883c428c3')


def relative(opcode, address, target):
    return opcode + struct.pack('<i', target - address - len(opcode) - 4)


def machine(code, *, other=None, readonly_globals=None, data=None):
    bodies = {ENTRY: code}
    if other is not None:
        bodies[OTHER] = other
    raw = bytearray(0x6000)
    for address, body in bodies.items():
        raw[address - BASE:address - BASE + len(body)] = body
    for address, value in (data or {}).items():
        raw[address - BASE:address - BASE + len(value)] = value
    raw = bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    sections = [dict(name='.text', rva=0x1000, raw=0x1000, size=0x3000, raw_size=0x3000),
                dict(name='.data', rva=0x4000, raw=0x4000, size=0x1000, raw_size=0x1000),
                dict(name='.rdata', rva=0x5000, raw=0x5000, size=0x1000, raw_size=0x1000)]
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
        leaves={}, fixtures={'fixture': hex(FIXTURE)})
    if readonly_globals is not None:
        context['readonly_globals'] = readonly_globals
    modules = {'build-native-entry-code': NATIVE, 'login-input-transfer-rules': LEAVES,
               'update-bindings': SimpleNamespace(rows=lambda native, image, at: instructions[at])}
    return HARNESS.make_harness(SimpleNamespace(extension=modules.__getitem__), store, context, exports, {})


class TutorialStateCallFrameTests(unittest.TestCase):
    def test_nested_native_call_then_tail_fixture_returns_to_actual_caller(self):
        body = ALLOCATE_FRAME + relative(b'\xe8', ENTRY + 4, OTHER) + RELEASE_FRAME
        h = machine(body, other=relative(b'\xe9', OTHER, FIXTURE))
        frames = []

        def fixture(uc):
            stack = uc.reg_read(h.x.UC_X86_REG_RSP)
            frames.append((stack, struct.unpack('<Q', uc.mem_read(stack, 8))[0]))
            h.finish(0x1234)

        h.add_fixture(FIXTURE, fixture)
        self.assertEqual(h.call(ENTRY), 0x1234)
        self.assertEqual(frames, [(HARNESS.STACK_ENTRY - 0x30, ENTRY + 9)])
        self.assertEqual(h.validate()['fixture_calls'], 1)
        self.assertEqual(h.entry_counts[OTHER], 1)

    def test_tail_rejects_forged_aligned_frame_or_another_allowed_return_pc(self):
        body = ALLOCATE_FRAME + relative(b'\xe8', ENTRY + 4, OTHER) + RELEASE_FRAME
        # Both return destinations below are valid instructions in the export.
        for adjustment, destination in ((bytes.fromhex('4883ec10'), ENTRY + 9), (b'', ENTRY + 13)):
            with self.subTest(adjustment=adjustment.hex(), destination=hex(destination)):
                forge = adjustment + bytes.fromhex('48b8') + struct.pack('<Q', destination) + bytes.fromhex('48890424')
                other = forge + relative(b'\xe9', OTHER + len(forge), FIXTURE)
                h = machine(body, other=other)
                h.add_fixture(FIXTURE, lambda uc: self.fail('Forged native frame reached fixture'))
                with self.assertRaisesRegex(ValueError, 'caller/return boundary'):
                    h.call(ENTRY)

    def test_direct_fixtures_and_native_return_balance_separate_live_frames(self):
        first = relative(b'\xe8', ENTRY + 4, FIXTURE)
        second = relative(b'\xe8', ENTRY + 9, FIXTURE)
        h = machine(ALLOCATE_FRAME + first + second + RELEASE_FRAME)
        calls = []

        def fixture(uc):
            stack = uc.reg_read(h.x.UC_X86_REG_RSP)
            calls.append(struct.unpack('<Q', uc.mem_read(stack, 8))[0])
            h.finish(0x5678)

        h.add_fixture(FIXTURE, fixture)
        self.assertEqual(h.call(ENTRY), 0x5678)
        self.assertEqual(calls, [ENTRY + 9, ENTRY + 14])
        self.assertEqual(h.validate()['fixture_calls'], 2)
        self.assertEqual(h.validate()['abi_checks'], 1)

    def test_optional_readonly_global_grants_exact_encoded_source_extent(self):
        instructions = {1: bytes.fromhex('0fb605'), 4: bytes.fromhex('8b05'),
                        8: bytes.fromhex('488b05'), 16: bytes.fromhex('f30f6f05')}
        for width, opcode in instructions.items():
            with self.subTest(width=width):
                address = GLOBAL + (0x1000 if width == 16 else 0)
                value = bytes(range(1, width + 1))
                body = relative(opcode, ENTRY, address) + b'\xc3'
                other = relative(opcode, OTHER, address + 1) + b'\xc3'
                h = machine(body, other=other, readonly_globals={hex(address): value.hex()},
                            data={address: value})
                result = h.call(ENTRY)
                if width == 16:
                    result = h.uc.reg_read(h.x.UC_X86_REG_XMM0)
                self.assertEqual(result, int.from_bytes(value, 'little'))
                with self.assertRaisesRegex(ValueError, 'native read outside declared input'):
                    h.call(OTHER)
                with self.assertRaisesRegex(ValueError, 'global pointer'):
                    h.set_global(h.scratch + 0x100)
        writer = machine(relative(bytes.fromhex('48890d'), ENTRY, GLOBAL) + b'\xc3',
                         readonly_globals={hex(GLOBAL): '00' * 8})
        with self.assertRaisesRegex(ValueError, 'write-protected memory'):
            writer.call(ENTRY, 0x1234)
        self.assertEqual(bytes(writer.uc.mem_read(GLOBAL, 8)), bytes(8))

    def test_readonly_global_rejects_width_mismatch_source_drift_and_text(self):
        invalid = (True, 8, '', '00' * 2, '00' * 3, '00' * 7, '00' * 9, '00' * 17)
        for encoded in invalid:
            with self.subTest(encoded=encoded):
                with self.assertRaisesRegex(ValueError, 'exact source storage'):
                    machine(b'\xc3', readonly_globals={hex(GLOBAL): encoded})
        with self.assertRaisesRegex(ValueError, 'readonly source bytes changed'):
            machine(b'\xc3', readonly_globals={hex(GLOBAL): '01' * 8})
        with self.assertRaisesRegex(ValueError, 'exact source storage'):
            machine(b'\xc3', readonly_globals={hex(ENTRY): 'c3'})

    def test_empty_leaf_scope_and_absent_global_execute_full_root(self):
        h = machine(bytes.fromhex('b82a000000c3'))
        self.assertEqual(h.call(ENTRY), 42)
        metrics = h.validate()
        self.assertEqual(metrics['call_counts'], 1)
        self.assertEqual(metrics['abi_checks'], 1)
        self.assertEqual(metrics['fixture_calls'], 0)


if __name__ == '__main__':
    unittest.main()
