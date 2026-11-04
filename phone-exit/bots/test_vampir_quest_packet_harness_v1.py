"""Execute small synthetic x64 functions to exercise the new harness guards."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load

HARNESS = load('quest-packet-harness-v1')
NATIVE = load('build-native-entry-code')


class PacketHarnessTests(unittest.TestCase):
    def make(self, code):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        base = 0x140000000
        entry, copy_root, copy_thunk = base + 0x1000, base + 0x1100, base + 0x2000
        helper = b'\x48\x83\xec\x28\xe8' + struct.pack('<i', copy_thunk - (copy_root + 9)) + b'\x48\x83\xc4\x28\xc3'
        raw = bytearray(0x4000)
        raw[0x1000:0x1000 + len(code)] = code
        raw[0x1100:0x1100 + len(helper)] = helper
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
        instructions = {entry: rows(entry, code), copy_root: rows(copy_root, helper)}
        report = dict(new_source_sha256=sha, functions=[dict(address=hex(at), decompilation_completed=True,
            instructions=[dict(address=hex(row['address']), bytes=row['bytes']) for row in items])
            for at, items in instructions.items()])
        payload = json.dumps(report).encode()
        export = root / 'ghidra/request-exports' / sha / 'run-fixture' / 'details.json'
        export.parent.mkdir(parents=True)
        export.write_bytes(payload)
        context = dict(source_sha256=sha, source=str(root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'),
                       family='quest-sync', functions=dict(entry=hex(entry), raw=hex(copy_root)), leaves={}, bindings=[], fixtures={})
        image = SimpleNamespace(offset=lambda rva: rva, pe=SimpleNamespace(base=base))
        store = SimpleNamespace(source=lambda identity: raw, image=lambda native, identity: image)
        admission = SimpleNamespace(source_sha256=sha, store=store, proof=dict(package=dict(relation=dict(tables=[],
            boundaries=[dict(consumer='shared-input', role='memcpy', target=hex(copy_thunk))]))))
        original = HARNESS.load
        def extension(name):
            if name == 'update-bindings':
                return SimpleNamespace(rows=lambda native, image, at: instructions[at])
            return original(name)
        with patch.object(HARNESS, 'admit', return_value=admission), patch.object(HARNESS, 'load', side_effect=extension):
            h = HARNESS.make_harness(context, {'run-fixture': hashlib.sha256(payload).hexdigest()}, set(instructions), root=root)
        return h, entry, copy_root

    def test_preserved_win64_registers_and_aligned_return_are_verified(self):
        h, entry, _ = self.make(b'\xb8\x2a\0\0\0\xc3')
        self.assertEqual(h.call(entry), 42)
        self.assertEqual(h.abi_checks, 1)

    def test_nonvolatile_register_corruption_is_rejected(self):
        h, entry, _ = self.make(b'\x48\x31\xdb\xc3')
        with self.assertRaisesRegex(ValueError, 'nonvolatile'):
            h.call(entry)

    def test_read_past_declared_input_is_rejected(self):
        h, entry, _ = self.make(b'\x48\x8b\x01\xc3')
        source = h.scratch + 0x1000
        h.allow_read(source, 4)
        with self.assertRaisesRegex(ValueError, 'read outside'):
            h.call(entry, source)

    def test_source_memory_cannot_be_written(self):
        h, entry, _ = self.make(b'\xc6\x01\0\xc3')
        with self.assertRaisesRegex(ValueError, 'write outside'):
            h.call(entry, entry)

    def test_output_write_requires_an_explicit_region(self):
        h, entry, _ = self.make(b'\xc6\x01\x2a\xc3')
        destination = h.scratch + 0x1000
        with self.assertRaisesRegex(ValueError, 'write outside'):
            h.call(entry, destination)
        h.allow_write(destination, 1)
        h.call(entry, destination)
        self.assertEqual(bytes(h.uc.mem_read(destination, 1)), b'\x2a')

    def test_memcpy_checks_native_caller_source_and_destination(self):
        h, _, copy_root = self.make(b'\xc3')
        source, destination = h.scratch + 0x1000, h.scratch + 0x2000
        h.allow_read(source, 4)
        h.allow_write(destination, 4)
        h.uc.mem_write(source, b'ABCD')
        h.call(copy_root, destination, rdx=source, r8=4)
        self.assertEqual(bytes(h.uc.mem_read(destination, 4)), b'ABCD')
        with self.assertRaisesRegex(ValueError, 'memcpy'):
            h.call(copy_root, destination, rdx=source, r8=5)

    def test_duplicate_or_foreign_fixture_cannot_shadow_native_code(self):
        h, entry, _ = self.make(b'\xc3')
        with self.assertRaisesRegex(ValueError, 'undeclared'):
            h.add_fixture(entry, lambda machine: None)

    def test_instruction_budget_exhaustion_is_a_failure(self):
        h, entry, _ = self.make(b'\xeb\xfe')
        with self.assertRaisesRegex(ValueError, 'budget exhausted'):
            h.call(entry, budget=10)


if __name__ == '__main__':
    unittest.main()
