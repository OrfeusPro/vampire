"""Проверки чистого PAK directory формата без EXE, native replay и ключевых файлов."""
import copy
import hashlib
import struct
import sys
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import HERE, load

sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
import capstone


FORMAT = load('resource-directory-format-v1')
FIXTURE_KEY = bytes(range(32))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def decoder():
    result = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    result.detail = True
    return result


def key_fixture(displacements=None):
    displacements = displacements if displacements is not None else list(range(-32, 0, 4))
    code = b''.join(b'\xc7\x45' + struct.pack('b', displacement)
        + FIXTURE_KEY[(number % 8)*4:(number % 8)*4 + 4]
        for number, displacement in enumerate(displacements))
    # A direct call is decoded as data; the helper never executes it.
    code += b'\xe8\x00\x00\x00\x00\xc3'
    raw = b'\x00'*32 + code + b'\x00'*16
    instructions = [dict(address=ins.address, file_offset=32 + ins.address - 0x140001000,
        bytes=bytes(ins.bytes).hex()) for ins in decoder().disasm(code, 0x140001000)]
    proof = dict(exe_sha256=digest(raw), key_callback=dict(separate_key_file_saved=False,
        fragments=[dict(file_offset=32, begin_rva=0x1000, end_rva=0x1000 + len(code),
            sha256=digest(code), instructions=instructions)], cases=[dict(destination_delta=delta,
            poison=poison, output_bytes=32, output_sha256=digest(FIXTURE_KEY), guards_unchanged=True)
            for delta, poison in ((0, 0), (1, 85), (15, 170), (16, 255))]))
    return proof, raw


def prefix(*, method=1, blocks=19, encrypted=False, short=(True, True, True),
        position=4096, usize=1234567, size=654321, block_bits=32):
    bits = (method << 23) | (blocks << 6) | (bool(encrypted) << 22) | block_bits
    for enabled, bit in zip(short, (31, 30, 29)):
        bits |= bool(enabled) << bit
    value = struct.pack('<I', bits)
    value += struct.pack('<I' if short[0] else '<Q', position)
    value += struct.pack('<I' if short[1] else '<Q', usize)
    if method:
        value += struct.pack('<I' if short[2] else '<Q', size)
    return value


class DirectoryKeyProofTests(unittest.TestCase):
    def test_static_fixture_candidate_matches_saved_cases_without_execution(self):
        proof, raw = key_fixture()
        before = copy.deepcopy(proof)
        with patch('subprocess.run', side_effect=AssertionError('No execution permitted')):
            candidate = FORMAT.key_from_proof(proof, raw, decoder())
        self.assertEqual(candidate, FIXTURE_KEY)
        self.assertEqual(proof, before)

    def test_explicit_historical_candidate_source_is_used_without_current_exe_fallback(self):
        proof, raw = key_fixture()
        proof['key_candidate_source_sha256'] = proof['exe_sha256']
        proof['exe_sha256'] = 'a'*64
        self.assertEqual(FORMAT.key_from_proof(proof, raw, decoder()), FIXTURE_KEY)
        proof['exe_sha256'] = digest(raw)
        proof['key_candidate_source_sha256'] = 'b'*64
        with self.assertRaisesRegex(ValueError, 'static directory key proof'):
            FORMAT.key_from_proof(proof, raw, decoder())

    def test_source_or_fragment_byte_corruption_is_rejected_without_operand_diagnostics(self):
        proof, raw = key_fixture()
        changed = raw[:40] + bytes([raw[40] ^ 1]) + raw[41:]
        for update_source in (False, True):
            value = copy.deepcopy(proof)
            if update_source:
                value['exe_sha256'] = digest(changed)
            with self.subTest(update_source=update_source), self.assertRaises(ValueError) as error:
                FORMAT.key_from_proof(value, changed, decoder())
            self.assertEqual(str(error.exception), 'Invalid static directory key proof')

    def test_every_saved_case_and_output_digest_is_required(self):
        for change in ('missing', 'guards', 'bytes', 'poison', 'delta', 'hash', 'boolean'):
            proof, raw = key_fixture()
            cases = proof['key_callback']['cases']
            if change == 'missing':
                cases.pop()
            elif change == 'guards':
                cases[0]['guards_unchanged'] = False
            elif change == 'bytes':
                cases[0]['output_bytes'] = 31
            elif change == 'poison':
                cases[0]['poison'] = 1
            elif change == 'delta':
                cases[0]['destination_delta'] = 2
            elif change == 'hash':
                for case in cases:
                    case['output_sha256'] = 'f'*64
            else:
                cases[0]['destination_delta'] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                FORMAT.key_from_proof(proof, raw, decoder())

    def test_all_fragment_instructions_need_exact_bounds_and_single_instruction_decoding(self):
        for change in ('missing_row', 'offset', 'bytes', 'address_gap', 'merge', 'fragment_bounds', 'fragment_hash'):
            proof, raw = key_fixture()
            fragment = proof['key_callback']['fragments'][0]
            instructions = fragment['instructions']
            if change == 'missing_row':
                instructions.pop()
            elif change == 'offset':
                instructions[0]['file_offset'] -= 1
            elif change == 'bytes':
                instructions[0]['bytes'] = '90'
            elif change == 'address_gap':
                instructions[1]['address'] += 1
            elif change == 'merge':
                instructions[0]['bytes'] += instructions[1]['bytes']
                instructions.pop(1)
            elif change == 'fragment_bounds':
                fragment['end_rva'] += 1000
            else:
                fragment['sha256'] = 'f'*64
            with self.subTest(change=change), self.assertRaises(ValueError):
                FORMAT.key_from_proof(proof, raw, decoder())

    def test_exactly_eight_unique_contiguous_stack_stores_are_required(self):
        for positions in (list(range(-32, -4, 4)), list(range(-36, 0, 4)),
                [-32, -28, -24, -20, -16, -12, -8, -8],
                [-36, -28, -24, -20, -16, -12, -8, -4]):
            proof, raw = key_fixture(positions)
            with self.subTest(positions=positions), self.assertRaises(ValueError):
                FORMAT.key_from_proof(proof, raw, decoder())

    def test_wrong_architecture_or_missing_details_is_rejected(self):
        proof, raw = key_fixture()
        for mode, details in ((capstone.CS_MODE_32, True), (capstone.CS_MODE_64, False)):
            value = capstone.Cs(capstone.CS_ARCH_X86, mode)
            value.detail = details
            with self.subTest(mode=mode, details=details), self.assertRaises(ValueError):
                FORMAT.key_from_proof(proof, raw, value)


class DirectoryEntryPrefixTests(unittest.TestCase):
    def test_scalar_prefix_supports_mixed_32_and_64_bit_fields_and_multiblock(self):
        for short in ((True, True, True), (False, False, False), (True, False, True)):
            encoded = b'padding' + prefix(short=short, encrypted=True, blocks=148)
            actual = FORMAT.entry_prefix(encoded, 7)
            self.assertEqual(actual, dict(offset=4096, bytes=654321, uncompressed=1234567,
                method=1, encrypted=True, blocks=148))

    def test_stored_prefix_uses_uncompressed_size_without_assuming_block_arrays(self):
        value = FORMAT.entry_prefix(prefix(method=0, blocks=0, block_bits=0,
            short=(False, False, False), size=1), 0)
        self.assertEqual(value, dict(offset=4096, bytes=1234567, uncompressed=1234567,
            method=0, encrypted=False, blocks=0))
        # No compressed block array is consumed or claimed by the prefix reader.
        self.assertEqual(FORMAT.entry_prefix(prefix(blocks=148), 0)['blocks'], 148)

    def test_empty_stored_records_allow_both_encryption_flags(self):
        for encrypted in (False, True):
            value = prefix(method=0, blocks=0, block_bits=0, position=128261157,
                usize=0, encrypted=encrypted)
            with self.subTest(encrypted=encrypted):
                self.assertEqual(FORMAT.entry_prefix(value, 0), dict(offset=128261157,
                    bytes=0, uncompressed=0, method=0, encrypted=encrypted, blocks=0))

    def test_every_truncated_scalar_prefix_is_rejected(self):
        value = prefix(short=(False, False, False))
        for length in range(len(value)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                FORMAT.entry_prefix(value[:length], 0)

    def test_unknown_method_inconsistent_blocks_and_empty_sizes_are_rejected(self):
        for value in (prefix(method=2), prefix(method=0, blocks=1), prefix(method=1, blocks=0),
                prefix(usize=0), prefix(size=0)):
            with self.subTest(value_bytes=len(value)), self.assertRaises(ValueError):
                FORMAT.entry_prefix(value, 0)

    def test_prefix_offset_type_and_buffer_budget_are_bounded(self):
        value = prefix()
        for offset in (-1, len(value), True, '0'):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                FORMAT.entry_prefix(value, offset)
        with patch.object(FORMAT, 'MAX_ENCODED', 8), self.assertRaisesRegex(ValueError, 'prefix'):
            FORMAT.entry_prefix(value, 0)


class LogicalDirectoryPathTests(unittest.TestCase):
    def test_historical_mounts_produce_logical_paths_without_filesystem_resolution(self):
        self.assertEqual(FORMAT.canonical_path('../../../ProjectRED/Content/RED/Data/', 'CSV/Achievement.csv'),
            'ProjectRED/Content/RED/Data/CSV/Achievement.csv')
        self.assertEqual(FORMAT.canonical_path('../../../', 'Engine/A B.uasset'), 'Engine/A B.uasset')
        self.assertEqual(FORMAT.canonical_path('ProjectRED/Content', 'UI/Icon.uasset'),
            'ProjectRED/Content/UI/Icon.uasset')

    def test_mount_and_relative_path_reject_host_paths_traversal_and_ambiguity(self):
        pairs = [('../../../../ProjectRED/', 'A.csv'), ('../../.././ProjectRED/', 'A.csv'),
            ('../../../ProjectRED//Data/', 'A.csv'), ('/absolute/', 'A.csv'), ('C:/Data/', 'A.csv'),
            ('../../../', '../A.csv'), ('../../../', './A.csv'), ('../../../', '/A.csv'),
            ('../../../', 'A//B.csv'), ('../../../', 'A/'), ('../../../', 'A\\B.csv'),
            ('../../../', 'A:stream'), ('../../../', 'A\0B.csv'), ('../../../', 'A\nB.csv'),
            ('../../../', ''), ('', 'A.csv')]
        for mount, path in pairs:
            with self.subTest(mount=mount, path=path), self.assertRaises(ValueError):
                FORMAT.canonical_path(mount, path)

    def test_logical_path_budget_includes_joined_mount_and_relative_path(self):
        with self.assertRaisesRegex(ValueError, 'budget'):
            FORMAT.canonical_path('../../../' + 'M'*2048 + '/', 'N'*2048)
        with self.assertRaises(ValueError):
            FORMAT.canonical_path('../../../', 'N'*(FORMAT.MAX_PATH + 1))


if __name__ == '__main__':
    unittest.main()
