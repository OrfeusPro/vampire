"""Independent byte/state checks of pure expectations; no native execution."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest import mock
import zlib

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oracle = load('frame-integrity-oracle')
contract = oracle.CONTRACT


def prepared_fixture(ordinal=8):
    strings = {hex(offset): '' for offset in oracle.HANDOFF.STRING_OFFSETS}
    strings['0x10'] = 'Ж🙂'
    integers = {hex(offset): 0 for offset in oracle.HANDOFF.SCALAR_WIDTHS}
    integers.update({'0x50': 0x89abcdef, '0x120': 0 if ordinal == 8 else 0xffffffff,
                     '0x130': 0x80, '0x131': 0xff})
    return dict(strings=strings, integers=integers)


class FrameIntegrityOracleTests(unittest.TestCase):
    def test_existing_primitive_and_ping_import_are_actual_hashed_dependencies(self):
        tools = contract.tools()
        for module in (oracle.PRIMITIVES, oracle.PING):
            path = Path(module.__file__)
            self.assertEqual(tools[str(path)], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_crc_known_prefixes_keep_raw_state_and_empty_continuation(self):
        spec = next(s for s in contract.primitive_specs()
                    if s['operation'] == 'crc' and s['group'] == 'incremental')
        obs = oracle.expected_case(spec)['observation']
        self.assertEqual(obs['values'], [0, 0x83dcefb7, 0x9ae0daaf, 0x9ae0daaf, 0xcbf43926, 0xcbf43926])
        self.assertEqual(obs['states'], [value ^ 0xffffffff for value in obs['values']])
        altered = oracle.expected_case(spec)
        altered['observation']['states'][1] = altered['observation']['values'][1]
        with self.assertRaises(ValueError):
            oracle.validate_case(altered, spec)

    def test_arbitrary_raw_seed_uses_complemented_external_zlib_seed(self):
        spec = next(s for s in contract.primitive_specs()
                    if s['operation'] == 'crc' and s['group'] == 'raw-seed' and s['payload_hex'])
        obs = oracle.expected_case(spec)['observation']
        data = bytes.fromhex(spec['payload_hex'])
        expected = zlib.crc32(data, 0xffffffff) & 0xffffffff
        self.assertEqual(obs['values'], [expected])
        self.assertNotEqual(obs['values'], [zlib.crc32(data) & 0xffffffff])
        self.assertEqual(obs['init_calls'], 0)

    def test_xor_key_order_signed_return_and_fallback_are_exact(self):
        for spec in contract.primitive_specs():
            if spec['operation'] != 'xor':
                continue
            obs = oracle.expected_case(spec)['observation']
            if spec['group'] == 'known-order':
                self.assertEqual(bytes.fromhex(obs['output_hex']),
                                 (spec['key_bits'] or contract.FALLBACK_KEY).to_bytes(8, 'little'))
            if spec['group'] == 'signed':
                self.assertEqual(obs['output_hex'], '')
                self.assertIn(obs['returned'], (0x80000000, 0xffffffff))
                self.assertGreaterEqual(obs['returned'], 0)
            self.assertIs(obs['disjoint_source_immutable'], None if spec['in_place'] else True)

    def test_real_frame_crc_covers_id_old_sequence_body_and_header_stays_plain(self):
        spec = next(s for s in contract.integration_specs() if s['prepared_ordinal'] == 8)
        row = oracle.expected_case(spec, {8: prepared_fixture()})
        wire = row['observation']['wire']
        body = bytes.fromhex(wire['writer_delta_hex'])
        # FString length is UTF-8 byte length, bool values remain raw bytes.
        self.assertEqual(body[:2], struct.pack('<H', len('Ж🙂'.encode('utf-8'))))
        self.assertEqual(body[-2:], bytes.fromhex('80ff'))
        frame = bytes.fromhex(wire['frame_hex'])
        self.assertEqual(int.from_bytes(frame[:3], 'little'), len(frame))
        key = contract.FALLBACK_KEY.to_bytes(8, 'little')
        decoded = bytes(value ^ key[i & 7] for i, value in enumerate(frame[3:]))
        self.assertEqual(decoded[4:8], bytes.fromhex('03000000'))
        self.assertEqual(decoded[8:], body)
        self.assertEqual(int.from_bytes(decoded[:4], 'little'), zlib.crc32(decoded[4:]) & 0xffffffff)
        self.assertEqual(wire['checksum_final_state'], int.from_bytes(decoded[:4], 'little') ^ 0xffffffff)
        self.assertNotEqual(frame, bytes.fromhex(wire['plaintext_frame_hex']))

    def test_wrong_crc_range_key_order_sequence_or_identity_fixture_is_rejected(self):
        spec = contract.integration_specs()[0]
        prepared = {8: prepared_fixture()}
        original = oracle.expected_case(spec, prepared)
        for key, replacement in (('checksum_value', 0x6a09e667), ('transform_identity', True),
                ('transform_effective_key_bits', 0), ('writer_prefix_hex', '03000100'),
                ('transport_before_cleanup', False)):
            actual = copy.deepcopy(original)
            actual['observation']['wire'][key] = replacement
            with self.assertRaises(ValueError):
                oracle.validate_case(actual, spec, prepared)

    def test_parent_selection_checks_exact_body_hash_and_accepted_writer_observation(self):
        projections, candidates, hashes = {}, [], []
        specs = oracle.PARENT_INPUT.prepared_specs()
        for ordinal, _, _ in contract.PREPARED_INPUTS:
            row = prepared_fixture(ordinal)
            row['integers']['0x50'] = ordinal
            projections[oracle.HANDOFF.parent_key(specs[ordinal])] = row
            body = oracle.BODY.login_body(row)
            hashes.append((ordinal, len(body), hashlib.sha256(body).hexdigest()))
            candidates.append(dict(prepared_ordinal=ordinal, group='core',
                pending_case='empty-count-equal', transport_result_byte=0,
                strings=row['strings'], integers=row['integers'],
                wire=dict(writer_calls=1, writer_delta_hex=body.hex())))
        prepare = dict(source_sha256='a' * 64)
        backend = dict(source_sha256='a' * 64, method='bounded_native',
                       scope='bounded_native_login_backend_wire', cases=candidates)
        with mock.patch.object(oracle.HANDOFF, 'prepared_rows', return_value=projections), \
                mock.patch.object(contract, 'PREPARED_INPUTS', tuple(hashes)):
            self.assertEqual(set(oracle.prepared_rows(prepare, backend)), {8, 5, 0, 16})
            wrong = copy.deepcopy(backend)
            wrong['cases'][0]['wire']['writer_delta_hex'] = '00'
            with self.assertRaises(ValueError):
                oracle.prepared_rows(prepare, wrong)
            duplicate = copy.deepcopy(backend)
            duplicate['cases'].append(copy.deepcopy(duplicate['cases'][0]))
            with self.assertRaises(ValueError):
                oracle.prepared_rows(prepare, duplicate)
            hashes[0] = (hashes[0][0], hashes[0][1], '0' * 64)
            with mock.patch.object(contract, 'PREPARED_INPUTS', tuple(hashes)):
                with self.assertRaises(ValueError):
                    oracle.prepared_rows(prepare, backend)


if __name__ == '__main__':
    unittest.main()
