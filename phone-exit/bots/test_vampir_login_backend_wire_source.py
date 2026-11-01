import copy
import unittest
from types import SimpleNamespace
from test_vampir_update_contracts import load


class BackendWireSourceTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('login-backend-wire-source')
        self.native = load('build-native-entry-code')

    def image(self, raw):
        return SimpleNamespace(data=raw, pe=SimpleNamespace(base=0x1000,
            sections=[dict(name='.text', rva=0, raw=0, raw_size=len(raw), size=len(raw))]),
            offset=lambda rva: rva, containing=lambda at: None)

    def test_internal_conditional_return_is_not_external_tail(self):
        raw = bytes.fromhex('83793000750333c0c3488b4118c3')
        rows = self.tool.fragment(self.native, self.image(raw), 0x1000, raw.hex())
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[-1]['mnemonic'], 'ret')
        with self.assertRaises(ValueError):
            self.tool.fragment(self.native, self.image(raw), 0x1000, raw.hex(), tail_target=0x2000)

    def test_return_tail_call_and_mid_instruction_boundaries_are_rejected(self):
        for raw in (bytes.fromhex('eb10c3'), bytes.fromhex('e800000000c3'),
                bytes.fromhex('488b'), bytes.fromhex('ffe0')):
            with self.subTest(code=raw.hex()), self.assertRaises(ValueError):
                self.tool.fragment(self.native, self.image(raw), 0x1000, raw.hex())

    def test_finite_tail_checks_target_and_native_bytes(self):
        raw = bytes.fromhex('488b4910e947150000')
        image = self.image(raw)
        target = 0x1000+9+0x1547
        self.tool.fragment(self.native, image, 0x1000, raw.hex(), tail_target=target)
        with self.assertRaises(ValueError):
            self.tool.fragment(self.native, image, 0x1000, raw.hex(), tail_target=target+1)
        with self.assertRaises(ValueError):
            self.tool.fragment(self.native, image, 0x1000, '90'+raw.hex()[2:], tail_target=target)
        image.containing = lambda at: (0, 16, 0)
        with self.assertRaises(ValueError):
            self.tool.fragment(self.native, image, 0x1000, raw.hex(), tail_target=target)

    def test_whole_export_duplicate_missing_or_incomplete_rows_are_blockers(self):
        rows = [dict(address=0x100, bytes='33c0'), dict(address=0x102, bytes='c3')]
        fn = dict(address='0x100', decompilation_completed=True,
            block_coverage_complete=True, direct_flow_coverage_complete=True,
            instructions=[dict(address=hex(r['address']), bytes=r['bytes']) for r in rows])
        good = dict(functions=[fn])
        self.tool.check_coverage(good, 0x100, rows)
        mutations = []
        duplicate = copy.deepcopy(good)
        duplicate['functions'][0]['instructions'].append(fn['instructions'][0])
        mutations.append(duplicate)
        missing = copy.deepcopy(good)
        missing['functions'][0]['instructions'].pop()
        mutations.append(missing)
        partial = copy.deepcopy(good)
        partial['functions'][0]['direct_flow_coverage_complete'] = False
        mutations.append(partial)
        mutations.append(dict(functions=[fn, fn]))
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.tool.check_coverage(value, 0x100, rows)

    def test_whole_digest_preserves_bytes_and_relative_control_locations(self):
        rows = [dict(address=0x100, bytes='33c0'), dict(address=0x102, bytes='c3')]
        moved = [dict(address=r['address']+0x800, bytes=r['bytes']) for r in rows]
        self.assertEqual(self.tool.whole_digest(rows), self.tool.whole_digest(moved))
        moved[-1]['address'] += 1
        self.assertNotEqual(self.tool.whole_digest(rows), self.tool.whole_digest(moved))
        moved = copy.deepcopy(rows)
        moved[0]['bytes'] = '31c0'
        self.assertNotEqual(self.tool.whole_digest(rows), self.tool.whole_digest(moved))


if __name__ == '__main__':
    unittest.main()
