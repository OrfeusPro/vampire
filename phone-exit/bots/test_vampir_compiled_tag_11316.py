import importlib.util
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent/'resource-tools/vampir'


class CompiledTag11316Tests(unittest.TestCase):
    def test_11318_tag_is_read_from_current_constructors_and_consumers(self):
        from test_vampir_version_login_context import context, load, ROOT, SHA11318
        reports=[load('verify-version-login-context').verify(context(name,SHA11318),ROOT)
                 for name in ('game-version','game-login')]
        self.assertEqual(reports[0]['binding']['tag'],reports[1]['binding']['tag'])
        self.assertEqual(reports[0]['binding']['pointer'],'0x14b1bbe98')
        self.assertEqual(reports[1]['binding']['literal'],'0x149961820')
        self.assertTrue(all(len(r['cases'])==4 and not r['network_used'] for r in reports))

    def tool(self):
        spec = importlib.util.spec_from_file_location('compiled_tag_11316_test', HERE/'replay-compiled-tag-11316.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_actual_slice_uses_current_pointer_and_copies_public_tag(self):
        report = self.tool().replay()
        self.assertEqual(report['binding'], dict(pointer_address='0x14b1b9e98', pointer_file_offset=186353816,
            pointer_bytes='2000964901000000', literal_address='0x149960020', literal_file_offset=160819744,
            compiled_tag='32283C4C6485307BCF524765A84409C3'))
        self.assertEqual(len(report['cases']), 4)
        for case in report['cases']:
            self.assertEqual(case['events'], ['construct', 'allocate', 'copy'])
            self.assertTrue(case['canaries_unchanged'])
            self.assertEqual(case['tag'], report['binding']['compiled_tag'])
        self.assertFalse(report['network_ready'])

    def test_corrupt_export_rejects_before_execution(self):
        tool = self.tool()
        tool.EXPORTS = {'run-571e3ba7330a': '0'*64}
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.replay()

    def test_malformed_literal_rejects_without_using_historical_value(self):
        class Image:
            class pe:
                base = 0
            def offset(self, address):
                return 0 if address == 0x14b1b9e98 else 8
        for data in (b'0'*31+b'G\0', b'0'*32+b'X', b'0'*31+b'\0'):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, 'literal format'):
                self.tool().binding((123).to_bytes(8, 'little')+data, Image())


if __name__ == '__main__':
    unittest.main()
