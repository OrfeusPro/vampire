"""Current allocation/source-copy boundaries; these tests never use the network."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('viper_cdo_current_tests', HERE / 'verify-viper-cdo-current.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ViperCdoCurrentTests(unittest.TestCase):
    def test_fresh_zero_branch_and_whole_composition_copy_only_declared_properties(self):
        result = tool.verify()
        report = json.loads(Path(result['report']).read_bytes())
        self.assertEqual(result['native_cases'], 24)
        self.assertEqual(len(report['allocation_cases']), 6)
        self.assertEqual(len(report['ordinary_cases']), 18)
        self.assertEqual({case['size'] for case in report['allocation_cases']}, {0x30, 0x78})
        self.assertTrue(all(case['zero_calls'] == 1 and not case['reused'] and case['guards_unchanged']
            for case in report['allocation_cases']))
        self.assertEqual(report['named_memset']['name'], 'memset')
        self.assertTrue(report['source_CDO_is_fixture'])
        for flag in ('runtime_admitted', 'loaded_preset_verified', 'complete_viper_payload_verified', 'network_used'):
            self.assertFalse(report[flag])
        self.assertEqual(len(report['whole_source']), 9)
        wrapper = next(row for row in report['whole_source'] if row['role'] == 'default_copy_wrapper')
        self.assertEqual(wrapper['instructions'], 16)
        self.assertEqual(wrapper['provenance'], 'whole_pe_unwind_bytes')
        self.assertFalse(wrapper['ghidra_export_admitted'])
        for case in report['ordinary_cases']:
            self.assertEqual(set(case['executed_roots'].values()), {1})
            self.assertEqual(len(case['executed_roots']), 9)
            self.assertEqual(case['completed_flags'], 0xb)
            self.assertTrue(case['guards_unchanged'])
            self.assertEqual(len(case['copied_fields']), {'empty': 0, 'all': 17, 'alternate': 9}[case['link_mode']])
            output = bytes.fromhex(case['output_bytes'])
            if case['link_mode'] == 'empty' or not case['modified_template']:
                self.assertEqual(output[:36], bytes(36))
                self.assertEqual(struct.unpack_from('<7fB', output, 36), (0.5,) * 7 + (0,))
            elif case['link_mode'] == 'all':
                self.assertEqual(struct.unpack_from('<9i', output), tuple(range(100, 109)))
                self.assertEqual(output[0x40], 3)
            else:
                self.assertEqual(struct.unpack_from('<9i', output), tuple(100 + i if i % 2 == 0 else 0 for i in range(9)))

    def test_partial_or_changed_wrapper_cannot_be_accepted_as_whole_source(self):
        for mutation in ('missing_instruction', 'changed_bytes'):
            with self.subTest(mutation=mutation):
                context = json.loads(tool.CONTEXT.read_bytes())
                if mutation == 'missing_instruction': context['default_copy_wrapper']['instructions'].pop()
                else: context['default_copy_wrapper']['instructions'][0]['bytes'] = '9053'
                with tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / 'context.json'; path.write_text(json.dumps(context), 'utf-8')
                    with self.assertRaisesRegex(ValueError, 'whole source changed|instruction differs from source'):
                        tool.verify(path)

    def test_changed_vtable_binding_cannot_inherit_the_copy_proof(self):
        context = json.loads(tool.CONTEXT.read_bytes())
        context['anchors'][0]['bytes'] = '00' * 8
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'context.json'; path.write_text(json.dumps(context), 'utf-8')
            with self.assertRaisesRegex(ValueError, 'source anchor changed'):
                tool.verify(path)

    def test_other_exe_sha_is_rejected_before_source_execution(self):
        context = json.loads(tool.CONTEXT.read_bytes()); context['source_sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'context.json'; path.write_text(json.dumps(context), 'utf-8')
            with self.assertRaisesRegex(ValueError, 'context/source differs'):
                tool.verify(path)


if __name__ == '__main__':
    unittest.main()
