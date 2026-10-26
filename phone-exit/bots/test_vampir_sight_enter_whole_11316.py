"""Whole native SightEnter with mixed arrays and bounded temporary owners."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class SightEnterWholeTests(unittest.TestCase):
    def test_whole_outer_callbacks_mixed_records_prefixes_copies_and_cleanup(self):
        result=load('replay-sight-enter-11316').verify()
        self.assertEqual(result['cases'],1170)
        self.assertEqual(result['summary'],dict(attempts=1176,copies=1242,temporary_records=4572,destructors=4352,released_buffers=28566))
        report=json.loads(Path(result['report']).read_text('utf-8'))
        self.assertFalse(report['network_used']);self.assertEqual(sum(row['accepted'] for row in report['cases']),6)

    def test_scope_rejects_missing_callback_and_changed_reader(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-enter-11316.json').read_text('utf-8'))
        functions={int(v,16) for v in context['functions'].values()};harness=load('update-native-harness')
        context['functions']['reader']='0x145788180'
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)
        context['functions']['reader']='0x1456c5390';functions.remove(0x1456c6400)
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)

    def test_move_copy_leaf_has_complete_internal_control_flow(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-enter-11316.json').read_text('utf-8'))
        at=0x1456bc8d0;data=bytes.fromhex(context['leaves'][hex(at)]);native=load('build-native-entry-code')
        rows=list(native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64).disasm(data,at))
        self.assertEqual(len(data),68);self.assertEqual(sum(row.size for row in rows),len(data))
        self.assertEqual(rows[-1].mnemonic,'ret');self.assertFalse(any(row.mnemonic=='call' for row in rows))
        addresses={row.address for row in rows}
        for row in rows:
            if row.mnemonic.startswith('j'):self.assertIn(int(row.op_str,16),addresses)


if __name__=='__main__':unittest.main()
