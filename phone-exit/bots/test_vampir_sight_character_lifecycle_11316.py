"""CharacterOther native read/copy/destroy; bounded temporary storage only."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class CharacterLifecycleTests(unittest.TestCase):
    def test_native_read_copy_and_both_destructors_with_all_prefixes(self):
        result=load('replay-sight-character-other-lifecycle-11316').verify()
        self.assertEqual(result['cases'],1797)
        report=json.loads(Path(result['report']).read_text('utf-8'));proof=report['lifecycle_summary']
        self.assertEqual(proof['attempts'],2077);self.assertEqual(proof['copies'],560)
        self.assertEqual(proof['destructors'],2637);self.assertGreater(proof['released_owner_buffers'],560)

    def test_copy_leaf_bodies_have_only_internal_control_flow(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-character-other-lifecycle-11316.json').read_text('utf-8'))
        native=load('build-native-entry-code')
        for at,end in ((0x1456b5280,0x1456b52cc),(0x1456bc700,0x1456bc7fb),(0x1456bc800,0x1456bc843)):
            data=bytes.fromhex(context['leaves'][hex(at)])
            rows=list(native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64).disasm(data,at))
            self.assertEqual(len(data),end-at);self.assertEqual(sum(r.size for r in rows),len(data))
            self.assertEqual(rows[-1].mnemonic,'ret');self.assertFalse(any(r.mnemonic=='call' for r in rows))
            addresses={r.address for r in rows}
            for row in rows:
                if row.mnemonic.startswith('j'):self.assertIn(int(row.op_str,16),addresses)

    def test_lifecycle_scope_rejects_changed_function_set_and_entry(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-character-other-lifecycle-11316.json').read_text('utf-8'))
        functions={int(v,16) for v in context['functions'].values()};harness=load('update-native-harness')
        context['functions']['destroy']='0x145784630'
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)
        context['functions']['destroy']='0x145785200';functions.remove(0x145784630);functions.add(0x1457938b0)
        with self.assertRaisesRegex(ValueError,'budget exceeded'):harness.make_harness(context,context['exports'],functions)


if __name__=='__main__':unittest.main()
