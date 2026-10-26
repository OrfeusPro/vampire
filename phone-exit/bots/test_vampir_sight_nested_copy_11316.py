"""Native nested-copy ownership prerequisites for whole SightEnter."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class SightNestedCopyTests(unittest.TestCase):
    def test_native_copies_distinct_strings_arrays_map_nodes_and_buckets(self):
        self.assertEqual(load('replay-sight-nested-copy-11316').verify()['cases'],62)

    def test_appearance_item_leaf_is_complete_with_only_internal_branches(self):
        context=json.loads((HERE/'knowledge/native-contexts/sight-nested-copy-11316.json').read_text('utf-8'))
        native=load('build-native-entry-code');at=0x1456b5280;raw=bytes.fromhex(context['leaves'][hex(at)])
        rows=list(native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64).disasm(raw,at))
        self.assertEqual(len(raw),76);self.assertEqual(rows[-1].address,0x1456b52cb)
        self.assertEqual(rows[-1].mnemonic,'ret');self.assertEqual(sum(r.size for r in rows),len(raw))
        self.assertFalse(any(r.mnemonic=='call' for r in rows))
        addresses={r.address for r in rows}
        for row in rows:
            if row.mnemonic.startswith('j'):self.assertIn(int(row.op_str,16),addresses)


if __name__=='__main__':unittest.main()
