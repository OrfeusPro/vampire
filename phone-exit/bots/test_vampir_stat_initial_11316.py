"""Initial stats: source-bound native array/application and strict projection."""
import importlib.util
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE/'vampir-shared'))
from vampir_core.character_select_result import SelectionRecord
from vampir_core.stat_change import SOURCE_SHA256,initial_stat_values


class InitialStatTests(unittest.TestCase):
    def test_actual_initial_array_and_model_setter(self):
        spec=importlib.util.spec_from_file_location('initial_stat_native_test',HERE/'resource-tools/vampir/replay-stat-initial-11316.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.verify()['cases'],203)

    def test_initial_projection_is_exact_and_preserves_signed_bits(self):
        row=SelectionRecord(((8,0xffffffff),(16,2**64-1)))
        self.assertEqual(initial_stat_values((row,),source_sha256=SOURCE_SHA256),((-1,-1),))
        with self.assertRaises(ValueError):initial_stat_values((row,),source_sha256='unknown')
        with self.assertRaises(ValueError):initial_stat_values([row],source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):initial_stat_values((SelectionRecord(((8,4),(17,100))),),source_sha256=SOURCE_SHA256)
        with self.assertRaises(ValueError):initial_stat_values((row,)*1025,source_sha256=SOURCE_SHA256)


if __name__=='__main__':unittest.main()
