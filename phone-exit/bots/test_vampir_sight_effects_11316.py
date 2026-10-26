"""Whole two nested SightEnter record readers; offline synthetic bytes only."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.sight_effect_records import SOURCE_SHA256,decode_ground_effect_data,decode_tether_effect_data


class SightEffectsTests(unittest.TestCase):
    def test_whole_native_readers_constructors_input_xyz_yaw(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-sight-effects-11316.py'
        spec=importlib.util.spec_from_file_location('sight_effects_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.verify()['cases'],2580)

    def test_fixed_limits_raw_float_heading_boolean_and_source(self):
        body=bytearray(50);body[28:40]=struct.pack('<III',0x7fc12345,0x80000000,0x3f800000)
        body[40]=255;body[45:49]=struct.pack('<I',0x7fc12345);body[49]=255
        result=decode_ground_effect_data(bytes(body),source_sha256=SOURCE_SHA256)
        self.assertEqual(result.at(0x28).bits,(0x7fc12345,0x80000000,0x3f800000))
        self.assertEqual(result.at(0x40).raw_byte,255);self.assertEqual(result.at(0x6c),0x7fc12345);self.assertEqual(result.at(0x70),3)
        with self.assertRaises(ValueError):result.at(0x28).finite_values()
        for decoder,size in ((decode_ground_effect_data,50),(decode_tether_effect_data,66)):
            for length in (0,size-1,size+1,65537):
                with self.assertRaises(ValueError):decoder(bytes(length),source_sha256=SOURCE_SHA256)
            with self.assertRaises(TypeError):decoder(bytearray(size),source_sha256=SOURCE_SHA256)
            with self.assertRaises(ValueError):decoder(bytes(size),source_sha256='old')
        for flag in (0,1,255):
            result=decode_tether_effect_data(bytes(65)+bytes([flag]),source_sha256=SOURCE_SHA256)
            self.assertIs(result.at(0x8c),bool(flag))


if __name__=='__main__':unittest.main()
