import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
from vampir_core.nid_metadata import encode_nid_metadata_with_device_key


class MetadataDeviceKeyTests(unittest.TestCase):
    def test_suffix_order_duplicates_and_explicit_identity(self):
        self.assertEqual(encode_nid_metadata_with_device_key({'I_World':'','I_PID':'fixture-player'},
            device_key='fixture-key',user_info_available=True),
            '{"I_PID":"fixture-player","I_World":"","I_World":"","I_DeviceKey":"fixture-key"}')

    def test_key_validation_and_missing_user_info(self):
        for key in ('',None,42,'quote"','slash\\','line\n','\ud800','x'*4097):
            with self.subTest(kind=type(key).__name__),self.assertRaises(ValueError):
                encode_nid_metadata_with_device_key({'I_PID':'fixture'},device_key=key,user_info_available=True)
        with self.assertRaises(ValueError):
            encode_nid_metadata_with_device_key({'I_PID':'fixture'},device_key='fixture',user_info_available=False)
        with self.assertRaises(ValueError):
            encode_nid_metadata_with_device_key({},device_key='fixture',user_info_available=True)


if __name__=='__main__':unittest.main()
