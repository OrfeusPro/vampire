import importlib.util,math,struct,types,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('area_priority_tests',Path(__file__).parent/'resource-tools/vampir/recast-area-priority-emulator.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class AreaPriorityInputTests(unittest.TestCase):
    def test_invalid_cost_arrays_fail_before_native_execution(self):
        instance=object.__new__(module.AreaPriorityEmulator)
        for costs,fixed in [([1]*63,[0]*64),([1]*64,[0]*65),([math.nan]*64,[0]*64),([1]*64,[math.inf]*64),([1e308]*64,[1e308]*64)]:
            with self.assertRaises(ValueError):instance.priorities(costs,fixed)

    def test_native_cost_reads_cannot_touch_object_header_or_past_last_double(self):
        instance=object.__new__(module.AreaPriorityEmulator);instance.cost_input=0x5000000;instance.inputs=[];instance.lengths=[]
        for delta,size in [(8,8),(0x200,8),(0x208,8),(0x400,8)]:instance.read_guard(None,None,instance.cost_input+delta,size,0,None)
        for delta,size in [(0,8),(4,8),(0x400,16),(0x408,8)]:
            with self.assertRaises(ValueError):instance.read_guard(None,None,instance.cost_input+delta,size,0,None)

    def fixture(self):
        raw=bytearray(2048);struct.pack_into('<I',raw,60,128);struct.pack_into('<II',raw,128+24+112+8,512,40)
        struct.pack_into('<5I',raw,512,768,0,0,600,0x800);raw[600:606]=b'A.dll\0'
        struct.pack_into('<3Q',raw,768,900,920,0);raw[902:907]=b'logf\0';raw[922:927]=b'expf\0'
        image=types.SimpleNamespace(pe=types.SimpleNamespace(base=0x140000000),offset=lambda rva:rva)
        return raw,image

    def test_import_lookup_follows_iat_index_instead_of_matching_nearby_name(self):
        raw,image=self.fixture();result=module.import_at_slot(image,raw,0x140000808)
        self.assertEqual((result['dll'],result['name']),('A.dll','expf'))
        self.assertEqual(result['thunk_file_offset'],776)

    def test_missing_and_ordinal_imports_are_not_guessed(self):
        raw,image=self.fixture()
        with self.assertRaises(ValueError):module.import_at_slot(image,raw,0x140000900)
        struct.pack_into('<Q',raw,776,(1<<63)|3)
        with self.assertRaises(ValueError):module.import_at_slot(image,raw,0x140000808)

if __name__=='__main__':unittest.main()
