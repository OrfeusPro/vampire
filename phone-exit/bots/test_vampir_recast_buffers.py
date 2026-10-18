import copy,hashlib,importlib.util,struct,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('recast_buffer_validation',Path(__file__).parent/'resource-tools/vampir/validate-recast-tile-buffers.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class RecastBufferValidationTests(unittest.TestCase):
    def fixture(self):
        buffers=bytes(range(88))
        raw=bytes(14)+struct.pack('<iQi',26,23,1)+struct.pack('<i',88)+b'abc'+struct.pack('<i',-1)
        records=[dict(index=0,start=30,end=41,stream_tile_bytes=3,actual_memory_size=88,
                      stored_memory_size=88,buffer_offset=0,header=buffers.hex(),cache_memory_size=0,
                      tile_sha256=hashlib.sha256(buffers).hexdigest())]
        return raw,buffers,records

    def test_full_contiguous_export_and_buffer_coverage(self):
        raw,buffers,records=self.fixture()
        self.assertEqual(module.validate_package(raw,buffers,records),1)
        for key,value in [('index',1),('start',31),('end',40),('buffer_offset',1),
                          ('stored_memory_size',89),('actual_memory_size',87),('stream_tile_bytes',4)]:
            changed=copy.deepcopy(records);changed[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):module.validate_package(raw,buffers,changed)

    def test_changed_bytes_or_header_fail(self):
        raw,buffers,records=self.fixture()
        with self.assertRaises(ValueError):module.validate_package(raw,buffers[:-1]+b'x',records)
        records[0]['header']='00'*88
        with self.assertRaises(ValueError):module.validate_package(raw,buffers,records)

    def test_trailing_bytes_truncation_and_nonempty_cache_fail(self):
        raw,buffers,records=self.fixture()
        for changed_raw,changed_buffers in [(raw[:-1],buffers),(raw+b'x',buffers),(raw,buffers+b'x'),(raw[:-4]+bytes(4),buffers)]:
            with self.assertRaises(ValueError):module.validate_package(changed_raw,changed_buffers,records)


if __name__=='__main__':unittest.main()
