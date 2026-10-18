import importlib.util,math,struct,unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
attachment=load('attachment_guard_tests','recast-attachment-emulator.py')
bv=load('bv_query_tests','build-recast-bv-nearest-study.py')

class AttachmentGuardTests(unittest.TestCase):
    def test_native_writes_are_limited_to_exact_polygon_heads_and_special_vertices(self):
        instance=object.__new__(attachment.AttachmentEmulator);instance.base=0x2000000
        instance.input_writes=[];instance.allowed_input_writes=[(0x3000100,0x3000104),(0x3000200,0x3000218)]
        for address,size in [(instance.base,8),(0x3000100,4),(0x3000200,16),(0x3000210,8)]:instance.write_guard(None,None,address,size,0,None)
        for address,size in [(0x3000100,8),(0x30000ff,4),(0x3000210,16),(0x3000300,4)]:
            with self.assertRaises(ValueError):instance.write_guard(None,None,address,size,0,None)
        self.assertEqual(len(instance.input_writes),3)

    def test_attachment_rejects_unknown_sides_and_out_of_range_record_before_execution(self):
        instance=object.__new__(attachment.AttachmentEmulator);raw=bytearray(88);struct.pack_into('<H',raw,26,1)
        for index,side in [(0,8),(0,-1),(-1,0),(1,0)]:
            with self.assertRaises(ValueError):instance.attach(raw,raw,[1,1,1],[0]*64,index,side)

    def test_bv_mode_rejects_invalid_scale_or_priority_without_running_native_code(self):
        instance=object.__new__(attachment.base.BVNearestEmulator)
        for scales,priorities in [([0,1,1],None),([1,math.inf,1],None),([1,1],None),([1,1,1],[0]*63),([1,1,1],[256]*64)]:
            with self.assertRaises(ValueError):instance.query([0,0,0],[1,1,1],scales,priorities)

    def test_bv_fixture_keeps_section_alignment_and_leaf_polygon_identity(self):
        raw=bv.bv_triangle();sections=attachment.base.base.parent.tile_sections(raw)
        self.assertEqual(struct.unpack_from('<H',raw,24)[0],1)
        self.assertEqual(sections[64],208)
        self.assertEqual(struct.unpack_from('<6Hi',raw,208),(0,0,0,1,0,1,0))
        self.assertEqual(len(raw),232)

if __name__=='__main__':unittest.main()
