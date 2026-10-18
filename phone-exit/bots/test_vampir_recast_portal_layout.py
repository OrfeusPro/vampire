import importlib.util,struct,unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
module=load('portal_layout','recast-portal-emulator.py')
fixtures=load('portal_fixtures','build-recast-portal-evidence.py')


class PortalLayoutTests(unittest.TestCase):
    def test_native_section_alignment_preserves_triangle_arrays(self):
        raw=fixtures.triangle_tile();sections=module.tile_sections(raw)
        self.assertEqual(sections[24],88)
        self.assertEqual(sections[16],160)
        self.assertEqual(sections[40],192)
        self.assertEqual(sections[56],200)
        self.assertEqual(list(raw[sections[56]:sections[56]+3]),[0,1,2])
        self.assertEqual(len(raw),216)

    def test_changed_counts_and_unaccounted_bytes_fail(self):
        raw=fixtures.triangle_tile()
        for offset in [4,6,16,18,20,22,24,26,30,36]:
            changed=bytearray(raw);struct.pack_into('<H',changed,offset,500)
            with self.subTest(offset=offset),self.assertRaises(ValueError):module.tile_sections(changed)
        for changed in [raw[:-1],raw+b'x',bytes(87)]:
            with self.assertRaises(ValueError):module.tile_sections(changed)

    def test_version_is_checked_before_pointer_assignment(self):
        raw=bytearray(fixtures.triangle_tile());struct.pack_into('<H',raw,0,8)
        with self.assertRaises(ValueError):module.tile_sections(raw)

    def test_all_direction_steps_have_distinct_exact_opposites(self):
        self.assertEqual(len(set(module.SIDE_STEPS.values())),8)
        for side,(x,y) in module.SIDE_STEPS.items():
            self.assertEqual(module.SIDE_STEPS[(side-4)&7],(-x,-y))


if __name__=='__main__':unittest.main()
