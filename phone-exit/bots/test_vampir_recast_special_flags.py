import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('special_flags',Path(__file__).parent/'resource-tools/vampir/recast-special-flags.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class SpecialFlagTests(unittest.TestCase):
    def test_bit7_bypasses_direction_gate_for_both_endpoint_directions(self):
        for side in [-1,*range(8)]:
            for same in [False,True]:
                for value in module.metadata(0xc0,side,same).values():
                    self.assertTrue(module.direction_gate(value,False))
                    self.assertTrue(module.direction_gate(value,True))

    def test_without_bit7_each_endpoint_has_opposed_direction_metadata(self):
        packed=module.metadata(0x40,-1,True)
        for endpoint in ['start','end']:
            outgoing=packed[endpoint+'_to_surface'];incoming=packed['surface_to_'+endpoint]
            self.assertNotEqual(module.direction_gate(outgoing,False),module.direction_gate(incoming,False))
            for value in [outgoing,incoming]:
                self.assertNotEqual(module.direction_gate(value,False),module.direction_gate(value,True))

    def test_same_tile_sentinel_bit_is_removed_only_for_cross_tile_end(self):
        same=module.metadata(0xc0,-1,True);cross=module.metadata(0xc0,-1,False)
        for field in ['end_to_surface','surface_to_end']:
            self.assertEqual(same[field]^cross[field],0x80)
        self.assertEqual(same['start_to_surface'],cross['start_to_surface'])

    def test_invalid_inputs_do_not_wrap_to_valid_flags(self):
        for flags,side in [(-1,0),(256,0),(0,8),(0,-2)]:
            with self.assertRaises(ValueError):module.metadata(flags,side,True)
        for value in [-1,256]:
            with self.assertRaises(ValueError):module.direction_gate(value,False)

if __name__=='__main__':unittest.main()
