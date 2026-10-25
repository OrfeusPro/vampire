"""Isolated native initialization must preserve unknown member bytes and stop at diagnostics."""
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('grid_init',HERE/'replay-grid-initialization.py')
grid=importlib.util.module_from_spec(spec);spec.loader.exec_module(grid)
SOURCE='C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'


def req(addresses):
    return dict(source=SOURCE,source_sha256=grid.SHA,question='ui-nktileview-property-schema',functions=[dict(address=hex(a)) for a in addresses])


class GridInitializationTests(unittest.TestCase):
    def test_real_native_bodies_preserve_incoming_values(self):
        result=grid.run(req([grid.LEAF]),req([grid.ROOTS[1]]),req([grid.ROOTS[0]]))
        self.assertEqual(len(result['cases']),40)
        self.assertEqual({r['terminal'] for r in result['cases']},{'returned','diagnostic_not_executed'})
        for row in result['cases']:
            self.assertEqual(row['preserved_member_bytes'],(bytes([row['pattern']])*16).hex())
        self.assertEqual(len(result['fragments']),2)

    def test_unscoped_leaf_request_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'Missing explicit'):
            grid.run(req([]),req([grid.ROOTS[1]]),req([grid.ROOTS[0]]))


if __name__=='__main__':unittest.main()
