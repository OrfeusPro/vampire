"""Grid candidate parsing preserves unknown omissions and rejects opaque bytes."""
import importlib.util
from pathlib import Path
import unittest

p=Path(__file__).parent/'resource-tools/vampir/decode-grid-slots.py'
s=importlib.util.spec_from_file_location('grid_decoder',p)
grid=importlib.util.module_from_spec(s);s.loader.exec_module(grid)
CHARACTER=bytes.fromhex('000402020102020500090000a0400000a0400000a0400000a040010100000001000000b30000004200000000000000')
ARENA=bytes.fromhex('0302010203050700000004000000b30000003e00000000000000')


class GridTests(unittest.TestCase):
    def test_omitted_positions_are_not_silently_zero(self):
        value=grid.decode(CHARACTER)
        self.assertEqual(value['explicit_properties']['Parent'],179)
        self.assertEqual(value['explicit_properties']['Content'],66)
        self.assertEqual(value['explicit_properties']['RowSpan'],1)
        self.assertIn('Row',value['omitted_properties'])
        self.assertNotIn('Row',value['explicit_properties'])
        self.assertIn('Column',value['omitted_properties'])

    def test_explicit_row_column_do_not_invent_spans(self):
        value=grid.decode(ARENA)
        self.assertEqual(value['explicit_properties'],dict(Row=7,Column=4,Parent=179,Content=62))
        self.assertIn('RowSpan',value['omitted_properties'])
        self.assertIn('ColumnSpan',value['omitted_properties'])

    def test_truncation_extra_bytes_and_nonzero_suffix_are_rejected(self):
        for raw in [CHARACTER[:-1],CHARACTER+b'\0',CHARACTER[:-1]+b'\1',ARENA[:-4]]:
            with self.subTest(raw=raw.hex()),self.assertRaises((ValueError,grid.canvas.struct.error)):
                grid.decode(raw)


if __name__=='__main__':unittest.main()
