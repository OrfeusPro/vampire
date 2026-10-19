"""Join indexed World CSV paths with native record field and virtual getter."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE=Path(__file__).resolve().parent


class WorldStateLabelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=HERE/'resource-tools/vampir/replay-world-state-label.py'
        spec=importlib.util.spec_from_file_location('world_label_test',path)
        cls.tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.tool)
        cls.report=json.loads((cls.tool.native.ROOT/'code-clues/world-state-label-replay.json').read_text('utf-8'))

    def test_native_report_and_field_bindings_reproduce(self):
        self.assertEqual(self.tool.build(),self.report)
        self.assertTrue(self.report['source_row2_label_verified'])
        self.assertFalse(self.report['live_registry_population_verified'])
        self.assertFalse(self.report['network_ready'])
        raw=Path(self.report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),self.report['sha256'])
        for key in ('getter','table','column_literal'):
            row=self.report[key];data=bytes.fromhex(row['bytes'])
            self.assertEqual(raw[row['file_offset']:row['file_offset']+len(data)],data)
        table=bytes.fromhex(self.report['table']['bytes'])
        self.assertEqual(struct.unpack_from('<Q',table,0x20)[0],0x141482e60)
        self.assertEqual(self.report['getter']['bytes'],'488d4148c3')
        self.assertEqual(bytes.fromhex(self.report['column_literal']['bytes']),b'LevelPath\0')

    def test_base_and_patch_indexed_rows_feed_native_field_and_getter(self):
        self.assertEqual(len(self.report['tables']),2)
        for table in self.report['tables']:
            self.assertTrue(table['current_archive_matches_extraction'])
            self.assertEqual(len(table['current_archive_sha256']),64)
            index=Path(table['index'])
            self.assertEqual(hashlib.sha256(index.read_bytes()).hexdigest(),table['index_sha256'])
            csvpath=index.parent/table['extraction']['file']
            self.assertEqual(hashlib.sha256(csvpath.read_bytes()).hexdigest(),table['extraction']['sha256'])
            rows=table['rows']
            self.assertEqual([r['Id'] for r in rows],['1','2'])
            self.assertEqual(table['header'][3],'LevelPath')
            self.assertEqual(table['execution']['cases'],[
                dict(key=1,label=rows[0]['LevelPath']),dict(key=2,label=rows[1]['LevelPath']),dict(key=3,label='')])
            self.assertEqual(rows[1]['LevelPath'],'Lobby/CharacterSelect/CharacterSelect_02')
            self.assertEqual([r['vtable'] for r in table['execution']['templates']],[0x1499d28a8]*2)
            if table['extraction']['source']['path'].endswith('pakchunk1-Windows.pak'):
                self.assertEqual(table['index_sha256'],'430a1b516df976ee6b1accfc93c7386f9ac95c66480ce0cf5c56888acfd03ea8')
                self.assertEqual(table['current_archive_sha256'],'03a229f23a86ac32e287dd5b7095a962ad8f342f1b5ac0addeb678616cf4f9e1')

    def test_assignment_range_and_insertion_constructor_source_are_preserved(self):
        rows={r['address']:r for f in self.report['fragments'] for r in f['instructions']}
        self.assertEqual(rows[0x145c628c1]['operands'],'rdi, [rbx + 0x48]')
        self.assertEqual(rows[0x145c62901]['direct_target'],0x1487a2e19)
        self.assertTrue(any(r.get('direct_target')==0x145c5c780 for r in rows.values()))


if __name__=='__main__':unittest.main()
