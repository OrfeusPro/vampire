import importlib.util
from pathlib import Path
import unittest


class ReleaseCreationClassesTests(unittest.TestCase):
    def test_current_archive_csv_and_native_lookup_agree(self):
        path = Path(__file__).parent / 'resource-tools/vampir/verify-release-creation-classes.py'
        spec = importlib.util.spec_from_file_location('creation_class_data_check', path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        _, report = tool.run()
        self.assertEqual(report['source_sha256'], tool.SHA)
        self.assertEqual(report['class_csv_sha256'], tool.CLASS_SHA)
        self.assertEqual(report['native_cases'], 54)
        self.assertFalse(report['network_used'])
        gunner = next(row for row in report['classes'] if row['key'] == 'Gunner')
        self.assertEqual(gunner, dict(key='Gunner', id=3, type=3, default_gender=1))
        self.assertEqual(len(report['classes']), 5)


if __name__ == '__main__': unittest.main()
