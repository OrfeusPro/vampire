"""Read-only native stat record/application replay; no game IO."""
import importlib.util
from pathlib import Path
import unittest


class NativeStatValuesTests(unittest.TestCase):
    def test_current_reader_prefixes_and_signed_application_order(self):
        path=Path(__file__).parent/'resource-tools/vampir/replay-stat-values-11316.py'
        spec=importlib.util.spec_from_file_location('stat_values_native_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        result=module.verify()
        self.assertEqual(result['cases'],130)
        self.assertTrue(Path(result['report']).is_file())


if __name__=='__main__':unittest.main()
