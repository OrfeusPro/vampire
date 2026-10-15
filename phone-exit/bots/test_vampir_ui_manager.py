import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('ui_manager_code',
    Path(__file__).parent / 'resource-tools/vampir/build-ui-manager-code.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class UIManagerAnchors(unittest.TestCase):
    def test_exact_instruction_preserved(self):
        row = dict(mnemonic='call', operands='qword ptr [rax + 0x520]', bytes='ff9020050000')
        self.assertIs(module.verify_anchor({123: row}, 123, row['mnemonic'], row['operands']), row)

    def test_missing_changed_call_or_offset_rejected(self):
        for rows in [{}, {123: dict(mnemonic='mov', operands='qword ptr [rax + 0x520]')},
                     {123: dict(mnemonic='call', operands='qword ptr [rax + 0x528]')}]:
            with self.assertRaises(ValueError):
                module.verify_anchor(rows, 123, 'call', 'qword ptr [rax + 0x520]')


if __name__ == '__main__':
    unittest.main()
