import copy
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('entry_buttons',
    Path(__file__).parent / 'resource-tools/vampir/build-entry-button-links.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def instruction(mnemonic, operands='', target=None):
    return dict(mnemonic=mnemonic, operands=operands, call=mnemonic == 'call', direct_target=target)


class EntryButtonEvidence(unittest.TestCase):
    def lookup(self):
        return [instruction('lea', 'rdx, [rip + 0x123]'),
                instruction('call', target=0x1415a8e80), instruction('mov', 'r8, r14'),
                instruction('call', target=0x144a72480), instruction('mov', 'rcx, rsi'),
                instruction('mov', 'qword ptr [rdi + 0xaa8], rax')]

    def test_lookup_preserves_named_result_store(self):
        binding = module.find_binding(self.lookup(), 0, 0x144a72480)
        self.assertEqual(binding['field_offset'], 0xaa8)

    def test_changed_getter_owner_or_store_rejected(self):
        rows = self.lookup()
        for index, replacement in [(1, instruction('call', target=1)),
                (2, instruction('mov', 'r8, r15')), (3, instruction('call', target=2)),
                (4, instruction('mov', 'rax, rsi')), (5, instruction('mov', 'qword ptr [rdi + 0xaa8], rbx'))]:
            changed = copy.deepcopy(rows)
            changed[index] = replacement
            with self.assertRaises(ValueError):
                module.find_binding(changed, 0, 0x144a72480)

    def test_field_alias_and_branch_polarity(self):
        rows = [instruction('cmp', 'rsi, qword ptr [rbx + 0xa8]'), instruction('jne', target=0x123)]
        result = module.match_comparisons(rows, 0xa00, 0xaa8)
        self.assertEqual(result[0]['matching_path'], 'fallthrough')
        self.assertEqual(module.match_comparisons(rows, 0xa00, 0xab0), [])
        rows[1] = instruction('je', target=0x123)
        self.assertEqual(module.match_comparisons(rows, 0xa00, 0xaa8)[0]['matching_path'], 'taken')

    def test_unknown_comparison_branch_rejected(self):
        rows = [instruction('cmp', 'rsi, qword ptr [rbx + 0xa8]'), instruction('ja', target=0x123)]
        with self.assertRaises(ValueError):
            module.match_comparisons(rows, 0xa00, 0xaa8)


if __name__ == '__main__':
    unittest.main()
