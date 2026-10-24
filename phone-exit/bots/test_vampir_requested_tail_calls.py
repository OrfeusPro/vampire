import unittest
from test_vampir_update_contracts import load


class RequestedTailCallsTests(unittest.TestCase):
    def row(self, **updates):
        result = dict(address=0x100, mnemonic='jmp', branch=True, call=False, direct_target=0x200, bytes='e9fb000000')
        result.update(updates)
        return result

    def test_only_explicit_external_e9_tail_is_modelled(self):
        tool = load('collect-requested-functions')
        rows = [self.row(), self.row(address=0x110, mnemonic='jne', bytes='0f85ea000000'),
                self.row(address=0x120, direct_target=0x300), self.row(address=0x130, bytes='ffe0')]
        self.assertEqual(tool.reviewed_tail_calls(rows, {0x100, 0x200}),
                         [dict(address='0x100', target='0x200', bytes='e9fb000000')])
        self.assertEqual(tool.reviewed_tail_calls(rows, {0x100}), [])

    def test_local_branch_is_not_reclassified(self):
        tool = load('collect-requested-functions')
        self.assertEqual(tool.reviewed_tail_calls([self.row(), self.row(address=0x200)], {0x200}), [])


if __name__ == '__main__':
    unittest.main()
