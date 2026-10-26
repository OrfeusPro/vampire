import unittest
from types import SimpleNamespace
from unittest.mock import Mock
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

    def test_partial_linear_fragment_never_supplies_tail_models(self):
        tool=load('collect-requested-functions')
        native=SimpleNamespace(decode_ranges=Mock(side_effect=ValueError('Fragment not fully decoded')))
        tails,scan=tool.scan_tail_calls(native,object(),(1,2,3),{0x200})
        self.assertEqual(tails,[]);self.assertEqual(scan['state'],'deferred_to_ghidra')
        self.assertFalse(scan['tail_models_applied'])
        native.decode_ranges=Mock(side_effect=ValueError('Invalid unwind chain'))
        with self.assertRaisesRegex(ValueError,'Invalid unwind chain'):tool.scan_tail_calls(native,object(),(1,2,3),{0x200})

    def test_complete_scan_preserves_only_reviewed_explicit_tails(self):
        tool=load('collect-requested-functions')
        native=SimpleNamespace(decode_ranges=lambda image,roots:[dict(instructions=[self.row()])])
        tails,scan=tool.scan_tail_calls(native,object(),(1,2,3),{0x200})
        self.assertEqual(len(tails),1);self.assertEqual(scan,dict(state='complete'))


if __name__ == '__main__':
    unittest.main()
