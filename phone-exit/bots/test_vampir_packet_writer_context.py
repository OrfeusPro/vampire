import hashlib
import unittest

from test_vampir_version_login_context import context, load, ROOT, SHA


def writer_context(name):
    value = context(name)
    path = ROOT/'ghidra/request-exports'/SHA/'run-6f00cf979ea3/details.json'
    value['exports'].append(dict(address=value['bindings']['bindings']['writer'], state='ready',
        artifacts=[dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())]))
    return value


class PacketWriterContextTests(unittest.TestCase):
    def test_whole_writers_success_and_every_failure_boundary(self):
        tool = load('verify-packet-writer-context')
        for name, fields in (('game-version', 13), ('game-login', 25)):
            with self.subTest(packet=name):
                report = tool.verify(writer_context(name), ROOT)
                self.assertEqual(len(report['fields']), fields)
                self.assertEqual(len(report['cases']), 4*(fields+1))
                self.assertEqual(report['binding']['table_slot'], 0x10)
                self.assertFalse(report['network_used'])
                self.assertFalse(report['profile_activated'])
                self.assertTrue(all(c['guards'] for c in report['cases']))

    def test_changed_field_order_and_archive_kind_are_rejected(self):
        tool = load('verify-packet-writer-context')
        value = writer_context('game-version')
        fields = value['contract']['writer_check']['fields']
        fields[2], fields[3] = fields[3], fields[2]
        with self.assertRaisesRegex(ValueError, 'field order'):
            tool.verify(value, ROOT)
        value = writer_context('game-login')
        value['contract']['writer_check']['fields'][-1][0] = 'u8'
        with self.assertRaisesRegex(ValueError, 'field order'):
            tool.verify(value, ROOT)

    def test_wrong_table_slot_and_helper_are_rejected(self):
        tool = load('verify-packet-writer-context')
        for key in ('writer', 'string-writer'):
            value = writer_context('game-version')
            value['bindings']['bindings'][key] = '0x1467ce030'
            with self.subTest(key=key), self.assertRaises(ValueError):
                tool.verify(value, ROOT)

    def test_corrupt_export_and_overlapping_fields_are_rejected(self):
        tool = load('verify-packet-writer-context')
        value = writer_context('game-login')
        value['exports'][-1]['artifacts'][0]['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'export SHA changed'):
            tool.verify(value, ROOT)
        value = writer_context('game-login')
        value['contract']['writer_check']['fields'][1][1] = 17
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            tool.verify(value, ROOT)


if __name__ == '__main__':
    unittest.main()
