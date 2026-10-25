"""Coverage must expose missing slot classes and reject stale or repeated provenance."""
import copy
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).parent/'resource-tools/vampir/audit-ui-slot-coverage.py'
spec = importlib.util.spec_from_file_location('slot_coverage', path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class SlotCoverageTests(unittest.TestCase):
    def setUp(self):
        self.exports = [dict(index=i, name='slot'+str(i), type=kind, offset=i*20, size=18, sha256=str(i)*64)
                        for i,kind in [(1,'CanvasPanelSlot'),(2,'ButtonSlot'),(3,'GridSlot')]]
        def proof(i):
            e=self.exports[i-1]
            return dict(provenance=dict(slot_export=i, slot_type=e['type'], offset=e['offset'], sha256=e['sha256']))
        self.catalog=dict(decoded_slots=[proof(1)],excluded_slots=[proof(2)])

    def test_missing_class_and_rejected_slots_remain_distinct(self):
        rows=audit.coverage(self.exports,self.catalog)
        self.assertEqual([r['status'] for r in rows],['decoded','rejected','unaccounted'])
        self.assertEqual(rows[2]['kind'],'GridSlot')
        self.assertNotIn('row',rows[2])

    def test_stale_provenance_is_rejected(self):
        self.catalog['decoded_slots'][0]['provenance']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'mismatch'):audit.coverage(self.exports,self.catalog)

    def test_duplicate_accounting_is_rejected(self):
        self.catalog['excluded_slots'].append(copy.deepcopy(self.catalog['decoded_slots'][0]))
        with self.assertRaisesRegex(ValueError,'duplicate'):audit.coverage(self.exports,self.catalog)


if __name__=='__main__':unittest.main()
