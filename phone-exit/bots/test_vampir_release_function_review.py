import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('function_review', Path(__file__).parent / 'resource-tools/vampir/build-release-function-review.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReviewTests(unittest.TestCase):
    def test_cross_pass_conflicts_and_missing_functions_do_not_become_verified(self):
        historical = dict(source_sha256='old', functions=[dict(address=a, name=a) for a in ['a', 'b', 'c', 'd']])
        def match(old, new):
            return dict(old_address=old, new_address=new)
        result = MODULE.review_functions(historical, dict(old_source_sha256='old', new_source_sha256='new',
            analysis_timed_out=True, passes=[dict(correlator='bytes', matches=[match('a', 'x'), match('b', 'y'), match('d', 'z')]),
                                           dict(correlator='instructions', matches=[match('a', 'y'), match('d', 'z'), match('extra', 'other')])]))
        self.assertEqual(result['counts'], dict(conflicting_candidates=2, not_matched=1, candidate_requires_verification=1))
        self.assertTrue(result['analysis_timed_out'])
        self.assertFalse(result['roles_transferred'])
        self.assertEqual(result['compatibility'], 'not_established')
        self.assertEqual(result['functions'][1]['candidates'][0]['competing_old_addresses'], ['a'])
        self.assertEqual(len(result['matches_outside_historical_export']), 1)
        self.assertEqual(result['functions'][3]['candidates'][0]['correlators'], ['bytes', 'instructions'])

    def test_wrong_source_and_duplicate_historical_addresses_are_rejected(self):
        correlation = dict(old_source_sha256='old', new_source_sha256='new', analysis_timed_out=False, passes=[])
        with self.assertRaisesRegex(ValueError, 'source mismatch'):
            MODULE.review_functions(dict(source_sha256='wrong', functions=[]), correlation)
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            MODULE.review_functions(dict(source_sha256='old', functions=[dict(address='a'), dict(address='A')]), correlation)


if __name__ == '__main__':
    unittest.main()
