import runpy
import unittest
from pathlib import Path


present = runpy.run_path(str(Path(__file__).parent / 'resource-tools/vampir/build-skill-catalog-meta.py'))['book_presentations']


class BookPresentationTests(unittest.TestCase):
    def setUp(self):
        self.rows = {'11': {'Id': '11', 'Img': 'ICON', 'ImgBg': ''}}
        self.meta = {'11': {'kind': 'active', 'kind_evidence': [{'marker': '[Active]'}],
                            'provenance': {'entry': 1505, 'csv_record': 8}}}
        self.book = {'skill_id': '11', 'relation_verified': True,
                     'record': {'provenance': {'entry': 1, 'csv_record': 2}},
                     'skill_names_en': [{'Id': '11', 'Name': 'Whirlpool'}, {'Id': '99', 'Name': 'Wrong target'}]}

    def test_verified_target_keeps_exact_name_icon_and_origins(self):
        icon = {'key': 'ICON', 'status': 'exact_unique_name', 'images': [{'file': 'icon.png', 'sha256': 'hash'}]}
        result = present({'book': self.book}, self.rows, self.meta, {'ICON': icon})['book']
        self.assertEqual(result['target']['id'], '11')
        self.assertEqual([n['text'] for n in result['target']['display_names']], ['Whirlpool'])
        self.assertEqual(result['target']['images']['Img'], icon)
        self.assertEqual(result['target']['provenance']['csv_record'], 8)
        self.assertEqual(result['kind'], 'active')
        self.assertFalse(result['acquisition_verified'])

    def test_candidate_matching_an_existing_skill_does_not_promote_a_link(self):
        book = dict(self.book, relation_verified=False, candidate_skill=self.rows['11'])
        result = present({'book': book}, self.rows, self.meta, {})['book']
        self.assertIsNone(result['target'])
        self.assertEqual(result['kind'], 'unknown')

    def test_verified_missing_skill_stays_unknown(self):
        result = present({'book': dict(self.book, skill_id='99')}, self.rows, self.meta, {})['book']
        self.assertFalse(result['relation_verified'])
        self.assertIsNone(result['target'])

    def test_missing_image_or_type_does_not_invalidate_verified_target(self):
        self.meta['11']['kind'] = 'unknown'
        self.meta['11']['kind_evidence'] = []
        result = present({'book': self.book}, self.rows, self.meta, {})['book']
        self.assertEqual(result['target']['id'], '11')
        self.assertEqual(result['kind'], 'unknown')
        self.assertEqual(result['target']['images']['Img']['images'], [])


if __name__ == '__main__':
    unittest.main()
