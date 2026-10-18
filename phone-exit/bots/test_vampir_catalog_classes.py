import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('catalog_classes', Path(__file__).parent / 'resource-tools/vampir/build-catalog-classes.py')
classes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(classes)


class CatalogClassesTest(unittest.TestCase):
    def test_unknown_does_not_mean_all_and_lists_use_exact_tokens(self):
        known = {'DarkMage', 'Reaper'}
        self.assertEqual(classes.skill_classes('', known)['status'], 'unknown')
        self.assertEqual(classes.skill_classes('All', known)['status'], 'all')
        self.assertEqual(classes.skill_classes('DarkMage, Reaper', known)['keys'], ['DarkMage', 'Reaper'])
        self.assertEqual(classes.skill_classes('DarkMageExtra', known)['status'], 'unknown')
        self.assertEqual(classes.skill_classes('DarkMage,Alien', known)['status'], 'unknown')

    def test_book_restriction_is_kept_when_target_skill_says_all(self):
        result = classes.book_classes('1', classes.skill_classes('All', {'DarkMage'}), {'1': 'DarkMage'})
        self.assertEqual(result, {'status': 'specified', 'keys': ['DarkMage']})
        self.assertEqual(classes.book_classes('', classes.skill_classes('All', set()), {})['status'], 'all')

    def test_missing_or_conflicting_fields_are_not_compatible_by_guess(self):
        known = {'DarkMage', 'Reaper'}
        self.assertEqual(classes.book_classes('999', classes.skill_classes('All', known), {})['status'], 'unknown')
        self.assertEqual(classes.book_classes('1', classes.skill_classes('Reaper', known), {'1': 'DarkMage'})['status'], 'conflict')
        self.assertEqual(classes.book_classes('', classes.skill_classes('', known), {})['status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
