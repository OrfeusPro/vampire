"""Bounded raw-directory components and source-defined mount joining."""
import copy
import struct
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load


PATHS = load('resource-directory-paths-v2')
FORMAT = load('resource-directory-format-v1')
CORE = load('recover-pak-game-config')


def string(value, *, wide=False):
    if wide:
        raw = (value + '\0').encode('utf-16le')
        return struct.pack('<i', -len(raw)//2) + raw
    raw = value.encode('utf-8') + b'\0'
    return struct.pack('<i', len(raw)) + raw


def directory(groups, *, wide=False, padding=b''):
    raw = struct.pack('<I', len(groups))
    for name, entries in groups:
        raw += string(name, wide=wide) + struct.pack('<I', len(entries))
        for filename, offset in entries:
            raw += string(filename, wide=wide) + struct.pack('<i', offset)
    return raw + padding


class RawDirectoryPartsTests(unittest.TestCase):
    def test_components_preserve_exact_legacy_fields_and_encoded_offsets(self):
        raw = directory([('/', [('A.uasset', 0), ('A.uexp', 12)]),
            ('CSV/', [('Quest.csv', 28)]), ('', [('EmptyDir.csv', 50)])], padding=b'\0'*10)
        actual = PATHS.directory_parts(raw, 4, CORE.Cursor)
        legacy = copy.deepcopy(actual)
        for row in legacy['entries']:
            row.pop('directory')
            row.pop('name')
        self.assertEqual(legacy, CORE.parse_directory(raw, 4))
        self.assertEqual(actual['entries'][0], dict(path='/A.uasset', encoded_entry_offset=0,
            directory='/', name='A.uasset'))
        self.assertEqual(actual['entries'][-1]['directory'], '')
        self.assertEqual(actual['trailing_bytes'], 10)

    def test_wide_component_strings_preserve_unicode_and_legacy_equivalence(self):
        raw = directory([('/Текстуры/', [('Карта.uasset', 64)])], wide=True)
        actual = PATHS.directory_parts(raw, 1, CORE.Cursor)
        row = actual['entries'][0]
        self.assertEqual((row['directory'], row['name']), ('/Текстуры/', 'Карта.uasset'))
        self.assertEqual(CORE.parse_directory(raw, 1)['entries'][0],
            {key: row[key] for key in ('path', 'encoded_entry_offset')})

    def test_duplicate_legacy_path_is_rejected_even_with_different_component_splits(self):
        for groups in ([('/', [('A.csv', 0), ('A.csv', 12)])],
                [('/', [('A.csv', 0)]), ('', [('/A.csv', 12)])]):
            with self.subTest(groups=groups), self.assertRaisesRegex(ValueError, 'Duplicate'):
                PATHS.directory_parts(directory(groups), 2, CORE.Cursor)

    def test_negative_encoded_offsets_are_rejected(self):
        for offset in (-1, -(2**31)):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                PATHS.directory_parts(directory([('/', [('A.csv', offset)])]), 1, CORE.Cursor)

    def test_truncated_strings_counts_and_offsets_are_rejected(self):
        raw = directory([('/Sub/', [('A.csv', 16)])])
        for size in range(len(raw)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                PATHS.directory_parts(raw[:size], 1, CORE.Cursor)

    def test_count_mismatch_invalid_expected_count_and_excess_trailer_are_rejected(self):
        raw = directory([('/', [('A.csv', 0)])])
        for expected in (-1, 0, 2, True, '1', 100001):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                PATHS.directory_parts(raw, expected, CORE.Cursor)
        with self.assertRaisesRegex(ValueError, 'trailer'):
            PATHS.directory_parts(raw + b'\0'*16, 1, CORE.Cursor)
        with self.assertRaisesRegex(ValueError, 'count'):
            PATHS.directory_parts(struct.pack('<I', 10001), 0, CORE.Cursor)

    def test_buffer_budget_and_empty_directory_are_explicit(self):
        raw = directory([])
        self.assertEqual(PATHS.directory_parts(raw, 0, CORE.Cursor),
            dict(directory_count=0, file_count=0, trailing_bytes=0, entries=[]))
        with patch.object(PATHS, 'LIMIT', 3), self.assertRaisesRegex(ValueError, 'input'):
            PATHS.directory_parts(raw, 0, CORE.Cursor)


class DirectoryMountJoinTests(unittest.TestCase):
    def test_root_slash_directory_joins_under_mount_instead_of_becoming_absolute(self):
        self.assertEqual(PATHS.canonical_path('../../../ProjectRED/Content/RED/UI/', '/',
            'IMG_Map.uasset', FORMAT), 'ProjectRED/Content/RED/UI/IMG_Map.uasset')
        self.assertEqual(PATHS.canonical_path('../../../', '/', 'Engine.ini', FORMAT), 'Engine.ini')

    def test_one_leading_directory_slash_and_empty_directory_have_exact_join_semantics(self):
        for directory_part in ('/Sub/', 'Sub/'):
            with self.subTest(directory=directory_part):
                self.assertEqual(PATHS.canonical_path('../../../ProjectRED/Content/', directory_part,
                    'A.csv', FORMAT), 'ProjectRED/Content/Sub/A.csv')
        self.assertEqual(PATHS.canonical_path('../../../ProjectRED/Content/', '', 'A.csv', FORMAT),
            'ProjectRED/Content/A.csv')

    def test_filename_leading_slash_is_rejected_before_concatenation(self):
        for part in ('/', '', 'Sub', 'Sub/'):
            with self.subTest(directory=part), self.assertRaises(ValueError):
                PATHS.canonical_path('../../../ProjectRED/', part, '/absolute.csv', FORMAT)

    def test_mount_without_trailing_separator_and_platform_paths_are_unsupported(self):
        for mount in ('../../../ProjectRED', '', '/absolute/', 'C:/Data/', '\\server\\share/'):
            with self.subTest(mount=mount), self.assertRaises(ValueError):
                PATHS.canonical_path(mount, '/Sub/', 'A.csv', FORMAT)

    def test_only_one_boundary_slash_is_trimmed_and_remaining_ambiguity_is_rejected(self):
        for part in ('//', '//Sub/', '/Sub//'):
            with self.subTest(directory=part), self.assertRaises(ValueError):
                PATHS.canonical_path('../../../ProjectRED/', part, 'A.csv', FORMAT)

    def test_parent_dot_backslash_control_and_empty_names_remain_rejected(self):
        for part, name in (('/../', 'A.csv'), ('/./', 'A.csv'), ('Sub/', '../A.csv'),
                ('Sub\\', 'A.csv'), ('/', 'A\\B.csv'), ('/', ''), ('/', 'A\0B.csv'),
                ('/', 'A:B.csv'), ('/', './A.csv')):
            with self.subTest(directory=part, name=name), self.assertRaises(ValueError):
                PATHS.canonical_path('../../../ProjectRED/', part, name, FORMAT)

    def test_normalized_aliases_are_visible_for_the_callers_collision_guard(self):
        first = PATHS.canonical_path('../../../ProjectRED/', '/', 'A.csv', FORMAT)
        second = PATHS.canonical_path('../../../ProjectRED/', '', 'A.csv', FORMAT)
        self.assertEqual(first, second)
        self.assertEqual(len({first, second}), 1)


if __name__ == '__main__':
    unittest.main()
