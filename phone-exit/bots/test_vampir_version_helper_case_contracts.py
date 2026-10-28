"""Bounded report coverage rejects repeated rows and scope promotion."""
import copy
import importlib.util
import itertools
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'
spec = importlib.util.spec_from_file_location('version_helper_cases', HERE / 'version-helper-case-contracts.py')
TOOL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TOOL)


def sample(family):
    """Independent fixture matrices mirror the published verifier input dimensions."""
    poisons = (0, 85, 170, 255)
    if family == 'version-nm-device':
        cases = [dict(poison=p, profile=s, guards=True, repeated_cache_only=True)
            for p, s in itertools.product(poisons, ('cached', 'cached-one-char', 'cached-space', 'stored',
                'parse-failure', 'zero-guid', 'write-failure', 'read-failure-value', 'read-failure-empty'))]
        return dict(cases=cases, user_identity_read=False)
    if family == 'version-cpu':
        profiles = [('GenuineIntel', 'Fixture CPU'), ('AuthenticAMD', '  Fixture CPU  '),
            (' Vendor ', '\t\r\nSpaced CPU\t\r\n'), ('', ''), ('GenuineIntel', ' \t\r\n\v\f'),
            ('GenuineIntel', 'Unknown'), ('GenuineIntel', 'A|B|C'), ('GenuineIntel', 'A\0Hidden'), ('GenuineIntel', 'X' * 63)]
        return dict(cases=[dict(poison=p, vendor=a, brand=b, allocate_empty=e)
            for p, (a, b), e in itertools.product(poisons, profiles, (False, True))], host_identity_read=False)
    if family == 'version-windows':
        return dict(cases=[dict(poison=p, profile=s, values=list(v))
            for p, s, v in itertools.product(poisons,
                ('cached', 'cold', 'failed-version', 'other-thread', 'negative-equal', 'negative-cold'),
                ((10, 0, 26100, 1, 256), (6, 3, 9600, 255, 65535)))], host_identity_read=False)
    if family == 'version-combiner':
        pairs = [('', ''), ('', '_'), ('Windows', ''), ('Windows', '_'),
            ('Windows_', '10.0.26100.1.256.64bit'), ('контекст🙂', '_界'), ('a\0b', 'c\0d'), ('x' * 127, 'y' * 128)]
        return dict(cases=[dict(poison=p, function=f, left=a, right=b, spare=s, allocated_empty=e)
            for p, f, (a, b), s, e in itertools.product(poisons, ('first', 'second'), pairs, (0, 300), (False, True))], overflow_cases=2)
    if family == 'version-platform':
        rows = []
        for p in poisons:
            rows += [dict(kind='selector', poison=p, platform=s, truth=t)
                for s, t in itertools.product(('Android', 'IOS', 'Windows', 'Linux', '', 'windows'), (1, 128, 255))]
            rows += [dict(kind='empty_platform', poison=p)]
            rows += [dict(kind='store', poison=p, initial=a, resolved=b)
                for a, b in ((True, True), (False, True), (False, False))]
            rows += [dict(kind='lookup', poison=p, count=c, target=t)
                for c, t in ((0, 3), (-1, 3), (3, 1), (3, 3), (3, 4), (2, 3), (2, 18446744073709551615))]
        return dict(cases=rows)
    scenarios = [('windows-cached', True), ('windows-cold', True), ('windows-absent', False),
        ('windows-missing', True), ('windows-duplicate', True), ('windows-negative-count', True),
        ('android-cold', True), ('ios-cold', True), ('unknown-cold', True)] if family.endswith('-platform') else [(None, False), (None, True)]
    cases = []
    for p, (name, present), empty, enum, send in itertools.product(poisons, scenarios, (False, True), (0, 4294967295), (0, 1)):
        row = dict(poison=p, context_present=present, empty=empty, raw_enum=enum, send_return=send, guards=True, native_nm_calls=2)
        if name is not None:
            row['platform_scenario'] = name
        cases.append(row)
    level = {'version-prepare-nm': 1, 'version-prepare-system': 2,
             'version-prepare-combiner': 3, 'version-prepare-platform': 4}[family]
    return dict(cases=cases, **{flag: i < level for i, flag in enumerate(TOOL.NATIVE_FLAGS)})


class VersionCaseContractsTests(unittest.TestCase):
    def test_all_nine_reviewed_matrices_and_separate_overflow_count(self):
        self.assertEqual(tuple(TOOL.case_count(f) for f in TOOL.FAMILIES), (36, 72, 48, 256, 116, 64, 64, 64, 288))
        self.assertEqual(sum(TOOL.case_count(f) for f in TOOL.FAMILIES), 1008)
        for family in TOOL.FAMILIES:
            with self.subTest(family=family):
                TOOL.validate_report(family, sample(family))

    def test_missing_extra_and_duplicated_rows_rejected_for_every_family(self):
        for family in TOOL.FAMILIES:
            for change in ('missing', 'extra', 'duplicate'):
                with self.subTest(family=family, change=change):
                    report = sample(family)
                    if change == 'missing': report['cases'].pop()
                    elif change == 'extra': report['cases'].append(copy.deepcopy(report['cases'][0]))
                    else: report['cases'][-1] = copy.deepcopy(report['cases'][0])
                    with self.assertRaises(ValueError): TOOL.validate_report(family, report)

    def test_wrong_poison_and_missing_dimension_rejected_for_every_family(self):
        for family in TOOL.FAMILIES:
            for change in ('wrong', 'missing'):
                with self.subTest(family=family, change=change):
                    report = sample(family)
                    if change == 'wrong': report['cases'][0]['poison'] = 7
                    else: del report['cases'][0]['poison']
                    with self.assertRaises(ValueError): TOOL.validate_report(family, report)

    def test_bool_and_integer_dimensions_are_not_interchangeable(self):
        for family, field, replacement in (('version-cpu', 'allocate_empty', 0),
                ('version-combiner', 'allocated_empty', 0), ('version-prepare-nm', 'empty', 0),
                ('version-prepare-platform', 'context_present', 1), ('version-nm-device', 'poison', False)):
            with self.subTest(family=family):
                report = sample(family);report['cases'][0][field] = replacement
                with self.assertRaises(ValueError): TOOL.validate_report(family, report)

    def test_platform_kinds_and_specific_dimensions_cannot_substitute(self):
        for kind, field, value in (('selector', 'truth', 0), ('empty_platform', 'kind', 'empty'),
                ('store', 'initial', 1), ('lookup', 'target', 5)):
            with self.subTest(kind=kind):
                report = sample('version-platform')
                next(r for r in report['cases'] if r['kind'] == kind)[field] = value
                with self.assertRaises(ValueError): TOOL.validate_report('version-platform', report)

    def test_integration_present_state_must_match_platform_scenario(self):
        report = sample('version-prepare-platform')
        row = next(r for r in report['cases'] if r['platform_scenario'] == 'windows-absent')
        row['context_present'] = True
        with self.assertRaises(ValueError): TOOL.validate_report('version-prepare-platform', report)

    def test_cumulative_native_flags_require_exact_booleans(self):
        for family in TOOL.FAMILIES[5:]:
            for flag in TOOL.NATIVE_FLAGS:
                with self.subTest(family=family, flag=flag):
                    report = sample(family);report[flag] = not report[flag]
                    with self.assertRaises(ValueError): TOOL.validate_report(family, report)
                    report = sample(family);report[flag] = int(report[flag])
                    with self.assertRaises(ValueError): TOOL.validate_report(family, report)

    def test_standalone_cannot_claim_integrated_preparation(self):
        for family in TOOL.FAMILIES[:5]:
            report = sample(family);report['native_nm_used'] = True
            with self.assertRaises(ValueError): TOOL.validate_report(family, report)

    def test_nm_guards_cache_repetition_and_identity_read_are_required(self):
        for key in ('guards', 'repeated_cache_only'):
            report = sample('version-nm-device');report['cases'][0][key] = False
            with self.assertRaises(ValueError): TOOL.validate_report('version-nm-device', report)
        for value in (True, None, 0):
            report = sample('version-nm-device');report['user_identity_read'] = value
            with self.assertRaises(ValueError): TOOL.validate_report('version-nm-device', report)

    def test_system_host_identity_is_excluded(self):
        for family in ('version-cpu', 'version-windows'):
            for value in (True, None, 0):
                report = sample(family);report['host_identity_read'] = value
                with self.assertRaises(ValueError): TOOL.validate_report(family, report)

    def test_integration_guards_and_nm_execution_required(self):
        for family in TOOL.FAMILIES[5:]:
            for key, value in (('guards', False), ('native_nm_calls', 0), ('native_nm_calls', 2.0)):
                report = sample(family);report['cases'][0][key] = value
                with self.assertRaises(ValueError): TOOL.validate_report(family, report)

    def test_overflow_proof_is_separate_and_exact(self):
        for value in (None, 0, 1, 3, 2.0):
            report = sample('version-combiner');report['overflow_cases'] = value
            with self.assertRaises(ValueError): TOOL.validate_report('version-combiner', report)

    def test_rows_must_be_objects_and_matrix_values_json_dimensions(self):
        for value in (None, [], 'row'):
            report = sample('version-cpu');report['cases'][0] = value
            with self.assertRaises(ValueError): TOOL.validate_report('version-cpu', report)
        report = sample('version-cpu');report['cases'][0]['poison'] = float('nan')
        with self.assertRaises(ValueError): TOOL.validate_report('version-cpu', report)

    def test_only_registered_family_and_fixed_verifier_module(self):
        self.assertEqual(TOOL.verifier('version-prepare-platform'), 'verify-version-prepare-context')
        self.assertEqual(TOOL.verifier('version-nm-device'), 'verify-version-nm-device-context')
        for name in ('version-prepare', 'version-sdk', '../arbitrary', None, []):
            with self.assertRaises(ValueError): TOOL.case_count(name)
            with self.assertRaises(ValueError): TOOL.verifier(name)
            with self.assertRaises(ValueError): TOOL.validate_report(name, {})


if __name__ == '__main__':
    unittest.main()
