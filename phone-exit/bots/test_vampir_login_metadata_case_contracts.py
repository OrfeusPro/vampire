"""Metadata matrix coverage, ordered schema and bounded execution claims."""
import copy
import hashlib
import itertools
from pathlib import Path
import unittest

from test_vampir_update_contracts import load

TOOL = load('login-metadata-case-contracts')
METADATA = load('verify-login-metadata-context')
PREPARE = load('verify-login-prepare-context')


def sample(family):
    if family == 'login-metadata':
        cases = []
        for b, p, d, m, poison in itertools.product(
                ('none', 'invalid', 'ready', 'shared', 'weak-shared', 'unmanaged'),
                ('full', 'empty', 'omit-gates', 'omit-nid', 'omit-channel', 'unicode-quote'),
                (False, True), (False, True), (85, 170)):
            active = b not in ('none', 'invalid');mapping = dict(METADATA.FIELD_MAP) if active else {}
            if active:
                if p in ('empty', 'omit-gates'):
                    for key in ('I_GameCode', 'I_NMBuildCode', 'I_NMNID', 'I_NMNIDChannelType'): mapping.pop(key)
                if p == 'empty': mapping.pop('I_NMCharacterID')
                if p == 'omit-nid': mapping.pop('I_NMNID');mapping.pop('I_NMNIDChannelType')
                mapping.update(I_NMDeviceKey=80, I_PlatformADID=112, I_NMIDFV=None,
                    I_NMAppSetID=None, I_NMInstallPackageName=None, I_NMAppSetIDScope=None)
            calls = dict(collector=1, loader=1, copy=1, selector=27, writer=1) if active else dict(collector=1, loader=1, move=1)
            cases.append(dict(backend=b, pattern=p, optional_device=d, marketing=m, poison=poison,
                guards=True, field_map=mapping, mapping={key: '' for key in mapping}, native_calls=calls))
        return dict(cases=cases, field_map=dict(METADATA.FIELD_MAP))
    metadata_cases = [('none', 'full', False), ('invalid', 'full', True), ('ready', 'full', False),
        ('ready', 'empty', True), ('ready', 'omit-gates', True), ('shared', 'unicode-quote', True),
        ('weak-shared', 'omit-nid', False), ('unmanaged', 'omit-channel', True)]
    cases = []
    for s, empty, send, m in itertools.product(PREPARE.SCENARIOS, (False, True), (0, 1), metadata_cases):
        aux = s[2] and s[3] and bool(s[4] & 2);active = m[0] not in ('none', 'invalid')
        calls = (dict(collector=1, loader=1, copy=1, selector=27, writer=1) if active else dict(collector=1, loader=1, move=1)) if aux else {}
        cases.append(dict(scenario=s[0], selector=3, empty=empty, send_return=send, poison=85,
            cache_case='warm', metadata_case=list(m), guards=True, metadata_calls=calls))
    return dict(cases=cases, native_sdk_used=True, native_metadata_used=True,
        metadata_fields=[dict(key=k) for k in TOOL.COLLECTOR_ORDER])


class LoginMetadataCaseContractsTests(unittest.TestCase):
    def test_registered_families_and_exact_counts(self):
        self.assertEqual(TOOL.FAMILIES, ('login-metadata', 'login-prepare-metadata'))
        self.assertEqual([TOOL.case_count(f) for f in TOOL.FAMILIES], [288, 448])
        for family in TOOL.FAMILIES: TOOL.validate_report(family, sample(family))

    def test_fixed_verifiers_and_only_reviewed_family_names(self):
        self.assertEqual(TOOL.verifier('login-metadata'), 'verify-login-metadata-context')
        self.assertEqual(TOOL.verifier('login-prepare-metadata'), 'verify-login-prepare-context')
        for name in ('login-sdk', '../custom', None, []):
            with self.assertRaises(ValueError): TOOL.case_count(name)
            with self.assertRaises(ValueError): TOOL.verifier(name)
            with self.assertRaises(ValueError): TOOL.validate_report(name, {})

    def test_missing_extra_and_duplicate_rows_rejected_for_both_families(self):
        for family, change in itertools.product(TOOL.FAMILIES, ('missing', 'extra', 'duplicate')):
            r = sample(family)
            if change == 'missing': r['cases'].pop()
            elif change == 'extra': r['cases'].append(copy.deepcopy(r['cases'][0]))
            else: r['cases'][-1] = copy.deepcopy(r['cases'][0])
            with self.subTest(family=family, change=change), self.assertRaises(ValueError): TOOL.validate_report(family, r)

    def test_standalone_each_dimension_is_exact(self):
        for key, value in (('backend', 'other'), ('pattern', 'other'), ('optional_device', 0), ('marketing', 0), ('poison', 0)):
            r = sample('login-metadata');r['cases'][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'matrix'): TOOL.validate_report('login-metadata', r)

    def test_integrated_each_dimension_is_exact(self):
        for key, value in (('scenario', 'other'), ('selector', True), ('empty', 0), ('send_return', False),
                ('poison', 170), ('cache_case', 'resolve'), ('metadata_case', ['none', 'full', 0])):
            r = sample('login-prepare-metadata');r['cases'][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'matrix'): TOOL.validate_report('login-prepare-metadata', r)

    def test_missing_dimensions_non_object_rows_and_nan_are_rejected(self):
        for family in TOOL.FAMILIES:
            r = sample(family);del r['cases'][0]['poison']
            with self.assertRaises(ValueError): TOOL.validate_report(family, r)
            for value in (None, [], 'row'):
                r = sample(family);r['cases'][0] = value
                with self.assertRaises(ValueError): TOOL.validate_report(family, r)
            r = sample(family);r['cases'][0]['poison'] = float('nan')
            with self.assertRaises(ValueError): TOOL.validate_report(family, r)

    def test_guards_and_optional_identity_reads_are_exact_booleans(self):
        for family in TOOL.FAMILIES:
            for value in (False, 1, None):
                r = sample(family);r['cases'][0]['guards'] = value
                with self.assertRaises(ValueError): TOOL.validate_report(family, r)
            for key in ('host_identity_read', 'user_identity_read', 'nm_identity_read'):
                r = sample(family);r[key] = False;TOOL.validate_report(family, r)
                for value in (True, 0, None):
                    r[key] = value
                    with self.assertRaises(ValueError): TOOL.validate_report(family, r)

    def test_integrated_native_flags_cannot_be_missing_or_fixture_claim(self):
        for flag in ('native_sdk_used', 'native_metadata_used'):
            for value in (False, 1, None):
                r = sample('login-prepare-metadata');r[flag] = value
                with self.assertRaises(ValueError): TOOL.validate_report('login-prepare-metadata', r)

    def test_standalone_cannot_claim_sdk_getters_or_fixture_metadata(self):
        for key, value in (('native_sdk_used', True), ('native_metadata_used', False)):
            r = sample('login-metadata');r[key] = value
            with self.assertRaises(ValueError): TOOL.validate_report('login-metadata', r)

    def test_global_schema_and_per_case_provenance_cannot_change(self):
        r = sample('login-metadata');r['field_map']['I_OS'] = 0.0
        with self.assertRaisesRegex(ValueError, 'schema'): TOOL.validate_report('login-metadata', r)
        r = sample('login-metadata');row = next(c for c in r['cases'] if c['backend'] == 'ready')
        row['field_map']['I_OS'] = 16
        with self.assertRaisesRegex(ValueError, 'provenance'): TOOL.validate_report('login-metadata', r)
        r = sample('login-metadata');r['cases'][0]['mapping']['injected'] = ''
        with self.assertRaisesRegex(ValueError, 'provenance'): TOOL.validate_report('login-metadata', r)

    def test_case_gates_are_not_interchangeable(self):
        r = sample('login-metadata');row = next(c for c in r['cases'] if c['backend'] == 'ready' and c['pattern'] == 'omit-nid')
        row['field_map']['I_NMNID'] = 0x230;row['mapping']['I_NMNID'] = ''
        with self.assertRaisesRegex(ValueError, 'provenance'): TOOL.validate_report('login-metadata', r)

    def test_native_calls_track_active_backend_and_disabled_aux(self):
        r = sample('login-metadata');r['cases'][0]['native_calls']['writer'] = 1
        with self.assertRaisesRegex(ValueError, 'calls'): TOOL.validate_report('login-metadata', r)
        r = sample('login-metadata');row = next(c for c in r['cases'] if c['backend'] == 'ready');row['native_calls']['selector'] = 26
        with self.assertRaisesRegex(ValueError, 'calls'): TOOL.validate_report('login-metadata', r)
        r = sample('login-prepare-metadata');row = next(c for c in r['cases'] if c['scenario'] == 'aux-absent')
        row['metadata_calls']['collector'] = 1
        with self.assertRaisesRegex(ValueError, 'calls'): TOOL.validate_report('login-prepare-metadata', r)

    def test_metadata_projection_preserves_all27_keys_including_repeated_world(self):
        r = sample('login-prepare-metadata');self.assertEqual(sum(f['key'] == 'I_World' for f in r['metadata_fields']), 2)
        for changed in (list(reversed(r['metadata_fields'])), r['metadata_fields'][:-1],
                r['metadata_fields'][:-1] + [dict(key='I_World')]):
            bad = copy.deepcopy(r);bad['metadata_fields'] = changed
            with self.assertRaisesRegex(ValueError, 'field order'): TOOL.validate_report('login-prepare-metadata', bad)

    def test_optional_collector_order_must_match_marshal_order(self):
        for family in TOOL.FAMILIES:
            r = sample(family);r['collector_order'] = list(TOOL.COLLECTOR_ORDER);TOOL.validate_report(family, r)
            r['collector_order'].reverse()
            with self.assertRaisesRegex(ValueError, 'collector order'): TOOL.validate_report(family, r)

    def test_tools_pin_actual_imported_constants_and_contract(self):
        expected = {str(TOOL.HERE / name): hashlib.sha256((TOOL.HERE / name).read_bytes()).hexdigest()
            for name in ('login-metadata-case-contracts.py', 'verify-login-metadata-context.py', 'verify-login-prepare-context.py')}
        self.assertEqual(TOOL.tools(), expected)


if __name__ == '__main__':
    unittest.main()
