"""Exact reviewed case matrices for bounded Version helper reports.

This validates report coverage, not a source, proof, real provider or live entry.
The caller must validate those identities and the immutable native report.
"""
import importlib.util
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILIES = ('version-nm-device', 'version-cpu', 'version-windows', 'version-combiner',
            'version-platform', 'version-prepare-nm', 'version-prepare-system',
            'version-prepare-combiner', 'version-prepare-platform')
COUNTS = dict(zip(FAMILIES, (36, 72, 48, 256, 116, 64, 64, 64, 288)))
POISONS = (0, 0x55, 0xaa, 0xff)
NATIVE_FLAGS = ('native_nm_used', 'native_system_used', 'native_combiners_used', 'native_platform_used')
NM_PROFILES = ('cached', 'cached-one-char', 'cached-space', 'stored', 'parse-failure',
               'zero-guid', 'write-failure', 'read-failure-value', 'read-failure-empty')
CPU_PROFILES = (('GenuineIntel', 'Fixture CPU'), ('AuthenticAMD', '  Fixture CPU  '),
                (' Vendor ', '\t\r\nSpaced CPU\t\r\n'), ('', ''), ('GenuineIntel', ' \t\r\n\v\f'),
                ('GenuineIntel', 'Unknown'), ('GenuineIntel', 'A|B|C'), ('GenuineIntel', 'A\0Hidden'),
                ('GenuineIntel', 'X' * 63))
WINDOWS_PROFILES = ('cached', 'cold', 'failed-version', 'other-thread', 'negative-equal', 'negative-cold')
WINDOWS_VALUES = ((10, 0, 26100, 1, 256), (6, 3, 9600, 255, 65535))
COMBINER_PAIRS = (('', ''), ('', '_'), ('Windows', ''), ('Windows', '_'),
                  ('Windows_', '10.0.26100.1.256.64bit'), ('контекст🙂', '_界'),
                  ('a\0b', 'c\0d'), ('x' * 127, 'y' * 128))


def case_count(family):
    if not isinstance(family, str) or family not in COUNTS:
        raise ValueError('Unreviewed Version helper family')
    return COUNTS[family]


def verifier(family):
    case_count(family)
    return 'verify-version-prepare-context' if family.startswith('version-prepare-') else 'verify-' + family + '-context'


def _platform_scenarios():
    spec = importlib.util.spec_from_file_location('version_platform_case_fixtures', HERE / 'version-platform-fixtures.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SCENARIOS


def _canonical(value):
    # JSON keeps false and 0 distinct; Python tuple/set equality does not.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _expected(family):
    if family == 'version-nm-device':
        return ('poison', 'profile'), [dict(poison=p, profile=s) for p, s in itertools.product(POISONS, NM_PROFILES)]
    if family == 'version-cpu':
        return ('poison', 'vendor', 'brand', 'allocate_empty'), [dict(poison=p, vendor=a, brand=b, allocate_empty=e)
            for p, (a, b), e in itertools.product(POISONS, CPU_PROFILES, (False, True))]
    if family == 'version-windows':
        return ('poison', 'profile', 'values'), [dict(poison=p, profile=s, values=list(v))
            for p, s, v in itertools.product(POISONS, WINDOWS_PROFILES, WINDOWS_VALUES)]
    if family == 'version-combiner':
        return ('poison', 'function', 'left', 'right', 'spare', 'allocated_empty'), [
            dict(poison=p, function=f, left=a, right=b, spare=s, allocated_empty=e)
            for p, f, (a, b), s, e in itertools.product(POISONS, ('first', 'second'), COMBINER_PAIRS, (0, 300), (False, True))]
    if family == 'version-platform':
        result = []
        for poison in POISONS:
            result.extend(dict(kind='selector', poison=poison, platform=platform, truth=truth)
                for platform, truth in itertools.product(('Android', 'IOS', 'Windows', 'Linux', '', 'windows'), (1, 128, 255)))
            result.append(dict(kind='empty_platform', poison=poison))
            result.extend(dict(kind='store', poison=poison, initial=a, resolved=b)
                for a, b in ((True, True), (False, True), (False, False)))
            result.extend(dict(kind='lookup', poison=poison, count=count, target=target)
                for count, target in ((0, 3), (-1, 3), (3, 1), (3, 3), (3, 4), (2, 3), (2, 0xffffffffffffffff)))
        return None, result
    fields = ('poison', 'context_present', 'empty', 'raw_enum', 'send_return')
    if family == 'version-prepare-platform':
        fields += ('platform_scenario',)
        result = [dict(poison=p, context_present=s['present'], empty=e, raw_enum=v,
                       send_return=r, platform_scenario=s['name'])
            for p, s, e, v, r in itertools.product(POISONS, _platform_scenarios(), (False, True), (0, 0xffffffff), (0, 1))]
    else:
        result = [dict(zip(fields, values))
            for values in itertools.product(POISONS, (False, True), (False, True), (0, 0xffffffff), (0, 1))]
    return fields, result


def _dimensions(fields, row):
    if fields is None:
        fields = {
            'selector': ('kind', 'poison', 'platform', 'truth'),
            'empty_platform': ('kind', 'poison'),
            'store': ('kind', 'poison', 'initial', 'resolved'),
            'lookup': ('kind', 'poison', 'count', 'target'),
        }.get(row.get('kind'))
        if fields is None:
            raise ValueError('Unreviewed Version platform case kind')
    if any(key not in row for key in fields):
        raise ValueError('Version helper matrix dimension missing')
    return {key: row[key] for key in fields}


def validate_report(family, report):
    """Reject incomplete, duplicated or reclassified bounded case reports."""
    count = case_count(family)
    if not isinstance(report, dict) or not isinstance(report.get('cases'), list) or len(report['cases']) != count:
        raise ValueError('Version helper case count differs')
    fields, expected = _expected(family)
    if len(expected) != count or len({_canonical(row) for row in expected}) != count:
        raise ValueError('Reviewed Version helper matrix definition differs')
    try:
        actual = [_canonical(_dimensions(fields, row)) for row in report['cases'] if isinstance(row, dict)]
    except (TypeError, ValueError) as error:
        raise ValueError('Version helper matrix has invalid dimensions') from error
    if len(actual) != count or len(set(actual)) != count or set(actual) != {_canonical(row) for row in expected}:
        raise ValueError('Version helper matrix is incomplete, duplicated or changed')
    if family.startswith('version-prepare-'):
        level = FAMILIES.index(family) - 4
        if any(report.get(flag) is not (i < level) for i, flag in enumerate(NATIVE_FLAGS)):
            raise ValueError('Version helper integration native scope differs')
        if any(row.get('guards') is not True or type(row.get('native_nm_calls')) is not int
                or row['native_nm_calls'] != 2 for row in report['cases']):
            raise ValueError('Version helper integration guards or NM calls differ')
    else:
        if any(flag in report for flag in NATIVE_FLAGS):
            raise ValueError('Standalone Version helper cannot claim preparation integration')
        if family == 'version-nm-device':
            if report.get('user_identity_read') is not False or any(row.get('guards') is not True
                    or row.get('repeated_cache_only') is not True for row in report['cases']):
                raise ValueError('NM helper identity boundary or guards differ')
        if family in ('version-cpu', 'version-windows') and report.get('host_identity_read') is not False:
            raise ValueError('System helper host identity boundary differs')
        if family == 'version-combiner' and (type(report.get('overflow_cases')) is not int or report['overflow_cases'] != 2):
            raise ValueError('Combiner overflow proof count differs')
