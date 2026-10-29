"""Exact bounded metadata report coverage; no source or live-entry admission."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILIES = ('login-metadata', 'login-prepare-metadata')
COUNTS = dict(zip(FAMILIES, (288, 448)))
COLLECTOR_ORDER = ('I_GameCode', 'I_GameVersion', 'I_TID', 'I_CountryCD', 'I_PID',
    'I_ChannelType', 'I_SDKVersion', 'I_World', 'I_PlatformADID', 'I_ConnectIP',
    'I_UDID', 'I_JoinedCountryCode', 'I_DeviceOSVersion', 'I_DeviceModel', 'I_OS',
    'I_Region', 'I_TimeZone', 'I_LanguageCD', 'I_NMDeviceKey', 'I_NMIDFV', 'I_World',
    'I_NMMarket', 'I_NMNID', 'I_PCSeq', 'I_NMCPU', 'I_NMRAM', 'I_NMVGA')
INTEGRATION_CASES = (('none', 'full', False), ('invalid', 'full', True), ('ready', 'full', False),
    ('ready', 'empty', True), ('ready', 'omit-gates', True), ('shared', 'unicode-quote', True),
    ('weak-shared', 'omit-nid', False), ('unmanaged', 'omit-channel', True))
TOOLS = ('login-metadata-case-contracts.py', 'verify-login-metadata-context.py', 'verify-login-prepare-context.py')


def tools():
    return {str(HERE / name): hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in TOOLS}


def case_count(family):
    if not isinstance(family, str) or family not in COUNTS:
        raise ValueError('Unreviewed Login metadata family')
    return COUNTS[family]


def verifier(family):
    case_count(family)
    return 'verify-login-metadata-context' if family == 'login-metadata' else 'verify-login-prepare-context'


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _native_calls(active):
    return dict(collector=1, loader=1, copy=1, selector=27, writer=1) if active else dict(collector=1, loader=1, move=1)


def _field_provenance(field_map, pattern):
    result = dict(field_map)
    if pattern in ('empty', 'omit-gates'):
        for key in ('I_GameCode', 'I_NMBuildCode', 'I_NMNID', 'I_NMNIDChannelType'):
            result.pop(key)
    if pattern == 'empty':
        result.pop('I_NMCharacterID')
    if pattern == 'omit-nid':
        result.pop('I_NMNID');result.pop('I_NMNIDChannelType')
    result.update(I_NMDeviceKey=0x50, I_PlatformADID=0x70, I_NMIDFV=None,
        I_NMAppSetID=None, I_NMInstallPackageName=None, I_NMAppSetIDScope=None)
    return result


def validate_report(family, report):
    """Validate exact dimensions and emitted bounded native/schema claims.

    Source, context, scope, proof hashes, activation and network flags belong to
    the caller's admission guard. Native field values and cleanup are checked by
    the verifiers; this contract preserves their complete scenario coverage.
    """
    count = case_count(family)
    if not isinstance(report, dict) or not isinstance(report.get('cases'), list) or len(report['cases']) != count:
        raise ValueError('Login metadata case count differs')
    metadata = _load('verify-login-metadata-context')
    scenarios = _load('verify-login-prepare-context').SCENARIOS
    if family == 'login-metadata':
        fields = ('backend', 'pattern', 'optional_device', 'marketing', 'poison')
        expected = [dict(zip(fields, values)) for values in itertools.product(
            metadata.BACKENDS, metadata.PATTERNS, (False, True), (False, True), (0x55, 0xaa))]
    else:
        fields = ('scenario', 'selector', 'empty', 'send_return', 'poison', 'cache_case', 'metadata_case')
        expected = [dict(scenario=s[0], selector=3, empty=e, send_return=r, poison=0x55,
                         cache_case='warm', metadata_case=list(m))
            for s, e, r, m in itertools.product(scenarios, (False, True), (0, 1), INTEGRATION_CASES)]
    if len(expected) != count:
        raise ValueError('Reviewed Login metadata matrix definition changed')
    try:
        wanted = {_canonical(row) for row in expected}
        actual = [_canonical({key: row[key] for key in fields}) for row in report['cases'] if isinstance(row, dict)]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Login metadata matrix dimensions invalid') from error
    if len(wanted) != count or len(actual) != count or len(set(actual)) != count or set(actual) != wanted:
        raise ValueError('Login metadata matrix incomplete, duplicated or changed')
    if any(row.get('guards') is not True for row in report['cases']):
        raise ValueError('Login metadata case guards differ')
    for key in ('user_identity_read', 'nm_identity_read', 'host_identity_read'):
        if key in report and report[key] is not False:
            raise ValueError('Login metadata real identity boundary differs')
    if 'collector_order' in report and _canonical(report['collector_order']) != _canonical(list(COLLECTOR_ORDER)):
        raise ValueError('Login metadata collector order differs')
    if family == 'login-metadata':
        if _canonical(report.get('field_map')) != _canonical(metadata.FIELD_MAP):
            raise ValueError('Login metadata field schema differs')
        for flag, expected_flag in (('native_sdk_used', False), ('native_metadata_used', True)):
            if flag in report and report[flag] is not expected_flag:
                raise ValueError('Standalone metadata native scope differs')
        for row in report['cases']:
            active = row['backend'] not in ('none', 'invalid')
            field_map = _field_provenance(metadata.FIELD_MAP, row['pattern']) if active else {}
            if (_canonical(row.get('field_map')) != _canonical(field_map)
                    or not isinstance(row.get('mapping'), dict) or set(row['mapping']) != set(field_map)
                    or _canonical(row.get('native_calls')) != _canonical(_native_calls(active))):
                raise ValueError('Login metadata field provenance or native calls differ')
    else:
        if report.get('native_sdk_used') is not True or report.get('native_metadata_used') is not True:
            raise ValueError('Login metadata integration native flags differ')
        projected = report.get('metadata_fields')
        if (not isinstance(projected, list) or len(projected) != 27 or any(not isinstance(row, dict) for row in projected)
                or [row.get('key') for row in projected] != list(COLLECTOR_ORDER)):
            raise ValueError('Login metadata integration field order differs')
        by_name = {s[0]: s for s in scenarios}
        for row in report['cases']:
            _, _, enabled, present, mask, _ = by_name[row['scenario']]
            aux = enabled and present and bool(mask & 2)
            active = row['metadata_case'][0] not in ('none', 'invalid')
            expected_calls = _native_calls(active) if aux else {}
            if _canonical(row.get('metadata_calls')) != _canonical(expected_calls):
                raise ValueError('Login metadata integration native calls differ')
