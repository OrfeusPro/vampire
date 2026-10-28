"""Read-only admission of immutable updater bundles; no analysis or network imports."""
import ctypes
import hashlib
import importlib.metadata
import json
import locale
from pathlib import Path
import platform
import re
import sys

SHA = re.compile(r'[0-9a-f]{64}')
MAX_DOCUMENT = 32 * 1024 * 1024


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def document(path, expected):
    path = Path(path).resolve()
    if not isinstance(expected, str) or not SHA.fullmatch(expected) or path.stat().st_size > MAX_DOCUMENT:
        raise ValueError('Invalid prepared bundle document')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Prepared bundle document changed')
    return json.loads(raw)


def select(root, selected='prepared-next', capability='world-session'):
    """Resolve the mutable pointer once, returning an immutable profile selector."""
    root = Path(root).resolve()
    if selected == 'prepared-next':
        path = root / 'knowledge/next-profiles' / (capability + '.json')
        if path.stat().st_size > 65536:
            raise ValueError('Prepared profile pointer exceeds budget')
        value = json.loads(path.read_bytes())
        if value.get('schema') != 1 or value.get('capability') != capability:
            raise ValueError('Prepared profile pointer scope differs')
        sha = value.get('bundle_sha256')
    elif isinstance(selected, str) and selected.startswith('prepared:'):
        sha = selected.partition(':')[2]
    else:
        raise ValueError('Explicit prepared profile required')
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError('Prepared profile requires a complete bundle SHA')
    return 'prepared:' + sha


def _effective(check, sha):
    if (check.get('source_scope', 'client') != 'client' or check.get('offline_reviewed') is not True
            or sha not in check.get('source_sha256', [])):
        raise ValueError('Prepared check has no reviewed target declaration')
    variant = check.get('source_variants', {}).get(sha)
    if variant is None:
        return check
    if not isinstance(variant, dict) or not variant or set(variant) - {
            'test_pattern', 'dependencies', 'artifact_dependencies', 'timeout_seconds'}:
        raise ValueError('Prepared source variant differs')
    result = {k: v for k, v in check.items() if k != 'source_variants'}
    result.update(variant)
    result['selected_source_variant'] = sha
    return result


def _system_files(names):
    if names not in ([], ['ucrtbase.dll']):
        raise ValueError('Unsupported prepared runtime library')
    if not names:
        return set()
    if sys.platform != 'win32':
        raise ValueError('Prepared CRT requires Windows')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint
    value = ctypes.create_unicode_buffer(32768)
    size = kernel.GetSystemDirectoryW(value, len(value))
    if not 0 < size < len(value):
        raise ValueError('Cannot resolve prepared CRT')
    return {(Path(value.value) / name).resolve() for name in names}


def validate(*, root, workspace, selected='prepared-next', capability='world-session'):
    root, workspace = Path(root).resolve(), Path(workspace).resolve()
    selected = select(root, selected, capability)
    bundle_sha = selected.partition(':')[2]
    bundle = document(root / 'knowledge/prepared-bundles' / bundle_sha / 'manifest.json', bundle_sha)
    if (bundle.get('schema') != 1 or bundle.get('capability') != capability
            or bundle.get('state') != 'prepared_offline' or bundle.get('live_verified') is not False
            or bundle.get('runtime_activated') is not False):
        raise ValueError('Prepared bundle scope differs')
    source_sha = bundle.get('source_sha256')
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise ValueError('Prepared bundle source is missing')
    tools = workspace / 'phone-exit/bots/resource-tools/vampir'
    rules = bundle.get('rules', {})
    canonical_rules={}
    for path, expected in rules.items():
        key=str(Path(path).resolve())
        if key in canonical_rules and canonical_rules[key]!=expected:
            raise ValueError('Prepared admission rule paths conflict')
        canonical_rules[key]=expected
    rules=canonical_rules
    mandatory = {tools / name for name in ('update-bundle.py', 'update-profile.py', 'update-contracts.py',
        'research-workflow.py', 'knowledge/update-contracts.json', 'knowledge/research-checks.json')}
    mandatory.add(workspace / 'phone-exit/bots/vampir-shared/vampir_core/release_bundle.py')
    if not mandatory.issubset({Path(p).resolve() for p in rules}):
        raise ValueError('Prepared admission rules are incomplete')
    files = {}
    stamps = {}

    def pin(path, expected, *, roots=(root, workspace)):
        path = Path(path).resolve()
        if not any(path.is_relative_to(base) for base in roots):
            raise ValueError('Prepared artifact outside declared roots')
        if not isinstance(expected, str) or not SHA.fullmatch(expected):
            raise ValueError('Prepared artifact needs a complete SHA')
        if path in files:
            if files[path] != expected:
                raise ValueError('Prepared artifact hashes conflict')
            return
        before = path.stat()
        if digest(path) != expected:
            raise ValueError('Prepared artifact changed: ' + path.name)
        after = path.stat()
        stamp = (before.st_size, before.st_mtime_ns)
        if stamp != (after.st_size, after.st_mtime_ns):
            raise ValueError('Prepared artifact changed while reading')
        files[path], stamps[path] = expected, stamp

    for filename, expected in rules.items():
        pin(filename, expected, roots=(workspace,))
    specs = json.loads((tools / 'knowledge/update-contracts.json').read_bytes())
    registry = json.loads((tools / 'knowledge/research-checks.json').read_bytes())['checks']
    definitions = {r['id']: r for r in registry}
    if len(definitions) != len(registry):
        raise ValueError('Ambiguous prepared check registry')
    contracts = {r['id']: r for r in specs['contracts']}
    required = set(specs['capabilities'][capability]['requires'])
    while True:
        expanded = required | {d for name in required for d in contracts[name]['depends_on']}
        if expanded == required:
            break
        required = expanded
    if set(bundle.get('contracts', {})) != required:
        raise ValueError('Prepared contract coverage differs')
    installed = Path(bundle['source']).resolve()
    install = Path(bundle['install']).resolve()
    if installed != install / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe':
        raise ValueError('Prepared installed EXE path differs')
    pin(installed, source_sha, roots=(install,))
    for filename, expected in bundle.get('artifacts', {}).items():
        pin(filename, expected, roots=(root, workspace, install))
    runtime_cache = {}
    compiled_tags = set()
    for name in sorted(required):
        contract, outcome = contracts[name], bundle['contracts'][name]
        if contract.get('coverage') != 'source_checks' or outcome.get('state') != 'passed':
            raise ValueError('Prepared contract is partial')
        context = outcome['context']
        cp = Path(context['path']).resolve()
        if not cp.is_relative_to(root / 'knowledge/update-contexts'):
            raise ValueError('Prepared contract context outside library')
        value = document(cp, context['sha256'])
        if value.get('source_sha256') != source_sha or value['contract']['id'] != name:
            raise ValueError('Prepared contract context source differs')
        expected_checks = set(contract['checks']) | set(contract.get('context_checks', []))
        checks = {c['id']: c for c in outcome['checks']}
        if len(checks) != len(outcome['checks']) or set(checks) != expected_checks or not checks:
            raise ValueError('Prepared semantic coverage differs')
        for check_id, receipt in checks.items():
            if receipt.get('state') != 'passed':
                raise ValueError('Prepared semantic check failed')
            report_path = Path(receipt['report']).resolve()
            if not report_path.is_relative_to(root / 'knowledge'):
                raise ValueError('Prepared check report outside library')
            proof = document(report_path, receipt['sha256'])
            if check_id in contract.get('context_checks', []):
                if (proof.get('source_sha256') != source_sha or proof.get('context_sha256') != context['sha256']
                        or proof.get('method') == 'function_only' or proof.get('scope') == 'function_only'
                        or not proof.get('cases') or proof.get('network_used') is not False):
                    raise ValueError('Prepared context check has no semantic proof')
                if check_id == 'version-login-tag':
                    compiled_tags.add(proof.get('binding', {}).get('tag'))
                continue
            check = _effective(definitions[check_id], source_sha)
            definition = proof['definition']
            if (proof.get('state') != 'passed' or definition.get('source_sha256') != source_sha
                    or definition.get('check') != check or definition.get('python_version') != platform.python_version()
                    or definition.get('executable') != sys.executable
                    or definition.get('runner_sha256') != digest(tools / 'research-workflow.py')):
                raise ValueError('Prepared check definition or runtime differs')
            wanted = {(workspace / 'phone-exit/bots' / check['test_pattern']).resolve()}
            wanted.update((workspace / p).resolve() for p in check['dependencies'])
            if {Path(p).resolve() for p in definition['inputs']} != wanted:
                raise ValueError('Prepared check input set differs')
            for filename, expected in definition['inputs'].items():
                pin(filename, expected, roots=(workspace,))
            wanted_artifacts = {(root / p).resolve() for p in check.get('artifact_dependencies', [])}
            wanted_artifacts.update(_system_files(check.get('system_runtime_files', [])))
            if {Path(p).resolve() for p in definition['artifacts']} != wanted_artifacts:
                raise ValueError('Prepared check artifact set differs')
            for filename, expected in definition['artifacts'].items():
                path = Path(filename).resolve()
                if path.is_relative_to(root):
                    pin(path, expected)
                else:
                    if path not in _system_files(check.get('system_runtime_files', [])):
                        raise ValueError('Unreviewed prepared runtime artifact')
                    pin(path, expected, roots=(path.parent,))
            runtime = {}
            for dist in check.get('runtime_distributions', []):
                if dist not in runtime_cache:
                    matches = [d for d in importlib.metadata.distributions(
                        path=[str(workspace / 'phone-exit/.tools/vampir-analysis')])
                        if d.metadata['Name'].lower() == dist.lower()]
                    if len(matches) != 1:
                        raise ValueError('Prepared native runtime is missing')
                    runtime_cache[dist] = dict(version=matches[0].version,
                        record_sha256=hashlib.sha256((matches[0].read_text('RECORD') or '').encode()).hexdigest())
                runtime[dist] = runtime_cache[dist]
            if definition.get('runtime_metadata') != runtime:
                raise ValueError('Prepared native runtime changed')
            if check.get('system_runtime_files') and definition.get('system_runtime_locale') != locale.setlocale(locale.LC_ALL):
                raise ValueError('Prepared runtime locale changed')
    if capability in ('launcher', 'world-session'):
        sdk_receipt = bundle.get('sdk_profile_receipt', {})
        sp = Path(sdk_receipt.get('path', '')).resolve()
        if not sp.is_relative_to(root / 'knowledge/prepared-profiles'):
            raise ValueError('Prepared SDK profile receipt outside library')
        package = document(sp, sdk_receipt.get('sha256'))
        sdk = bundle.get('sdk_profile', {})
        if (package.get('profile') != sdk or package.get('source_sha256') != source_sha
                or package.get('state') != 'prepared_offline' or Path(sdk.get('source','')).resolve() != installed
                or sdk.get('runtime_scope') != 'sdk-launcher-auth' or sdk.get('supported_auth_flows') != ['launcher']
                or sdk.get('source_sha256') != source_sha or not sdk.get('public_gmc2') or not sdk.get('nid')
                or any(sdk.get(k) is not False for k in ('direct_sdk_operations_verified', 'network_ready', 'game_protocol_verified'))):
            raise ValueError('Prepared SDK profile is missing or has different scope')
    if capability == 'world-session':
        from .runtime_admission import descriptor
        expected_adapter = descriptor(workspace)
        if bundle.get('runtime_adapter') != expected_adapter:
            raise ValueError('Prepared runtime adapter is missing or changed')
        if any(rules.get(str((workspace / name).resolve())) != expected
               for name, expected in expected_adapter['consumers'].items()):
            raise ValueError('Prepared runtime consumer rules are incomplete')
        game = bundle.get('game_profile', {})
        if (not game.get('config_snapshot_sha256') or not re.fullmatch('[0-9A-F]{32}', game.get('compiled_tag', ''))
                or not game.get('app_version') or not game.get('cdn_url')):
            raise ValueError('Prepared game profile is incomplete')
        if compiled_tags != {game['compiled_tag']}:
            raise ValueError('Prepared tag does not match semantic Version/Login proof')
        config_sha = game['config_snapshot_sha256']
        config_path = root / 'resource-config-snapshots' / config_sha / 'manifest.json'
        config = document(config_path, config_sha)
        if (config.get('exe_sha256') != source_sha or Path(config['source_exe']).resolve() != installed):
            raise ValueError('Prepared game config source differs')
        archive = Path(config['source_archive']['path']).resolve()
        pin(archive, config['archive_sha256'], roots=(install,))
        rows = [r for r in config.get('configs', []) if r.get('snapshot_file') == 'DefaultGame.ini']
        if len(rows) != 1:
            raise ValueError('Prepared game config is ambiguous')
        ini = config_path.parent / 'DefaultGame.ini'
        pin(ini, rows[0]['payload_sha256'])
        lines, values = ini.read_text('utf-8-sig').splitlines(), {}
        for row in rows[0]['values']:
            if row['section'] != 'NetworkSetting':
                continue
            key, sep, value = lines[row['line']-1].strip().partition('=')
            if not sep or (key.strip(), value.strip()) != (row['key'], row['value']) or row['key'] in values:
                raise ValueError('Prepared INI provenance differs')
            values[row['key']] = row['value']
        from .sdk_config import prepare_cdn_config_url_ascii
        url = prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'], qa=values['CdnConfigUrlQA'],
            prefix=values['ConfigPrefix'], app_version=values['AppVersion'], platform_code=2)
        if (values['CdnConfig'] != 'True' or game['app_version'] != values['AppVersion']
                or game['config_prefix'] != values['ConfigPrefix'] or game['cdn_url'] != 'https://' + url):
            raise ValueError('Prepared game settings differ from config evidence')
    for path, stamp in stamps.items():
        current = path.stat()
        if (current.st_size, current.st_mtime_ns) != stamp:
            raise ValueError('Prepared inputs changed during admission')
    bundle['bundle_sha256'] = bundle_sha
    bundle['selected_profile'] = selected
    return bundle
