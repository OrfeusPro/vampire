"""Assemble the current offline game candidate from explicit retained proofs."""
import argparse
import hashlib
import importlib.util
import importlib.metadata
import json
from pathlib import Path
import re
import platform
import struct
import sys

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
KNOWLEDGE = HERE / 'knowledge'
CONTEXT = KNOWLEDGE / 'game-candidate-current-inputs.json'
ROOT = Path('F:/PhoneExit Resources/Vampir')
RECIPE = 'game-candidate-current-v1'
SHA = re.compile(r'[0-9a-f]{64}')
ENTRY_CHECKS = ('character-list-current', 'clock-world-current', 'lobby-metadata-current', 'lobby-wire-current')


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Inputs:
    def __init__(self):
        self.files = {}
        self.stamps = {}

    def pin(self, path, expected=None):
        path = Path(path).resolve()
        before = path.stat()
        stamp = before.st_size, before.st_mtime_ns
        known = self.files.get(str(path))
        if known is None:
            actual = digest(path)
            after = path.stat()
            if stamp != (after.st_size, after.st_mtime_ns):
                raise ValueError('Candidate input changed during read: ' + path.name)
            self.files[str(path)] = actual
            self.stamps[path] = stamp
        else:
            actual = known
            if self.stamps[path] != stamp:
                raise ValueError('Candidate input changed during assembly: ' + path.name)
        if expected is not None and (not SHA.fullmatch(str(expected)) or actual != expected):
            raise ValueError('Candidate input SHA differs: ' + path.name)
        return actual

    def document(self, path, expected=None):
        path = Path(path).resolve()
        if not 0 < path.stat().st_size <= 32 * 1024 * 1024:
            raise ValueError('Candidate manifest exceeds budget')
        pinned = self.pin(path, expected)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != pinned:
            raise ValueError('Candidate manifest changed during read')
        return json.loads(raw)

    def pointer(self, value, directory):
        if type(value) is not dict or set(value) != {'path', 'sha256'} or not SHA.fullmatch(str(value['sha256'])):
            raise ValueError('Candidate requires a complete immutable pointer')
        path = Path(value['path']).resolve()
        if path != Path(directory).resolve() / value['sha256'] / 'manifest.json':
            raise ValueError('Candidate proof path differs')
        return self.document(path, value['sha256'])

    def retain(self, files):
        for path, expected in files.items():
            self.pin(path, expected)

    def barrier(self):
        for name, expected in self.files.items():
            if digest(name) != expected:
                raise ValueError('Candidate final SHA barrier failed: ' + Path(name).name)


def resource(inputs, root, installed, pointer, source_sha):
    profile = inputs.pointer(pointer, root / 'resource-config-snapshots')
    install = installed.parents[3]
    archive = install / 'ProjectRED/Content/Paks/ProjectRED-Windows.pak'
    if (profile['exe_sha256'] != source_sha or Path(profile['source_exe']).resolve() != installed
            or Path(profile['source_archive']['path']).resolve() != archive
            or profile.get('authoritative_directory_for_archive') is not True
            or profile.get('active_runtime_settings_verified') is not False
            or profile.get('config_precedence_verified') is not False):
        raise ValueError('Candidate requires the exact base game config source')
    inputs.pin(archive, profile['archive_sha256'])
    audit_sha = profile['release_manifest_sha256']
    if not SHA.fullmatch(audit_sha):
        raise ValueError('Candidate requires a full release audit SHA')
    audit = inputs.document(root / 'knowledge/update-audits' / audit_sha / 'manifest.json', audit_sha)
    if audit['exe']['sha256'] != source_sha or Path(audit['exe']['path']).resolve() != installed:
        raise ValueError('Candidate release audit EXE differs')
    rows = [row for row in audit['files'] if Path(row['path']).resolve() == archive]
    if (len(rows) != 1 or rows[0]['current']['sha256'] != profile['archive_sha256']
            or rows[0]['current']['size'] != archive.stat().st_size):
        raise ValueError('Candidate base archive differs from the release audit')
    configs = [row for row in profile['configs'] if row['snapshot_file'] == 'DefaultGame.ini']
    if len(configs) != 1:
        raise ValueError('Candidate base INI is missing or ambiguous')
    config = configs[0]
    ini = Path(pointer['path']).parent / 'DefaultGame.ini'
    inputs.pin(ini, config['payload_sha256'])
    lines = ini.read_text('utf-8-sig').splitlines()
    values = {}
    for row in config['values']:
        if row['section'] != 'NetworkSetting':
            continue
        key, sep, value = lines[row['line'] - 1].strip().partition('=')
        if not sep or (key.strip(), value.strip()) != (row['key'], row['value']) or row['key'] in values:
            raise ValueError('Candidate base INI row provenance differs')
        values[row['key']] = row['value']
    if values.get('CdnConfig') != 'True' or values.get('ConfigPrefix') != 'real':
        raise ValueError('Candidate base INI lacks the production CDN configuration')
    sys.path.insert(0, str(WORKSPACE / 'phone-exit/bots/vampir-shared'))
    from vampir_core.sdk_config import prepare_cdn_config_url_ascii
    url = prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'], qa=values['CdnConfigUrlQA'],
        prefix=values['ConfigPrefix'], app_version=values['AppVersion'], platform_code=2)
    return dict(app_version=values['AppVersion'], config_prefix=values['ConfigPrefix'], cdn_url='https://' + url,
                config_snapshot_sha256=pointer['sha256'], archive_sha256=profile['archive_sha256'],
                ini_sha256=config['payload_sha256'], release_audit_sha256=audit_sha)


def compiled_tag(inputs, root, image, contexts, source_sha):
    bindings = []
    for role in ('version-prepare', 'login-prepare'):
        context = inputs.pointer(contexts[role]['context'], root / 'knowledge/generated-native-contexts')
        if context['source_sha256'] != source_sha or context['family'] != role:
            raise ValueError('Candidate tag context source/role differs')
        bindings.append((context['globals']['tag_pointer'], context['compiled_tag_source']))
    pointer, binding = bindings[0]
    if bindings[0] != bindings[1] or not re.fullmatch('[0-9A-F]{32}', binding['value']):
        raise ValueError('Current Version and Login compiled tags disagree')
    raw = image.data
    literal = int(binding['literal'], 16)
    pointer_offset = image.offset(int(pointer, 16) - image.pe.base)
    literal_offset = image.offset(literal - image.pe.base)
    if (struct.unpack_from('<Q', raw, pointer_offset)[0] != literal
            or raw[literal_offset:literal_offset + 33] != (binding['value'] + '\0').encode('ascii')):
        raise ValueError('Candidate compiled tag pointer or literal differs')
    return dict(tag=binding['value'], pointer=pointer, literal=binding['literal'])


def lobby_shapes(inputs, root, native, image, context, source_sha):
    export = context['lobby_export']
    path = Path(export['path']).resolve()
    if path.parent.parent != root / 'ghidra/request-exports' / source_sha or path.name != 'details.json':
        raise ValueError('Candidate lobby prepare export path differs')
    report = inputs.document(path, export['sha256'])
    roles = context['lobby_roles']
    wanted = {'login_prepare', 'version_prepare', 'version_writer', 'login_writer', 'server_list_writer'}
    if report['new_source_sha256'] != source_sha or set(roles) != wanted:
        raise ValueError('Candidate lobby prepare source or role differs')
    normalize = load(HERE / 'audit-launcher-shape-11318.py').normalize_function
    functions = {row['address']: row for row in report['functions']}
    if set(functions) != set(roles.values()) or len(roles) != len(functions):
        raise ValueError('Candidate lobby export whole-root coverage differs')
    checked = {}
    for role, address in roles.items():
        result = normalize(native, image, functions[address])
        checked[role] = dict(address=address, instructions=len(result['shape']))
    prepare = functions[roles['login_prepare']]
    rows = {r['address']: r['bytes'] for r in prepare['instructions']}
    anchors = context['lobby_login_prepare_anchors']
    if not anchors or any(rows.get(at) != expected for at, expected in anchors.items()):
        raise ValueError('Candidate lobby login call/gate window changed')
    return dict(method='whole_static', export=export, functions=checked,
                login_prepare_anchors=anchors, send_wrapper_verified=False)


def build(context_path=CONTEXT, *, root=ROOT, installed=None):
    root = Path(root).resolve()
    index = load(HERE / 'knowledge-index.py')
    installed = Path(installed or index.INSTALL).resolve()
    inputs = Inputs()
    context = inputs.document(context_path)
    source_sha = context.get('source_sha256')
    if (context.get('schema') != 1 or context.get('recipe') != RECIPE
            or not SHA.fullmatch(str(source_sha))):
        raise ValueError('Candidate context source or recipe differs')
    inputs.pin(installed, source_sha)
    bridge_context = inputs.document(KNOWLEDGE / 'native-contexts/candidate-proof-bridges-11322.json',
                                    context['bridge_context_sha256'])
    bridge = inputs.pointer(context['bridges'], root / 'knowledge/candidate-proof-bridges-v1')
    bridge_api = load(HERE / 'candidate-proof-bridges.py')
    if bridge.get('context_sha256') != context['bridge_context_sha256'] or bridge.get('source_sha256') != source_sha:
        raise ValueError('Candidate bridge context or source differs')
    bridge_api.validate_saved(bridge_context, bridge)
    inputs.retain(bridge['files'])
    native = load(HERE / 'build-native-entry-code.py')
    raw = installed.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source_sha:
        raise ValueError('Candidate installed EXE changed before PE inspection')
    image = native.Image(raw)
    tag = compiled_tag(inputs, root, image, bridge_context['native'], source_sha)
    lobby = lobby_shapes(inputs, root, native, image, context, source_sha)

    sdk_path = WORKSPACE / 'phone-exit/bots/vampir-headless/sdk-launcher-profile.py'
    sdk = load(sdk_path).load_manifest(profile_sha256=context['sdk']['sha256'], source_sha256=source_sha,
                                      root=root, workspace=WORKSPACE, installed=installed)
    inputs.pointer(context['sdk'], root / 'sdk-launcher-profiles')
    inputs.retain(sdk['inputs'])

    registry = inputs.document(KNOWLEDGE / 'research-checks.json')
    definitions = {row['id']: row for row in registry['checks']}
    if len(definitions) != len(registry['checks']):
        raise ValueError('Candidate check registry is ambiguous')
    guard = load(HERE / 'entry-current-check-guard.py')
    entry = {}
    for identifier in ENTRY_CHECKS:
        material, pointer = guard.retained(index, root, KNOWLEDGE, definitions[identifier], source_sha)
        inputs.retain(material)
        entry[identifier] = pointer

    flow = inputs.pointer(context['version_flow'], root / 'knowledge/native-version-result-flow-checks')
    check = inputs.pointer(context['version_flow_check'], root / 'knowledge/check-results')
    definition = check['definition']
    flow_check = definitions['native-version-result-handler-context']
    effective = index.extension('research-workflow').source_definition(flow_check, source_sha)
    if (check['state'] != 'passed' or definition['check'] != effective
            or definition['source_sha256'] != source_sha or flow['source_sha256'] != source_sha
            or flow.get('recipe') != 'version-result-flow-v1' or flow.get('runtime_admitted') is not False
            or flow.get('network_used') is not False or len(flow.get('cases', [])) != 16
            or flow.get('context_sha256') != check.get('version_flow_guard', {}).get('context_sha256')
            or not all(flow.get(flag) is True for flag in ('native_input', 'native_gate', 'native_handler', 'login_prepare_captured'))):
        raise ValueError('Candidate game VersionResult composition differs')
    if definition['python_version'] != platform.python_version() or definition['executable'] != sys.executable:
        raise ValueError('Candidate game VersionResult Python runtime differs')
    distributions = importlib.metadata.distributions(path=[str(WORKSPACE / 'phone-exit/.tools/vampir-analysis')])
    runtime = {item.metadata['Name'].lower(): dict(version=item.version,
        record_sha256=hashlib.sha256((item.read_text('RECORD') or '').encode()).hexdigest())
        for item in distributions if item.metadata['Name'].lower() in definition['runtime_metadata']}
    if runtime != definition['runtime_metadata']:
        raise ValueError('Candidate game VersionResult native runtime differs')
    # The reviewed selected definition already matches the current registry.
    # Registry/dispatcher changes only affect orchestration of this saved result.
    # Freeze the current copies and preserve all other proof inputs byte for byte.
    controls = {KNOWLEDGE / 'research-checks.json', HERE / 'tooling-check-dispatch-v1.py'}
    for name, expected in definition['inputs'].items():
        path = Path(name).resolve()
        inputs.pin(path, None if path in controls else expected)
    inputs.retain(definition['artifacts'])
    for artifact in flow['evidence']:
        inputs.pin(artifact['path'], artifact['sha256'])

    game = resource(inputs, root, installed, context['resource_config'], source_sha)
    game['compiled_tag'] = tag['tag']
    for path in (Path(__file__), sdk_path, HERE / 'knowledge/update-contracts.json',
                 HERE / 'research-workflow.py', HERE / 'build-native-entry-code.py', HERE / 'audit-launcher-shape-11318.py',
                 WORKSPACE / 'phone-exit/bots/vampir-shared/vampir_core/sdk_config.py'):
        inputs.pin(path)
    inputs.barrier()
    return dict(schema=1, recipe=RECIPE, source_sha256=source_sha, source=str(installed),
        game_profile=game, compiled_tag_binding=tag, scopes=sorted(bridge['scopes']), lobby_shapes=lobby,
        entry_proofs=entry, inputs=inputs.files, sdk_profile=context['sdk'], bridges=context['bridges'],
        version_flow=context['version_flow'], version_flow_check=context['version_flow_check'],
        runtime_admitted=False, network_ready=False, live_verified=False, profile_activated=False,
        blockers=['current-lobby-runtime-composition', 'current-character-selection-and-world-runtime',
                  'current-viper-creation-admission'],
        limits=['Recovered base INI only; active engine config precedence is outside scope.',
                'Retained fixture boundaries remain in the component reports.',
                'Offline candidate assembly does not grant a network operation.'])


def verify_report(path, expected, *, root=ROOT, installed=None):
    root = Path(root).resolve()
    index = load(HERE / 'knowledge-index.py')
    installed = Path(installed or index.INSTALL).resolve()
    inputs = Inputs()
    value = inputs.pointer(dict(path=str(path), sha256=expected), root / 'game-source-candidates-current')
    if (value.get('schema') != 1 or value.get('recipe') != RECIPE
            or Path(value['source']).resolve() != installed
            or set(value['entry_proofs']) != set(ENTRY_CHECKS) or len(value['scopes']) != 7
            or not value.get('blockers') or any(value.get(key) is not False for key in
                ('runtime_admitted', 'network_ready', 'live_verified', 'profile_activated'))
            or value['inputs'].get(str(installed)) != value['source_sha256']
            or value['inputs'].get(str(Path(__file__).resolve())) != digest(__file__)):
        raise ValueError('Current offline candidate boundary differs')
    inputs.retain(value['inputs'])
    return value


def publish(context=CONTEXT, *, root=ROOT):
    root = Path(root).resolve()
    value = build(context, root=root)
    path = load(HERE / 'audit-client-release.py').save_snapshot(root / 'game-source-candidates-current', value)
    return path, digest(path), value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--context', type=Path, default=CONTEXT)
    parser.add_argument('--check', help='Check an existing offline candidate by full SHA')
    args = parser.parse_args()
    if args.check:
        if not SHA.fullmatch(args.check):
            parser.error('--check requires a full SHA256')
        path = args.root / 'game-source-candidates-current' / args.check / 'manifest.json'
        result = verify_report(path, args.check, root=args.root)
        sha = args.check
    else:
        path, sha, result = publish(args.context, root=args.root)
    print(json.dumps(dict(report=str(path), sha256=sha, inputs=len(result['inputs']),
                          version=result['game_profile']['app_version'], blockers=result['blockers'])))
