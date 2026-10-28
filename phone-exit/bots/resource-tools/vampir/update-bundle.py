"""Publish source-bound offline bundles for the next explicit launch; no game actions."""
import json
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'vampir-shared'))
from vampir_core import release_bundle
from vampir_core.sdk_config import prepare_cdn_config_url_ascii


def _read_va(raw, address, size):
    """Minimal PE32+ data reader; runtime admission never loads disassemblers."""
    pe = struct.unpack_from('<I', raw, 0x3c)[0]
    if raw[:2] != b'MZ' or raw[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', raw, pe+24)[0] != 0x20b:
        raise ValueError('Prepared tag requires a PE32+ image')
    count, optional = struct.unpack_from('<H', raw, pe+6)[0], struct.unpack_from('<H', raw, pe+20)[0]
    base = struct.unpack_from('<Q', raw, pe+48)[0]
    rva = address - base
    for number in range(count):
        section = pe + 24 + optional + number * 40
        va, length, offset = struct.unpack_from('<III', raw, section+12)
        if va <= rva and rva + size <= va + length:
            start = offset + rva - va
            if 0 <= start <= len(raw) - size:
                return raw[start:start+size]
    raise ValueError('Prepared tag data is outside file-backed sections')


def _config(index, args, audit):
    sha = audit['exe']['sha256']
    archives = {str(Path(r['path']).resolve()): r['current']['sha256'] for r in audit['files'] if r.get('current')}
    candidates = []
    for path in sorted((args.root / 'resource-config-snapshots').glob('*/manifest.json')):
        if index.digest(path) != path.parent.name:
            continue
        value = index.read_json(path)
        if value.get('exe_sha256') != sha:
            continue
        source = str(Path(value['source_archive']['path']).resolve())
        if archives.get(source) != value.get('archive_sha256'):
            continue
        ini = [c for c in value.get('configs', []) if c.get('snapshot_file') == 'DefaultGame.ini']
        if len(ini) == 1:
            candidates.append((path, value, ini[0]))
    # Identical recovered content from duplicate immutable receipts is harmless.
    unique = {}
    for path, value, config in candidates:
        unique.setdefault((value['archive_sha256'], config['payload_sha256']), (path, value, config))
    if len(unique) != 1:
        raise ValueError('Missing or ambiguous source-bound game configuration')
    path, value, config = next(iter(unique.values()))
    ini = path.parent / 'DefaultGame.ini'
    if index.digest(ini) != config['payload_sha256']:
        raise ValueError('Prepared game INI changed')
    lines = ini.read_text('utf-8-sig').splitlines()
    values = {}
    for row in config['values']:
        if row['section'] != 'NetworkSetting':
            continue
        key, separator, actual = lines[row['line']-1].strip().partition('=')
        if not separator or (key.strip(), actual.strip()) != (row['key'], row['value']) or row['key'] in values:
            raise ValueError('Prepared INI row provenance differs')
        values[row['key']] = row['value']
    if values.get('CdnConfig') != 'True':
        raise ValueError('Prepared game configuration has no CDN config')
    url = prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'], qa=values['CdnConfigUrlQA'],
        prefix=values['ConfigPrefix'], app_version=values['AppVersion'], platform_code=2)
    game = dict(config_snapshot_sha256=path.parent.name, app_version=values['AppVersion'],
        config_prefix=values['ConfigPrefix'], cdn_url='https://' + url)
    artifacts = {str(path): index.digest(path), str(ini): index.digest(ini),
        str(Path(value['source_archive']['path']).resolve()): value['archive_sha256']}
    return game, artifacts


def _sdk(index, workflow, args, profiles, sha):
    candidates = {}
    for item in profiles:
        path = Path(item['profile']).resolve()
        if not path.is_relative_to(args.root.resolve() / 'knowledge/prepared-profiles'):
            raise ValueError('Prepared SDK profile outside library')
        package = workflow.checked_manifest(index, path)
        profile = package.get('profile', {})
        if (package.get('source_sha256') == sha and package.get('state') == 'prepared_offline'
                and profile.get('source_sha256') == sha and profile.get('runtime_scope') == 'sdk-launcher-auth'):
            candidates[index.digest(path)] = (path, profile)
    if len(candidates) != 1:
        raise ValueError('Missing or ambiguous verified SDK profile builder result')
    return next(iter(candidates.values()))


def prepare(index, args, contracts, outcomes, capabilities, profiles, contexts, audit):
    workflow = index.extension('research-workflow')
    workspace = HERE.parents[3]
    specs = {c['id']: c for c in contracts['contracts']}
    sha = audit['exe']['sha256']
    result = dict(bundles=[], next_profiles={}, queue=[], live_verified=False)
    for capability, readiness in capabilities.items():
        if readiness.get('state') != 'prepared_offline':
            continue
        try:
            required = set(contracts['capabilities'][capability]['requires'])
            while True:
                expanded = required | {d for name in required for d in specs[name]['depends_on']}
                if expanded == required:
                    break
                required = expanded
            rules = {str(HERE / name): index.digest(HERE / name) for name in (
                'update-bundle.py', 'update-profile.py', 'update-contracts.py', 'research-workflow.py',
                'knowledge/update-contracts.json', 'knowledge/research-checks.json')}
            rules[str(Path(release_bundle.__file__).resolve())] = index.digest(Path(release_bundle.__file__))
            artifacts = {}

            def pin(filename, expected=None):
                path = Path(filename).resolve()
                actual = index.digest(path)
                if expected is not None and actual != expected:
                    raise ValueError('Prepared evidence artifact changed')
                if str(path) in artifacts and artifacts[str(path)] != actual:
                    raise ValueError('Prepared evidence artifacts conflict')
                artifacts[str(path)] = actual

            def evidence(value):
                if isinstance(value, dict):
                    if isinstance(value.get('path'), str) and isinstance(value.get('sha256'), str):
                        path = Path(value['path'])
                        if path.is_file():
                            pin(path, value['sha256'])
                    if isinstance(value.get('archive'),str) and isinstance(value.get('sha256'),str):
                        pin(value['archive'],value['sha256'])
                    for child in value.values():
                        evidence(child)
                elif isinstance(value, list):
                    for child in value:
                        evidence(child)

            selected = {}
            tag_bindings = []
            for name in sorted(required):
                c, outcome = specs[name], outcomes[name]
                if c['coverage'] != 'source_checks' or outcome['state'] != 'passed':
                    raise ValueError('Required contract is incomplete: ' + name)
                cp = Path(outcome['context']).resolve()
                pin(cp)
                context = workflow.checked_manifest(index, cp)
                evidence(context)
                checks = outcome['checks']
                for check in checks:
                    if check.get('state') != 'passed':
                        raise ValueError('Required semantic check is incomplete')
                    path = Path(check['report'])
                    pin(path, check['sha256'])
                    proof = workflow.checked_manifest(index, path)
                    definition = proof.get('definition', {})
                    for group in ('inputs', 'artifacts'):
                        for filename, expected in definition.get(group, {}).items():
                            # CRT is validated by the shared admission checker, not a public-library artifact.
                            if group == 'artifacts' and not Path(filename).resolve().is_relative_to(args.root.resolve()):
                                continue
                            pin(filename, expected)
                    evidence(proof.get('evidence', []))
                    if check['id'] in ('version-login-tag', 'packet-writer-projection'):
                        module = 'verify-version-login-context.py' if check['id'] == 'version-login-tag' else 'verify-packet-writer-context.py'
                        for tool in (module, 'update-native-harness.py', 'update-bindings.py', 'build-native-entry-code.py'):
                            rules[str(HERE / tool)] = index.digest(HERE / tool)
                    if check['id'] == 'version-login-tag':
                        tag_bindings.append(proof['binding'])
                selected[name] = dict(state='passed', context=dict(path=str(cp), sha256=index.digest(cp)), checks=checks)
            bundle = dict(schema=1, capability=capability, source_sha256=sha,
                source=str(Path(audit['exe']['path']).resolve()), install=str(args.install.resolve()),
                state='prepared_offline', function_verified=True, semantic_passed=True,
                live_verified=False, runtime_activated=False, contracts=selected, rules=rules, artifacts=artifacts,
                limits=['Source-bound offline contract checks only; live entry remains unverified.'])
            if capability in ('launcher', 'world-session'):
                sdk_path, sdk_profile = _sdk(index, workflow, args, profiles, sha)
                pin(sdk_path)
                evidence(sdk_profile.get('evidence', {}))
                bundle['sdk_profile'] = sdk_profile
                bundle['sdk_profile_receipt'] = dict(path=str(sdk_path), sha256=index.digest(sdk_path))
            if capability == 'world-session':
                from vampir_core.runtime_admission import descriptor
                bundle['runtime_adapter'] = descriptor(workspace)
                for filename, expected in bundle['runtime_adapter']['consumers'].items():
                    rules[str((workspace / filename).resolve())] = expected
                game, config_artifacts = _config(index, args, audit)
                artifacts.update(config_artifacts)
                tags = {b.get('tag') for b in tag_bindings}
                if len(tags) != 1 or not tag_bindings or not re.fullmatch('[0-9A-F]{32}', next(iter(tags)) or ''):
                    raise ValueError('Missing or conflicting native Version/Login tag proof')
                raw = Path(audit['exe']['path']).read_bytes()
                for binding in tag_bindings:
                    pointer = int.from_bytes(_read_va(raw, int(binding['pointer'], 16), 8), 'little')
                    if pointer != int(binding['literal'], 16) or _read_va(raw, pointer, 33) != (binding['tag'] + '\0').encode('ascii'):
                        raise ValueError('Prepared compiled tag differs from native proof')
                game['compiled_tag'] = next(iter(tags))
                bundle['game_profile'] = game
            path = workflow.snapshot(args.root, 'prepared-bundles', bundle)
            release_bundle.validate(root=args.root, workspace=workspace,
                selected='prepared:' + path.parent.name, capability=capability)
            result['bundles'].append(dict(capability=capability, path=str(path), sha256=path.parent.name))
        except (OSError, ValueError, KeyError, StopIteration, struct.error) as error:
            result['queue'].append(dict(contract=None, capability=capability,
                reason='Prepared bundle rejected: ' + str(error),
                next_check='Resolve this source-bound bundle prerequisite; active sessions are unchanged'))
    return result


def publish(index,args,result,*,tooling_checks=()):
    """Called only after the coordinator's final frozen-input validation."""
    failed=[c['id'] for c in tooling_checks if c.get('state')!='passed']
    if failed:
        if result['bundles']:
            result['queue'].append(dict(contract=None,capability='admission',
                reason='Infrastructure checks block next-profile publication: '+', '.join(failed),
                next_check='Fix the failed registered tooling checks and resume'))
        return result
    workflow=index.extension('research-workflow')
    for item in result['bundles']:
        bundle=release_bundle.validate(root=args.root,workspace=HERE.parents[3],
            selected='prepared:'+item['sha256'],capability=item['capability'])
        pointer=args.root/'knowledge/next-profiles'/(item['capability']+'.json')
        workflow.atomic(pointer,workflow.canonical(dict(schema=1,capability=item['capability'],
            source_sha256=bundle['source_sha256'],bundle_sha256=item['sha256'],live_verified=False)))
        result['next_profiles'][item['capability']]=str(pointer)
    return result
