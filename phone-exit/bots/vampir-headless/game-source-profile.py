"""Explicit recovered-base profile for our client; not the game's active cache."""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.sdk_config import prepare_cdn_config_url_ascii
from vampir_core.login_context import bind_game_app_version

ROOT = Path('F:/PhoneExit Resources/Vampir')
SNAPSHOT = '393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db'
SOURCE_SHA = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


@dataclass(frozen=True, slots=True)
class BaseGameProfile:
    app_version: str
    config_prefix: str
    cdn_url: str
    source_snapshot_sha256: str
    active_game_cache_verified: bool = False


def verify_file(path, expected):
    with Path(path).open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != expected: raise ValueError('Game profile source changed; refresh extracted evidence')


def load_profile(*, selected_profile, root=ROOT):
    if selected_profile != 'recovered-base': raise ValueError('Select the recovered-base profile explicitly')
    path = Path(root) / 'resource-config-snapshots' / SNAPSHOT / 'manifest.json'
    if path.stat().st_size > 2097152: raise ValueError('Game profile manifest exceeds local budget')
    verify_file(path, SNAPSHOT)
    manifest = json.loads(path.read_text('utf-8'))
    if manifest['exe_sha256'] != SOURCE_SHA: raise ValueError('Unsupported game client source')
    verify_file(manifest['source_exe'], SOURCE_SHA)
    verify_file(manifest['source_archive']['path'], manifest['archive_sha256'])
    config = next(config for config in manifest['configs'] if config['snapshot_file'] == 'DefaultGame.ini')
    ini = path.parent / 'DefaultGame.ini'
    verify_file(ini, config['payload_sha256'])
    lines = ini.read_text('utf-8-sig').splitlines()
    values = {}
    for row in config['values']:
        if row['section'] != 'NetworkSetting': continue
        line = lines[row['line'] - 1].strip()
        key, separator, value = line.partition('=')
        if not separator or (key.strip(), value.strip()) != (row['key'], row['value']):
            raise ValueError('INI row provenance differs')
        if row['key'] in values: raise ValueError('Ambiguous recovered NetworkSetting')
        values[row['key']] = row['value']
    if values['CdnConfig'] != 'True': raise ValueError('Explicit base profile has no CDN config')
    url = prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'], qa=values['CdnConfigUrlQA'],
        prefix=values['ConfigPrefix'], app_version=values['AppVersion'], platform_code=2)
    return BaseGameProfile(values['AppVersion'], values['ConfigPrefix'], 'https://' + url, SNAPSHOT)


def bind_profile(version, login, *, selected_profile, root=ROOT):
    profile = load_profile(selected_profile=selected_profile, root=root)
    version, login = bind_game_app_version(version, login, app_version=profile.app_version)
    return version, login, profile


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', choices=['recovered-base'], required=True)
    parser.add_argument('--check', action='store_true', required=True)
    args = parser.parse_args()
    try:
        profile = load_profile(selected_profile=args.profile)
        print(json.dumps(dict(profile=args.profile, app_version=profile.app_version,
            config_prefix=profile.config_prefix, source_snapshot_sha256=profile.source_snapshot_sha256,
            active_game_cache_verified=False, network_attempted=False)))
    except (OSError, ValueError, KeyError, StopIteration, IndexError):
        print(json.dumps(dict(error='source_profile_not_verified')))
        sys.exit(2)
