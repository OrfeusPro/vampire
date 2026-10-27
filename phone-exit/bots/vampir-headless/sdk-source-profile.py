"""Load the explicit current SDK profile; no analysis tools or fallback to old evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')
RELEASE_PROFILE_SHA = '4c8057b367524bc26e226088f5f5ef790309f82b8c81af90ffd7e829acdcd4d2'
RELEASE_SOURCE_SHA = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'


def load_release_profile(kind, *, root=ROOT):
    if kind not in ('public_gmc2', 'nid'):
        raise ValueError('Unsupported SDK profile section')
    path = Path(root) / 'sdk-source-profiles' / RELEASE_PROFILE_SHA / 'manifest.json'
    if path.stat().st_size > 1048576:
        raise ValueError('SDK profile manifest exceeds budget')
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != RELEASE_PROFILE_SHA:
        raise ValueError('Release SDK source profile changed')
    report = json.loads(payload)
    if report['name'] != 'recovered-release' or report['source_sha256'] != RELEASE_SOURCE_SHA:
        raise ValueError('Release SDK profile/source mismatch')
    if (report.get('runtime_scope') != 'sdk-launcher-auth' or
            report.get('supported_auth_flows') != ['launcher'] or
            any(report.get(key) is not False for key in
                ('network_ready', 'game_protocol_verified', 'direct_sdk_operations_verified'))):
        raise ValueError('Release SDK runtime scope mismatch')
    with Path(report['source']).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != RELEASE_SOURCE_SHA:
            raise ValueError('Installed SDK source changed; refresh profile evidence')
    return dict(report[kind], source=report['source'], source_sha256=RELEASE_SOURCE_SHA,
                sha256=RELEASE_SOURCE_SHA, profile_sha256=RELEASE_PROFILE_SHA,
                active_runtime_settings_verified=False)
