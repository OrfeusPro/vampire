"""Load the explicit current SDK profile; no analysis tools or fallback to old evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')
RELEASE_PROFILE_SHA = 'dd77f0c13f54949999b96de3c753dde608a8521087d83c80de5bbbc5a726c582'
RELEASE_SOURCE_SHA = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


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
    with Path(report['source']).open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != RELEASE_SOURCE_SHA:
            raise ValueError('Installed SDK source changed; refresh profile evidence')
    return dict(report[kind], source=report['source'], source_sha256=RELEASE_SOURCE_SHA,
                sha256=RELEASE_SOURCE_SHA, profile_sha256=RELEASE_PROFILE_SHA,
                active_runtime_settings_verified=False)
