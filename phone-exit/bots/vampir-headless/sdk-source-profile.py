"""Load the explicit current SDK profile; no analysis tools or fallback to old evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')
RELEASE_PROFILE_SHA = 'd4b562f9f774833843ddf08f7b867c0ae732dff6fb46ee29b4ba2ad9fcb027be'
RELEASE_SOURCE_SHA = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'


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
