"""Verify saved public SDK response offline; never write plaintext constants/key."""
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / 'vampir-shared'))
from vampir_core.gmc2_response import decode_gmc2_configuration
from vampir_core.sdk_config import lookup_sdk_url_value

ROOT = Path('F:/PhoneExit Resources/Vampir')
SNAPSHOT = 'b18141355f468fda8e654da37927f9323bf59ee5018f1fd00b1326eed6aae1f1'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build():
    path = ROOT / 'public-gmc2-snapshots' / SNAPSHOT / 'manifest.json'
    raw = path.read_bytes()
    if digest(raw) != SNAPSHOT:
        raise ValueError('Public GMC2 manifest changed')
    report = json.loads(raw)
    body = (path.parent / 'body.bin').read_bytes()
    if report['transport']['status'] != 200 or digest(body) != report['body_sha256']:
        raise ValueError('Public GMC2 success body changed')
    configuration = decode_gmc2_configuration(body, report['transport']['headers'])
    constants = dict(configuration.constants)
    modules = ('gmc2_response.py', 'gmc2_decode.py', 'sdk_secret.py', 'sdk_constants.py', 'sdk_config.py', 'cdn_config.py')
    hashes = {name: digest((HERE.parent.parent / 'vampir-shared/vampir_core' / name).read_bytes()) for name in modules}
    fields = [name for name in ('authTokenUrl', 'authAccountUrl', 'authUrl', 'emailAuthUrl', 'emailAuthTokenUrl', 'emailAuthViewUrl')
              if lookup_sdk_url_value(constants, name) is not None]
    canonical = json.dumps(constants, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return dict(schema_version=1, snapshot_sha256=SNAPSHOT, body_sha256=report['body_sha256'],
        tool_sha256=digest(Path(__file__).read_bytes()), runtime_sha256=hashes,
        normal_count=configuration.normal_count, secret_count=configuration.secret_count,
        merged_count=len(constants), constants_sha256=digest(canonical), available_auth_url_keys=fields,
        deckey_observed_in_http_response=True, plaintext_constants_saved=False,
        native_response_method_identity_verified=False, native_full_callback_verified=False,
        account_authentication_attempted=False, network_ready=False)


if __name__ == '__main__':
    report = build()
    target = ROOT / 'code-clues/public-gmc2-decoded.json'
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), sha256=digest(target.read_bytes()),
        normal_count=report['normal_count'], secret_count=report['secret_count'], merged_count=report['merged_count'],
        auth_url_fields=len(report['available_auth_url_keys']), network_ready=False), indent=2))
