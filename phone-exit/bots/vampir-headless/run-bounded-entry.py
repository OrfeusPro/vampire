"""One current launcher/lobby/game entry through the fresh character list."""
import argparse
from datetime import datetime, timezone
from functools import partial
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.bot_device_settings import validate, route_port
from vampir_core.bounded_entry_admission import scope, current
from vampir_core.patch_revision import parse_patch_client_revision
from vampir_core.socks_route import SocksRoute


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(account_id, selector, *, progress=lambda stage: None, _creation_factory=None):
    store = AccountStore(HERE / '.local/console.sqlite3')
    account = next((row for row in store.accounts() if row['id'] == account_id), None)
    if account is None or account['enabled'] is not True or account['device_type'] == 'Не использовать':
        raise ValueError('Expected an enabled account')
    email, password, settings = store.credential(account_id)
    if settings['server_id'] is None or settings['auth_flow'] != 'launcher':
        raise ValueError('Expected an assigned server and launcher authentication')
    device = validate(settings.get('device_settings'))
    port = route_port(settings['socks_port'])
    with scope(selector, root=ROOT, workspace=HERE.parents[2]):
        profile = current(selector)
        if _creation_factory is not None:
            from vampir_core.bounded_creation_admission import current as creation_current
            creation = creation_current()
            if creation['entry']['selected_profile'] != selector or not callable(_creation_factory):
                raise ValueError('Current creation requires its exact entry parent and explicit factory')
        progress('cdn')
        cdn = load('bounded_public_cdn', HERE.parent / 'resource-tools/vampir/fetch-public-cdn-config.py')
        provenance = cdn.profile(selector)
        body, transport = cdn.fetch(provenance['url'], route=SocksRoute(port) if port is not None else None)
        transport['socks5_loopback_port'] = port
        report = dict(profile=provenance, transport=transport, body_sha256=cdn.digest(body),
            body_bytes=len(body), fetched_utc=datetime.now(timezone.utc).isoformat(), analysis=cdn.analyze(body))
        manifest, _ = cdn.save(report, body)
        revision_path = Path(profile['source']).parents[2] / 'Saved/PersistentDownloadDir/Patch/windows.manifestlist'
        revision = parse_patch_client_revision(revision_path.read_bytes())
        def verify(prepared, data):
            tool = load('bounded_account_verification', HERE / 'verify-account.py')
            mail_password = store.mail_credential(account_id) if data.verification_steps else None
            try:
                status, _ = tool.continue_verification(email=email, settings=settings,
                    prepared=prepared, data=data, mail_password=mail_password, progress=progress)
            finally:
                mail_password = None
            if status != 'verified':
                raise tool.VerificationStopped(status)
            return status
        tool = load('bounded_selected_game_login', HERE / 'probe-selected-game-login.py')
        tool.exchange_game_login = partial(tool.exchange_game_login, expose_character_labels=True)
        result = tool.run(email, selected_profile=selector, manifest_path=manifest, socks_port=port,
            server_policy_byte=0, extra_number=revision, context='windows-sdk-initial-reset',
            region=settings['region'], server_id=settings['server_id'], password=password,
            auth_flow='launcher', language_code=1, lobby_context='sdk-with-partial-metadata',
            read_character_list=True, device_settings=device, _progress=progress, _verification=verify,
            creation_factory=_creation_factory)
        password = None
        game = result.get('game', {})
        if (_creation_factory is None and game.get('character_list_received') is True and game.get('character_list_result_code') == 0
                and type(game.get('characters')) is list):
            store.save_characters(account_id, region=settings['region'], server_id=settings['server_id'],
                characters=game['characters'], observed_utc=datetime.now(timezone.utc).isoformat())
        return dict(account_id=account_id, selected_profile=selector, source_sha256=profile['source_sha256'],
                    completed_utc=datetime.now(timezone.utc).isoformat(), result=result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--profile', required=True, help='bounded-entry:<полный SHA пакета>')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def progress(stage):
        print(json.dumps(dict(stage=stage)), flush=True)
    try:
        result = run(args.account, args.profile, progress=progress)
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        result = dict(account_id=args.account, selected_profile=args.profile,
                      status='bounded_entry_not_completed', error_type=type(error).__name__)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
