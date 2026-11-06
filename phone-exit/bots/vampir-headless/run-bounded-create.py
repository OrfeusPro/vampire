"""One durable current Viper creation attempt, then a separate fresh list."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore
from vampir_core.bounded_creation_admission import scope, current
from vampir_core.character_create import CharacterCreatePayload, encode_character_create


def load_entry():
    spec = importlib.util.spec_from_file_location('create_parent_entry', HERE / 'run-bounded-entry.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(account_id, selector, *, progress=lambda stage: None):
    store = AccountStore(HERE / '.local/console.sqlite3')
    attempt = None
    with scope(selector, root=ROOT, workspace=HERE.parents[2]):
        profile = current(selector)
        template = profile['payload_template']
        source = profile['source_sha256']
        # Device/auth credentials stay inside the existing parent entry path.
        settings = next((row for row in store.accounts() if row['id'] == account_id), None)
        if settings is None:
            raise ValueError('Unknown current creation account')
        if (settings['create_class'] != 'DarkMage' or settings['character_key'] is not None
                or settings['character_index'] is not None or settings['server_id'] is None):
            raise ValueError('Current creation requires an unassigned Viper account')

        def prepare(characters):
            nonlocal attempt
            if characters.result_code != 0 or characters.records or attempt is not None:
                raise ValueError('Current creation requires one accepted fresh empty list')
            store.save_characters(account_id, region=settings['region'], server_id=settings['server_id'],
                characters=[], observed_utc=datetime.now(timezone.utc).isoformat())
            nickname = store.creation_nickname(account_id, region=settings['region'], server_id=settings['server_id'])
            payload = CharacterCreatePayload(template['raw_class'], nickname, tuple(template['appearance']),
                template['appearance_text'], tuple(template['raw_flags']), tuple(tuple(row) for row in template['items']))
            encode_character_create(payload, source_sha256=source)
            attempt = store.begin_creation(account_id, region=settings['region'], server_id=settings['server_id'],
                nickname=nickname, source_sha256=source)
            progress('character_creation')
            return payload

        entry = load_entry()
        try:
            result = entry.run(account_id, profile['entry']['selected_profile'], progress=progress,
                               _creation_factory=prepare)
            game = result.get('result', {}).get('game', {})
            if attempt is not None:
                state = game.get('character_creation_state', 'unknown')
                store.finish_creation(attempt, state=state if state in
                    ('created', 'rejected', 'needs_refresh', 'not_queued') else 'unknown',
                    result_code=game.get('character_creation_result_code'),
                    key=game.get('created_character_key'), name=game.get('created_character_name'))
        finally:
            if attempt is not None:
                store.finish_creation(attempt, state='unknown')
        # Never send another Create here, including a rejected/unknown outcome.
        # The separate accepted list can resolve and assign a returned identity.
        refresh = None
        if attempt is not None:
            progress('character_list_refresh')
            refresh = entry.run(account_id, profile['entry']['selected_profile'], progress=progress)
            game = refresh.get('result', {}).get('game', {})
            if game.get('character_list_received') is True and game.get('character_list_result_code') == 0:
                store.reconcile_creation(account_id, region=settings['region'], server_id=settings['server_id'])
        return dict(account_id=account_id, selected_profile=selector, attempt_recorded=attempt is not None,
                    creation=result, refresh=refresh, world_entered=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def progress(stage):
        print(json.dumps(dict(stage=stage)), flush=True)
    try:
        result = run(args.account, args.profile, progress=progress)
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        result = dict(account_id=args.account, selected_profile=args.profile,
                      status='bounded_creation_not_completed', error_type=type(error).__name__)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
