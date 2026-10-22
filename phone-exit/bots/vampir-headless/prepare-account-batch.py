"""Prepare encrypted local accounts and server assignments; no external actions."""
import argparse
import collections
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.account_store import AccountStore

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--store', type=Path, default=HERE / '.local/console.sqlite3')
    parser.add_argument('--batch', required=True)
    parser.add_argument('--region', default='EU', choices=['EU', 'NA', 'SG', 'JP', 'TW', 'ASIA', 'KR'])
    parser.add_argument('--minimum-new', type=int, default=24)
    args = parser.parse_args()
    store = AccountStore(args.store)
    batch = store.prepare_batch(args.batch, region=args.region, minimum_new=args.minimum_new)
    accounts = [a for a in store.accounts() if a['id'] in batch['account_ids']]
    print(json.dumps(dict(prepared_only=True, mailboxes_created=False, registration_started=False,
        accounts=len(accounts), per_server=dict(collections.Counter(a['server_id'] for a in accounts)),
        passwords_saved_encrypted=True)))
