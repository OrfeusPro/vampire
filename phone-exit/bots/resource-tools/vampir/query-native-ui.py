"""Find a known widget's source variants and verified native references offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))


def select(report, query):
    paths = sorted(path for path in report['resources']
                   if path == query or path.rsplit('/', 1)[-1] == query)
    if not paths:
        raise ValueError('No exact indexed widget path/name: ' + query)
    return [dict(path=path, resources=report['resources'][path],
                 references=[row for row in report['references'] if row['literal']['canonical_path'] == path],
                 unresolved_candidates=[row for row in report['unresolved_candidates'] if row['literal']['canonical_path'] == path],
                 runtime_binding_verified=False) for path in paths]


def verify_sources(report, selected, directory):
    exe = Path(report['source'])
    if hashlib.sha256(exe.read_bytes()).hexdigest() != report['sha256']:
        raise ValueError('Executable changed; regenerate native UI index')
    if hashlib.sha256((directory / 'index.json').read_bytes()).hexdigest() != report['catalog_sha256']:
        raise ValueError('Catalog index changed; regenerate native UI index')
    for item in selected:
        for variant in item['resources']:
            path = directory / variant['catalog_file']
            if hashlib.sha256(path.read_bytes()).hexdigest() != variant['catalog_sha256']:
                raise ValueError('Widget catalog changed: ' + variant['catalog_file'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('widget', help='Exact WBP name or full /Game path')
    parser.add_argument('--full', action='store_true', help='Include contexts and source metadata')
    args = parser.parse_args()
    report = json.loads((ROOT / 'code-clues/native-ui-links.json').read_text(encoding='utf-8'))
    selected = select(report, args.widget)
    verify_sources(report, selected, ROOT / 'ui-catalog')
    if not args.full:
        selected = [dict(path=item['path'],
            variants=[dict(file=row['catalog_file'], entry=row['entry'], popup=row['popup']) for row in item['resources']],
            references=[dict(address=hex(row['instruction']['address']), root_rva=hex(row['root_begin_rva']),
                             literal_offset=row['literal']['file_offset']) for row in item['references']],
            unresolved_candidates=len(item['unresolved_candidates']), runtime_binding_verified=False) for item in selected]
    print(json.dumps(selected, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
