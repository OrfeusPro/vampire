"""Build/query one address-keyed index of exported functions and existing notes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
KNOWLEDGE = HERE / 'knowledge'
OUTPUT = ROOT / 'knowledge/function-registry.json'
ADDRESS = re.compile(r'(?<![A-Za-z0-9_])(?:0x)?(1[0-9a-fA-F]{8})(?![A-Za-z0-9_])', re.I)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def documents():
    return sorted(set(HERE.glob('*.md')) | set(KNOWLEDGE.rglob('*.md')) | set((HERE.parents[1] / 'vampir').glob('*.md')) |
                  set((HERE.parents[1] / 'vampir-headless').glob('*.md')) |
                  set((HERE.parents[1] / 'vampir-shared').glob('*.md')))


def checked_source(installed, expected_sha, snapshot=None):
    source = Path(snapshot) if snapshot is not None else Path(installed)
    if digest(source) != expected_sha:
        raise ValueError('Source digest mismatch' if snapshot is not None else
                         'Installed client changed; old registry is historical')
    return source


def build(source_snapshot=None):
    ghidra = ROOT / 'ghidra'
    latest_path = ghidra / 'latest-export.json'
    latest = json.loads(latest_path.read_text('utf-8'))
    folder = Path(latest['output'])
    report_path = folder / 'functions.json'
    if digest(report_path) != latest['report_sha256']:
        raise ValueError('Latest Ghidra report hash mismatch')
    report = json.loads(report_path.read_text('utf-8'))
    provenance_path = folder / 'provenance.json'
    provenance = json.loads(provenance_path.read_text('utf-8'))
    manifest_path = ghidra / 'entry-manifest.json'
    if digest(manifest_path) != provenance['manifest_sha256']:
        raise ValueError('Re-export Ghidra after manifest changes')
    manifest = json.loads(manifest_path.read_text('utf-8'))
    roles_path = KNOWLEDGE / 'function-roles.json'
    roles = json.loads(roles_path.read_text('utf-8'))
    questions_path = KNOWLEDGE / 'questions.json'
    questions = json.loads(questions_path.read_text('utf-8'))
    locations_path = KNOWLEDGE / 'document-locations.json'
    locations = json.loads(locations_path.read_text('utf-8'))
    navigation_topics = {}
    for entry in locations['documents']:
        path = (HERE.parents[3] / entry['current']).resolve()
        if not path.is_file():
            raise ValueError('Relocated document missing')
        if entry['topic'] != 'history':
            navigation_topics[str(path)] = entry['topic']
    for path in (KNOWLEDGE / 'evidence').glob('*/*.md'):
        navigation_topics[str(path.resolve())] = path.parent.name
    source_sha = report['source_sha256']
    if any(value != source_sha for value in (manifest['source_sha256'], roles['source_sha256'], questions['source_sha256'])):
        raise ValueError('Registry inputs belong to different client builds')
    source = checked_source(manifest['source'], source_sha, source_snapshot)
    expected = {f['address'].lower(): f['name'] for f in manifest['functions']}
    observed = {f['address'].lower(): f['name'] for f in report['functions']}
    if expected != observed or len(expected) != len(report['functions']):
        raise ValueError('Export inventory mismatch or duplicate addresses')
    inputs = {str(p): digest(p) for p in (latest_path, report_path, provenance_path, manifest_path, roles_path, questions_path, locations_path, Path(__file__))}
    records = {}
    for f in report['functions']:
        path = folder / f['pseudocode_file']
        if path.parent != folder or digest(path) != provenance['files'][path.name]:
            raise ValueError('Pseudocode provenance mismatch')
        inputs[str(path)] = digest(path)
        address = f['address'].lower()
        role = roles['roles'].get(address)
        if role and not (HERE / role['evidence']).is_file():
            raise ValueError('Role evidence document missing')
        records[address] = dict(address=address, analyst_name=f['name'],
            established_role=role, decompilation_completed=f['completed'],
            decompilation_message=f['message'], pseudocode=str(path),
            pseudocode_sha256=digest(path), references=[], callers=[], callees=[], questions=[])
    for address in roles['roles']:
        if address not in records:
            raise ValueError('Role refers to a function outside the current export')
    seen = set()
    for question in questions['questions']:
        if question['id'] in seen or question['status'] not in ('open', 'bounded_answer', 'blocked_experiment'):
            raise ValueError('Invalid question ID or status')
        seen.add(question['id'])
        for field in ('question', 'known', 'unknown', 'next_action', 'decision_rule', 'do_not_repeat'):
            if not isinstance(question[field], str) or not question[field].strip():
                raise ValueError('Missing question field: ' + field)
        for evidence in question['evidence']:
            target = (KNOWLEDGE / evidence).resolve()
            if not target.is_relative_to(HERE.resolve()) or not target.is_file():
                raise ValueError('Question evidence missing or outside resource tools')
        for address in question['addresses']:
            if address not in records:
                raise ValueError('Question refers to a function outside the export')
            records[address]['questions'].append(question['id'])
    documented_addresses = {}
    for path in documents():
        inputs[str(path)] = digest(path)
        for number, line in enumerate(path.read_text('utf-8-sig').splitlines(), 1):
            for address in {'0x' + m.group(1).lower() for m in ADDRESS.finditer(line)}:
                reference = dict(path=str(path), line=number, text=line.strip())
                if address in records:
                    records[address]['references'].append(reference)
                else:
                    # A documentation address can be data, a callsite or an
                    # unexported function. Preserve it without inventing a type.
                    if address not in documented_addresses:
                        documented_addresses[address] = dict(address=address,
                            analyst_name=None, established_role=None, pseudocode=None,
                            address_kind='documented_address_type_unverified',
                            references=[], callers=[], callees=[], questions=[])
                    documented_addresses[address]['references'].append(reference)
    edges = []
    for record in list(records.values()) + list(documented_addresses.values()):
        record['navigation_topics'] = sorted({navigation_topics[r['path']] for r in record['references']
                                              if r['path'] in navigation_topics})
    for function in report['functions']:
        caller = function['address'].lower()
        for call in function['calls']:
            for target in call.get('targets', []):
                if 'address' not in target:
                    continue
                callee = target['address'].lower()
                edge = dict(caller=caller, callsite=call['address'].lower(), callee=callee,
                            target_name=target.get('name'), target_exported=callee in records)
                edges.append(edge)
                records[caller]['callees'].append(edge)
                if callee in records:
                    records[callee]['callers'].append(edge)
    return dict(source=str(source), source_sha256=source_sha,
                source_scope='historical' if source_snapshot is not None else 'installed', export=str(folder),
                inputs=inputs, function_count=len(records), call_edge_count=len(edges),
                questions=questions['questions'],
                documented_addresses=sorted(documented_addresses.values(), key=lambda r: int(r['address'], 16)),
                functions=sorted(records.values(), key=lambda r: int(r['address'], 16)),
                limits=['Only selected exported functions, not every function in the EXE.',
                        'Address mention is a navigation reference, not proof of a role or executed branch.',
                        'Missing established_role means no curated claim; analyst names and decompilation are not proof.',
                        'Calls are Ghidra export edges; indirect and unexported targets are not a complete call graph.'])


def read_current():
    registry = json.loads(OUTPUT.read_text('utf-8'))
    for filename, sha in registry['inputs'].items():
        path = Path(filename)
        if not path.is_file() or digest(path) != sha:
            raise ValueError('Registry stale; run --build: ' + path.name)
    documented = {p for p in registry['inputs'] if p.endswith('.md')}
    if documented != {str(p) for p in documents()}:
        raise ValueError('Documentation inventory changed; run --build')
    if digest(Path(registry['source'])) != registry['source_sha256']:
        raise ValueError('Client changed; registry is historical')
    return registry


def query(registry, term):
    term = term.strip().lower()
    if not term:
        raise ValueError('Empty function search')
    if re.fullmatch(r'(?:0x)?1[0-9a-f]{8}', term):
        address = term if term.startswith('0x') else '0x' + term
        return [r for r in registry['functions'] + registry.get('documented_addresses', []) if r['address'] == address]
    return [r for r in registry['functions'] + registry.get('documented_addresses', []) if term in json.dumps(
        [r['analyst_name'], r['established_role'], r['references']], ensure_ascii=False).lower()]


def main():
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--query')
    parser.add_argument('--question', help='Stable question ID from knowledge/questions.json')
    parser.add_argument('--topic', help='Filter by evidence-document topic; navigation, not proof of function semantics')
    parser.add_argument('--source-snapshot', type=Path,
                        help='Explicit historical EXE with the exact export SHA; uses a separate historical registry')
    args = parser.parse_args()
    if args.source_snapshot is not None:
        latest = json.loads((ROOT / 'ghidra/latest-export.json').read_text('utf-8'))
        sha = latest['source_sha256']
        checked_source('', sha, args.source_snapshot)
        OUTPUT = ROOT / 'knowledge/historical' / sha / 'function-registry.json'
        print(json.dumps(dict(source_scope='historical', source_sha256=sha,
                              source_snapshot=str(args.source_snapshot)), ensure_ascii=False))
    if args.build:
        result = build(args.source_snapshot)
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        index = ['# Vampir — реестр исследованных функций', '',
                 f"SHA клиента: `{result['source_sha256']}`.", '',
                 'Историческая сборка; совместимость с установленной игрой не подтверждена.'
                 if args.source_snapshot is not None else 'Проверен SHA установленного клиента.', '',
                 f"Функций: {result['function_count']}; call edges из экспорта: {result['call_edge_count']}.", '',
                 'Это выбранный исследованный набор, не весь EXE. Поля и документы — в [JSON](function-registry.json).', '',
                 'Темы определяются документами-доказательствами; это навигация, не новая семантика функции.', '',
                 '| Адрес | Аналитическое имя | Уточнённая роль | Темы | Ссылок в документах |',
                 '| --- | --- | --- | --- | --- |']
        for row in result['functions']:
            role = row['established_role']
            index.append(f"| {row['address']} | [{row['analyst_name']}]({Path(row['pseudocode']).as_posix()}) | "
                         f"{role['role'] if role else 'Смотреть подробные references'} | "
                         f"{', '.join(row['navigation_topics'])} | {len(row['references'])} |")
        (OUTPUT.parent / 'INDEX.md').write_text('\n'.join(index) + '\n', encoding='utf-8')
        print(json.dumps(dict(path=str(OUTPUT), functions=result['function_count'],
                              edges=result['call_edge_count'], sha256=digest(OUTPUT))))
    if args.query is not None or args.topic is not None:
        registry = read_current()
        rows = query(registry, args.query) if args.query is not None else registry['functions'] + registry.get('documented_addresses', [])
        if args.topic is not None:
            available = {t for r in registry['functions'] + registry.get('documented_addresses', []) for t in r['navigation_topics']}
            if args.topic not in available:
                parser.error('Unknown evidence topic')
            rows = [r for r in rows if args.topic in r['navigation_topics']]
        for row in rows[:20]:
            print(json.dumps({**row, 'references': row['references'][:10],
                              'callers': row['callers'][:10], 'callees': row['callees'][:10]}, ensure_ascii=False))
        print(json.dumps(dict(matches=len(rows), shown=min(len(rows), 20))))
    if args.question is not None:
        registry = read_current()
        rows = [r for r in registry['questions'] if r['id'] == args.question]
        if not rows:
            parser.error('Unknown question ID')
        print(json.dumps(rows[0], ensure_ascii=False, indent=2))
    if not args.build and args.query is None and args.question is None and args.topic is None:
        parser.error('Use --build, --query or --question')


if __name__ == '__main__':
    main()
