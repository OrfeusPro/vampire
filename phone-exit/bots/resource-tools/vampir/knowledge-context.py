"""Explicit adapters for curated knowledge and bounded native replay metadata."""
import json
from pathlib import Path


def inventory(index, root, knowledge):
    paths = set(knowledge.rglob('*.md')) | set(knowledge.glob('*.json'))
    paths |= set((knowledge / 'releases').glob('*/facts.json'))
    if knowledge == index.HERE / 'knowledge':
        paths |= set(index.HERE.glob('*.md'))
        for folder in ('vampir', 'vampir-headless', 'vampir-shared'):
            paths |= set((index.HERE.parents[1] / folder).glob('*.md'))
    paths |= set((root / 'ghidra/release-comparisons').glob('*/run-*/*-replay/*/manifest.json'))
    paths |= set((root / 'client-code-snapshots').glob('*/ProjectRED-Win64-Shipping.exe'))
    return {str(p.resolve()): index.digest(p) for p in sorted(paths) if p.is_file()}


def text(value, field):
    if not isinstance(value, str) or not value.strip(): raise ValueError('Missing result field: ' + field)
    return value


def validate_fact(index, fact, sha, question_ids):
    for key in ('id', 'question', 'conclusion', 'method', 'unknown', 'next_check'):
        text(fact.get(key), key)
    if fact['question'] not in question_ids: raise ValueError('Fact has unknown question')
    if fact.get('source_sha256') != sha: raise ValueError('Fact belongs to another source')
    if not fact.get('addresses') or any(index.address(a) != a for a in fact['addresses']):
        raise ValueError('Fact needs canonical addresses')
    if not isinstance(fact.get('limits'), list) or not fact['limits']:
        raise ValueError('Fact needs explicit limits')
    for limit in fact['limits']: text(limit, 'limits')
    if not fact.get('evidence'): raise ValueError('Fact needs evidence')
    for evidence in fact['evidence']:
        if index.digest(evidence['path']) != evidence['sha256']: raise ValueError('Fact evidence changed: ' + evidence['path'])
    if fact['method'] == 'bounded_native' and not fact.get('checks'):
        raise ValueError('Native fact lacks registered checks')
    for check in fact.get('checks', []):
        if check.get('state') != 'passed' or index.digest(check['report']) != check['sha256']:
            raise ValueError('Fact check report changed or failed')
        report = index.read_json(check['report'])
        if report.get('state') != 'passed' or report['definition']['source_sha256'] != sha:
            raise ValueError('Fact check source/state differs')


def import_context(index, db, root, knowledge, inputs):
    db.executescript('''CREATE TABLE context(id TEXT PRIMARY KEY, source_sha TEXT NOT NULL,
        kind TEXT NOT NULL, path TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE context_inputs(path TEXT PRIMARY KEY, sha TEXT NOT NULL);''')
    def add(identifier, sha, kind, path, payload, searchable=None):
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        db.execute('INSERT INTO context VALUES(?,?,?,?,?)', (identifier, sha, kind, str(path), encoded))
        db.execute('INSERT INTO search VALUES(?,?,?,?,?,?)',
            (sha, '', identifier, searchable if searchable is not None else encoded, str(path), kind))
    questions_file = knowledge / 'questions.json'
    questions = index.read_json(questions_file)['questions'] if questions_file.is_file() else []
    ids = [q['id'] for q in questions]
    if len(ids) != len(set(ids)): raise ValueError('Duplicate question ID')
    for q in questions:
        # Existing prose mixes releases. Never infer applicability from numbers in text.
        add('question:' + q['id'], '', 'question', questions_file,
            dict(**q, applicability='historical_context_not_release_proof'))
    roles_file = knowledge / 'function-roles.json'
    if roles_file.is_file():
        roles = index.read_json(roles_file)
        sha = roles['source_sha256']
        if not index.SHA.fullmatch(sha): raise ValueError('Invalid legacy role source')
        for at, role in roles['roles'].items():
            add('role:' + sha + ':' + index.address(at), sha, 'role', roles_file,
                dict(address=index.address(at), **role, applicability='explicit_legacy_source'))
    checked_sources = set()
    for filename, expected in inputs.items():
        db.execute('INSERT INTO context_inputs VALUES(?,?)', (filename, expected))
        path = Path(filename)
        if path.suffix.lower() == '.exe':
            if expected != path.parent.name: raise ValueError('Source snapshot digest differs')
            db.execute('INSERT OR IGNORE INTO releases VALUES(?,?)', (expected, filename))
        elif path.suffix == '.md':
            add('document:' + filename, '', 'document', path,
                dict(applicability='unscoped_navigation'), path.read_text('utf-8-sig'))
        elif path.name == 'facts.json' and path.parent.parent.name == 'releases':
            sha = path.parent.name
            data = index.read_json(path)
            if not index.SHA.fullmatch(sha) or data.get('source_sha256') != sha:
                raise ValueError('Invalid facts release')
            for fact in data['facts']:
                validate_fact(index, fact, sha, set(ids))
                add('fact:' + sha + ':' + fact['id'], sha, 'fact', path, fact)
        elif path.name == 'manifest.json':
            if expected != path.parent.name: raise ValueError('Replay manifest digest differs')
            if path.stat().st_size > 32 * 1024 * 1024:
                add('replay:' + expected, '', 'unsupported_replay', path,
                    dict(reason='Manifest exceeds bounded adapter size; no proof imported'))
                continue
            data = index.read_json(path)
            sha = data.get('source_sha256', '')
            if (not isinstance(sha,str) or not index.SHA.fullmatch(sha) or not isinstance(data.get('cases'), list)
                    or not isinstance(data.get('limits'), list) or not data['limits']
                    or not isinstance(data.get('tool_sha256'),str) or not index.SHA.fullmatch(data['tool_sha256'])):
                add('replay:' + expected, '', 'unsupported_replay', path,
                    dict(reason='Unsupported replay contract; no proof imported'))
                continue
            source = root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
            if sha not in checked_sources:
                if index.digest(source) != sha: raise ValueError('Replay source snapshot differs')
                checked_sources.add(sha)
            # Retain fixture declarations/limits, not bodies or possible live values.
            payload = {k: data[k] for k in ('source_sha256', 'tool_sha256', 'limits',
                'fixtures', 'fixture_boundaries', 'native_execution', 'network_used') if k in data}
            payload.update(cases=len(data['cases']), applicability='saved_bounded_scenarios_not_session_proof')
            add('replay:' + expected, sha, 'native_replay', path, payload)
