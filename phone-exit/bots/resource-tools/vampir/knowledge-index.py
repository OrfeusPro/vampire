"""Source-scoped knowledge and explicit offline research workflow."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import sys
import tempfile
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
INSTALL = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe')
KNOWLEDGE = HERE / 'knowledge'
SHA = re.compile(r'[0-9a-f]{64}')
DIRECT_CALL = re.compile(r'^CALL\s+(0x[0-9a-f]+)$', re.I)
DATA_LEA = re.compile(r'^LEA\s+\w+,\[(0x[0-9a-f]+)\]$', re.I)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tool_inputs():
    return {name: digest(HERE/name) for name in ('knowledge-index.py', 'extract-native-enums.py',
        'build-headless-sdk-config.py', 'build-native-entry-code.py', 'knowledge-context.py')}


def extension(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def api():
    return SimpleNamespace(**globals())


def read_json(path):
    with Path(path).open('rb') as stream: raw = stream.read(33554433)
    if len(raw) > 33554432: raise ValueError('Report exceeds index budget')
    return json.loads(raw.decode('utf-8-sig'))


def address(value):
    result = int(value, 16) if isinstance(value, str) else value
    if type(result) is not int or not 0 < result < 1 << 63: raise ValueError('Invalid address')
    return f'0x{result:x}'


def child(folder, name):
    relative = PurePosixPath(name.replace('\\', '/'))
    if relative.is_absolute() or '..' in relative.parts or ':' in name:
        raise ValueError('Artifact path escapes receipt directory')
    path = (folder / Path(*relative.parts)).resolve()
    if not path.is_relative_to(folder.resolve()): raise ValueError('Artifact path escapes receipt directory')
    return path


class Sources:
    def __init__(self, root):
        spec = importlib.util.spec_from_file_location('index_pe', HERE / 'extract-native-enums.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.pe_class, self.root, self.cache = module.PE, Path(root), {}
        spec = importlib.util.spec_from_file_location('index_literals', HERE / 'build-headless-sdk-config.py')
        literals = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(literals)
        self.read_literal, self.literal_cache = literals.read_literal, {}

    def get(self, sha):
        if type(sha) is not str or not SHA.fullmatch(sha): raise ValueError('Invalid source SHA')
        if sha not in self.cache:
            path = self.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
            if digest(path) != sha: raise ValueError('Client source snapshot hash differs')
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('Source changed during indexing')
            self.cache[sha] = (path, raw, self.pe_class(raw))
        return self.cache[sha]

    def check_bytes(self, sha, at, data):
        _, raw, pe = self.get(sha)
        rva = int(at, 16) - pe.base
        for section in pe.sections:
            delta = rva - section['rva']
            if 0 <= delta and delta + len(data) <= section['raw_size']:
                offset = section['raw'] + delta
                if raw[offset:offset+len(data)] != data: raise ValueError('Export instruction/literal differs from EXE')
                return
        raise ValueError('Export address is not file-backed')

    def literal(self, sha, at):
        key = (sha, at)
        if key not in self.literal_cache:
            _, raw, pe = self.get(sha)
            def offset(rva):
                for section in pe.sections:
                    delta = rva - section['rva']
                    if 0 <= delta < section['raw_size'] and section['name'] in ('.rdata', '.data'):
                        return section['raw'] + delta
                raise ValueError('Not file-backed data')
            self.literal_cache[key] = self.read_literal(raw, SimpleNamespace(pe=pe, offset=offset), int(at, 16))
        return self.literal_cache[key]


def discover(root):
    ghidra = Path(root) / 'ghidra'
    patterns = ('export-*/run-*/functions.json',
        'release-comparisons/*/run-*/details/*/details.json',
        'request-exports/*/run-*/details.json',
        'release-comparisons/*/run-*/bootstrap/*/export/bootstrap.json')
    return sorted({p for pattern in patterns for p in ghidra.glob(pattern)})


def schema(db):
    db.executescript('''
        PRAGMA user_version=2;
        CREATE TABLE releases(sha TEXT PRIMARY KEY, source TEXT NOT NULL);
        CREATE TABLE artifacts(path TEXT PRIMARY KEY, sha TEXT NOT NULL, receipt TEXT,
            receipt_sha TEXT, state TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE functions(source_sha TEXT, address TEXT, PRIMARY KEY(source_sha,address));
        CREATE TABLE unresolved(artifact TEXT, ordinal INTEGER, source_sha TEXT, address TEXT,
            hint TEXT, reason TEXT, PRIMARY KEY(artifact,ordinal));
        CREATE TABLE variants(id TEXT PRIMARY KEY, source_sha TEXT, address TEXT,
            pseudocode_sha TEXT, completed INTEGER, message TEXT, body_json TEXT);
        CREATE TABLE observations(artifact TEXT, source_sha TEXT, address TEXT, variant TEXT,
            name TEXT, pseudocode TEXT, ordinal INTEGER, PRIMARY KEY(artifact,ordinal));
        CREATE TABLE calls(variant TEXT, source_sha TEXT, caller TEXT, callsite TEXT, target TEXT,
            kind TEXT, PRIMARY KEY(variant,callsite,target,kind));
        CREATE INDEX call_target ON calls(source_sha,target);
        CREATE TABLE literals(artifact TEXT, source_sha TEXT, address TEXT, text TEXT,
            PRIMARY KEY(artifact,source_sha,address));
        CREATE TABLE literal_refs(variant TEXT, source_sha TEXT, caller TEXT, instruction TEXT, target TEXT,
            PRIMARY KEY(variant,instruction,target));
        CREATE INDEX literal_target ON literal_refs(source_sha,target);
        CREATE VIRTUAL TABLE search USING fts5(source_sha UNINDEXED, address UNINDEXED,
            variant UNINDEXED, text, path UNINDEXED, kind UNINDEXED, tokenize='unicode61');
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    ''')


def receipt_for(report):
    return report.parent.parent / 'provenance.json' if report.name == 'bootstrap.json' else report.parent / 'provenance.json'


def add_literal(db, artifact, sha, at, text):
    db.execute('INSERT OR IGNORE INTO literals VALUES(?,?,?,?)', (artifact, sha, at, text))
    identifier = 'literal:' + hashlib.sha256((sha + at + text).encode()).hexdigest()
    if not db.execute('SELECT 1 FROM search WHERE variant=?', (identifier,)).fetchone():
        db.execute('INSERT INTO search VALUES(?,?,?,?,?,?)', (sha, at, identifier, text, artifact, 'literal'))


def missing_conditional_fallthroughs(instructions):
    """A listed x64 Jcc also requires its native fallthrough instruction."""
    covered={int(row['address'],16) for row in instructions}
    missing=[]
    for row in instructions:
        raw=bytes.fromhex(row['bytes'])
        conditional=(len(raw)==2 and 0x70<=raw[0]<=0x7f) or (len(raw)==6 and raw[0]==0x0f and 0x80<=raw[1]<=0x8f)
        if conditional and int(row['address'],16)+len(raw) not in covered:
            missing.append(row['address'])
    return missing


def import_report(db, sources, report):
    receipt_path = receipt_for(report)
    if not receipt_path.is_file():
        db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?,?)',
            (str(report), digest(report), None, None, 'unverified', 'Missing completion receipt; not imported'))
        return
    receipt = read_json(receipt_path)
    folder = receipt_path.parent
    files = {child(folder, name): expected for name, expected in receipt['files'].items()}
    if report.resolve() not in files: raise ValueError('Receipt does not pin report')
    # Logs, old script inputs and live project files are not proof prerequisites:
    # retain their recorded hashes, validate the report and every consumed output.
    checked = {}
    def consume(path):
        path = path.resolve()
        if path not in files or digest(path) != files[path]: raise ValueError('Export output hash differs from receipt: ' + str(path))
        checked[path] = files[path]
        return path
    consume(report)
    data = read_json(report)
    rows = []
    if 'pairs' in data:
        for pair in data['pairs']:
            for side in ('old', 'new'):
                rows.append((data[side + '_source_sha256'], pair[side], pair.get('old_analyst_name', ''), side))
    elif 'functions' in data:
        sha = data.get('new_source_sha256', data.get('source_sha256'))
        if receipt.get('source_sha256', sha) != sha: raise ValueError('Receipt source SHA differs')
        rows = [(sha, row, row.get('name', ''), '') for row in data['functions']]
    else:
        raise ValueError('Unsupported Ghidra export schema')
    seen = set()
    for ordinal, (sha, row, name, side) in enumerate(rows):
        source_path, _, _ = sources.get(sha)
        at = address(row['address'])
        seen.add((sha, at))
        db.execute('INSERT OR IGNORE INTO releases VALUES(?,?)', (sha, str(source_path)))
        if row.get('function_missing') is True or row.get('skipped') == 'body_budget':
            db.execute('INSERT INTO unresolved VALUES(?,?,?,?,?,?)',
                (str(report), ordinal, sha, at, name,
                 'Ghidra export body budget exceeded' if row.get('skipped') == 'body_budget' else 'No function object in this Ghidra export'))
            continue
        completed = row.get('decompilation_completed', row.get('completed'))
        if type(completed) is not bool: raise ValueError('Missing decompiler status')
        pseudo_name = row.get('pseudocode_file', at + '.c' if report.name == 'bootstrap.json' else None)
        pseudo = consume(report.parent / pseudo_name) if pseudo_name else None
        if completed and pseudo is None: raise ValueError('Completed decompilation has no pseudocode file')
        pseudo_text = pseudo.read_text('utf-8-sig') if pseudo else ''
        instructions = row.get('instructions', [])
        message = row.get('message', '')
        starts = set(row.get('decompiler_block_starts', []))
        covered = {ins['address'] for ins in instructions}
        if row.get('block_coverage_complete') is False or not starts <= covered:
            completed = False
            message += ' Decompiler basic blocks missing from instruction export.'
        if row.get('block_coverage_complete') is True and missing_conditional_fallthroughs(instructions):
            completed = False
            message += ' Native conditional fallthrough instructions missing from export.'
        if ('switch' in pseudo_text and not starts and any(
                re.fullmatch(r'JMP\s+[A-Z][A-Z0-9]*', ins.get('text', '')) and not ins.get('references')
                for ins in instructions)):
            completed = False
            message += ' Switch has unresolved indirect dispatch and no block coverage evidence; inspect case blocks.'
        if 'body_bytes' in row and sum(len(bytes.fromhex(ins['bytes'])) for ins in instructions) > row['body_bytes']:
            completed = False
            message += ' Instruction coverage exceeds declared function body; export incomplete.'
        for ins in instructions:
            raw = bytes.fromhex(ins['bytes'])
            if not raw: raise ValueError('Empty instruction')
            sources.check_bytes(sha, address(ins['address']), raw)
        body = json.dumps(dict(instructions=instructions, calls=row.get('calls', []),
            completed=completed, message=message), sort_keys=True, separators=(',', ':'))
        pseudo_sha = checked[pseudo] if pseudo else None
        variant = hashlib.sha256((sha + at + (pseudo_sha or '') + body).encode()).hexdigest()
        db.execute('INSERT OR IGNORE INTO releases VALUES(?,?)', (sha, str(source_path)))
        db.execute('INSERT OR IGNORE INTO functions VALUES(?,?)', (sha, at))
        fresh = db.execute('INSERT OR IGNORE INTO variants VALUES(?,?,?,?,?,?,?)',
            (variant, sha, at, pseudo_sha, int(completed), message, body)).rowcount
        # old_analyst_name is a comparison hint on the new side, never a verified role.
        name = (name + (' [comparison hint]' if side == 'new' and name else '')) or at
        db.execute('INSERT INTO observations VALUES(?,?,?,?,?,?,?)', (str(report), sha, at, variant, name, str(pseudo) if pseudo else None, ordinal))
        if fresh:
            text = name + '\n' + pseudo_text + '\n' + '\n'.join(i.get('text', '') for i in instructions)
            db.execute('INSERT INTO search VALUES(?,?,?,?,?,?)',
                (sha, at, variant, text, str(pseudo or report), 'function' if pseudo else 'instructions_without_pseudocode'))
            for ins in instructions:
                match = DIRECT_CALL.fullmatch(ins.get('text', '').strip())
                if match:
                    db.execute('INSERT OR IGNORE INTO calls VALUES(?,?,?,?,?,?)',
                        (variant, sha, at, address(ins['address']), address(match[1]), 'source_checked_direct_call'))
                match = DATA_LEA.fullmatch(ins.get('text', '').strip())
                if match:
                    target = address(match[1])
                    literal = sources.literal(sha, target)
                    if literal:
                        add_literal(db, str(report), sha, target, literal['text'])
                        db.execute('INSERT OR IGNORE INTO literal_refs VALUES(?,?,?,?,?)',
                            (variant, sha, at, address(ins['address']), target))
            for call in row.get('calls', []):
                for target in call.get('targets', []):
                    if 'address' in target:
                        db.execute('INSERT OR IGNORE INTO calls VALUES(?,?,?,?,?,?)',
                            (variant, sha, at, address(call['address']), address(target['address']), 'reported_call'))
    sha = data.get('new_source_sha256', data.get('source_sha256'))
    for literal in data.get('literals', []):
        raw = bytes.fromhex(literal['bytes'])
        at = address(literal['address'])
        sources.check_bytes(sha, at, raw)
        encoding = 'utf-16le' if len(raw) % 2 == 0 and raw[1::2] == bytes(len(raw)//2) else 'utf-8'
        text = raw.decode(encoding, errors='replace').rstrip('\0')
        add_literal(db, str(report), sha, at, text)
    detail = dict(format=report.name, functions=len(rows), duplicate_address_observations=len(rows)-len(seen), checked_outputs=len(checked),
        instruction_bytes_checked=any(row.get('instructions') for _, row, _, _ in rows),
        historical_input_hashes=receipt.get('inputs', {}), tools=receipt.get('tools', {}),
        limits='Source and consumed outputs checked; historical scripts are not required to match present files. No role transfer.')
    db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?,?)', (str(report), checked[report.resolve()],
        str(receipt_path), digest(receipt_path), 'verified_source_and_outputs', json.dumps(detail)))


def build(root, output, on_progress=None, knowledge=None):
    root, output = Path(root), Path(output)
    knowledge = Path(knowledge) if knowledge is not None else KNOWLEDGE
    context = extension('knowledge-context')
    context_inputs = context.inventory(api(), root, knowledge)
    inputs = tool_inputs()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_file():
        previous = open_index(output)
        try:
            builder = previous.execute("SELECT value FROM metadata WHERE key='tool_inputs'").fetchone()
            reports = {str(p) for p in discover(root)}
            old_reports = {r['path'] for r in previous.execute('SELECT path FROM artifacts')}
            same_reports = reports == old_reports
            newly_finished = any(not r['receipt'] and receipt_for(Path(r['path'])).is_file()
                for r in previous.execute('SELECT path,receipt FROM artifacts'))
            old_context = ({r['path']: r['sha'] for r in previous.execute('SELECT * FROM context_inputs')}
                if previous.execute('PRAGMA user_version').fetchone()[0] == 2 else None)
            if builder and json.loads(builder['value']) == inputs and old_reports <= reports and not newly_finished:
                verify_index(previous, include_context=False)
                if same_reports and old_context == context_inputs:
                    return dict(database=str(output), counts=index_counts(previous), reused=True,
                        roles_transferred=False, game_or_ghidra_started=False)
                # Append only new exports or refresh context on a private backup.
                # Existing source/output hashes were checked above; removed files,
                # newly completed receipts and changed tools still need a rebuild.
                handle, name = tempfile.mkstemp(prefix='knowledge-context-', suffix='.sqlite3', dir=output.parent)
                os.close(handle)
                temporary = Path(name)
                revised = sqlite3.connect(temporary)
                revised.row_factory = sqlite3.Row
                try:
                    previous.backup(revised)
                    added = sorted(reports-old_reports)
                    if added:
                        sources = Sources(root)
                        for number, name in enumerate(added, 1):
                            try: import_report(revised, sources, Path(name))
                            except (ValueError, OSError, KeyError, TypeError) as error:
                                raise ValueError(f'Export rejected: {name}: {error}') from error
                            if on_progress: on_progress(number, len(added))
                    if old_context != context_inputs:
                        revised.execute('DELETE FROM search WHERE variant IN (SELECT id FROM context)')
                        revised.executescript('DROP TABLE context; DROP TABLE context_inputs;')
                        context.import_context(api(), revised, root, knowledge, context_inputs)
                    if context.inventory(api(), root, knowledge) != context_inputs:
                        raise ValueError('Knowledge inputs changed during refresh')
                    if {str(p) for p in discover(root)} != reports or tool_inputs() != inputs:
                        raise ValueError('Index inputs changed during refresh')
                    verify_index(revised, include_context=False)
                    revised.commit()
                    if revised.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Index integrity failed')
                    counts = index_counts(revised)
                    revised.close()
                    previous.close()
                    temporary.replace(output)
                    return dict(database=str(output), counts=counts, reused=False, code_reused=True,
                        imported_reports=len(added),
                        roles_transferred=False, game_or_ghidra_started=False)
                finally:
                    revised.close()
                    if temporary.exists(): temporary.unlink()
        finally: previous.close()
    handle, temporary = tempfile.mkstemp(prefix='knowledge-index-', suffix='.sqlite3', dir=output.parent)
    os.close(handle)
    temporary = Path(temporary)
    db = sqlite3.connect(temporary)
    try:
        schema(db)
        sources = Sources(root)
        reports = discover(root)
        for number, report in enumerate(reports, 1):
            try: import_report(db, sources, report)
            except (ValueError, OSError, KeyError, TypeError) as error:
                raise ValueError(f'Export rejected: {report}: {error}') from error
            if on_progress and (number % 25 == 0 or number == len(reports)): on_progress(number, len(reports))
        context.import_context(api(), db, root, knowledge, context_inputs)
        if context.inventory(api(), root, knowledge) != context_inputs:
            raise ValueError('Knowledge inputs changed during indexing')
        if tool_inputs() != inputs: raise ValueError('Index builder/dependencies changed during import')
        db.execute('INSERT INTO metadata VALUES(?,?)', ('tool_inputs', json.dumps(inputs, sort_keys=True)))
        db.execute('INSERT INTO metadata VALUES(?,?)', ('root', str(root.resolve())))
        db.commit()
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Index integrity check failed')
        counts = index_counts(db)
        db.close()
        temporary.replace(output)
        return dict(database=str(output), counts=counts, reused=False, roles_transferred=False, game_or_ghidra_started=False)
    finally:
        db.close()
        if temporary.exists(): temporary.unlink()


def index_counts(db):
    return {name: db.execute('SELECT count(*) FROM ' + name).fetchone()[0]
        for name in ('releases', 'artifacts', 'functions', 'variants', 'observations', 'calls', 'literals', 'literal_refs', 'unresolved')}


def verify_index(db, include_context=True):
    for row in db.execute('SELECT path,sha,receipt,receipt_sha FROM artifacts'):
        if digest(row['path']) != row['sha'] or (row['receipt'] and digest(row['receipt']) != row['receipt_sha']):
            raise ValueError('Indexed artifact changed; rebuild required')
    for row in db.execute('SELECT DISTINCT o.pseudocode,v.pseudocode_sha FROM observations o JOIN variants v ON o.variant=v.id WHERE o.pseudocode IS NOT NULL'):
        if digest(row['pseudocode']) != row['pseudocode_sha']: raise ValueError('Indexed pseudocode changed')
    for row in db.execute('SELECT * FROM releases'):
        if digest(row['source']) != row['sha']: raise ValueError('Indexed source changed')
    if include_context and db.execute('PRAGMA user_version').fetchone()[0] == 2:
        for row in db.execute('SELECT * FROM context_inputs'):
            if digest(row['path']) != row['sha']: raise ValueError('Indexed knowledge changed')
    if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Index integrity check failed')


def open_index(path):
    db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    if db.execute('PRAGMA user_version').fetchone()[0] not in (1, 2):
        db.close()
        raise ValueError('Unsupported index schema')
    return db


def select_release(db, value):
    if value == 'all': return None
    if value == 'installed':
        value = digest(INSTALL)
    if not re.fullmatch(r'[0-9a-f]{8,64}', value): raise ValueError('Expected installed, all or SHA prefix of 8..64 hex characters')
    rows = db.execute('SELECT sha FROM releases WHERE sha LIKE ?', (value + '%',)).fetchall()
    if len(rows) != 1: raise ValueError('Release is absent or SHA prefix is ambiguous; no historical fallback')
    return rows[0]['sha']


def query(db, operation, value, release, limit):
    if operation == 'function':
        return [dict(r) for r in db.execute('''SELECT o.source_sha,o.address,group_concat(DISTINCT o.name) AS names,
            min(o.pseudocode) AS pseudocode,min(o.artifact) AS artifact,count(*) AS observations,
            v.completed,v.message,v.id AS variant FROM observations o JOIN variants v ON v.id=o.variant
            WHERE o.address=? AND (? IS NULL OR o.source_sha=?) GROUP BY v.id ORDER BY o.source_sha,v.completed DESC,v.id LIMIT ?''',
            (address(value), release, release, limit))]
    if operation == 'callers':
        return [dict(r) for r in db.execute('''SELECT DISTINCT source_sha,caller,callsite,target,kind
            FROM calls WHERE target=? AND (? IS NULL OR source_sha=?) ORDER BY source_sha,caller,callsite LIMIT ?''',
            (address(value), release, release, limit))]
    # Treat user text as a literal FTS phrase, not a hidden query language.
    phrase = '"' + value.replace('"', '""') + '"'
    results = [dict(r) for r in db.execute('''SELECT source_sha,address,variant,path,kind,
        snippet(search,3,'[',']',' … ',36) AS excerpt FROM search
        WHERE search MATCH ? AND (? IS NULL OR source_sha=? OR source_sha='') ORDER BY rank LIMIT ?''', (phrase, release, release, limit))]
    for result in results:
        if not result['source_sha']: result['applicability'] = 'unscoped_navigation_not_release_proof'
        if result['kind'] == 'literal':
            result['references'] = [dict(r) for r in db.execute('''SELECT r.caller AS function,r.instruction,
                min(o.artifact) AS artifact,min(o.pseudocode) AS pseudocode FROM literal_refs r
                JOIN observations o ON o.variant=r.variant WHERE r.source_sha=? AND r.target=?
                GROUP BY r.caller,r.instruction LIMIT 20''', (result['source_sha'],result['address']))]
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--database', type=Path)
    parser.add_argument('--knowledge', type=Path, default=KNOWLEDGE)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('build')
    sub.add_parser('verify')
    sub.add_parser('status')
    sub.add_parser('check')
    p = sub.add_parser('prepare')
    p.add_argument('--question', required=True)
    p.add_argument('--function', action='append', required=True)
    p.add_argument('--release', default='installed')
    p.add_argument('--reason')
    for name in ('collect', 'finish'):
        p = sub.add_parser(name)
        p.add_argument('--request', required=True, type=Path)
        if name == 'finish': p.add_argument('--result', required=True, type=Path)
    p = sub.add_parser('update')
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument('--baseline', type=Path)
    source.add_argument('--resume', type=Path)
    p.add_argument('--install', type=Path, default=INSTALL.parents[3])
    p.add_argument('--audit-only', action='store_true')
    p.add_argument('--plan-only', action='store_true')
    p = sub.add_parser('update-status')
    p.add_argument('--run', required=True, type=Path)
    for operation in ('search', 'function', 'callers'):
        p = sub.add_parser(operation)
        p.add_argument('value')
        p.add_argument('--release', default='installed')
        p.add_argument('--limit', type=int, default=20)
    args = parser.parse_args()
    database = args.database or args.root / 'knowledge/search.sqlite3'
    if args.operation == 'update':
        print(json.dumps(extension('research-update').update(api(), args, database), ensure_ascii=False))
        return
    if args.operation == 'update-status':
        print(json.dumps(extension('update-run').status(api(), args), ensure_ascii=False))
        return
    if args.operation in ('prepare', 'collect', 'finish', 'check'):
        workflow = extension('research-workflow')
        result = getattr(workflow, args.operation)(api(), args, database)
        print(json.dumps(result, ensure_ascii=False))
        return
    if args.operation == 'build':
        print(json.dumps(build(args.root, database, knowledge=args.knowledge,
            on_progress=lambda count,total: print(json.dumps(dict(event='index_progress', reports=count, total=total)), file=sys.stderr, flush=True)), ensure_ascii=False))
        return
    db = open_index(database)
    try:
        if args.operation == 'status':
            result = dict(releases=[dict(r) for r in db.execute('SELECT * FROM releases')],
                artifacts=[dict(r) for r in db.execute('SELECT state,count(*) AS count FROM artifacts GROUP BY state')])
        elif args.operation == 'verify':
            verify_index(db)
            result = dict(integrity='ok', files_checked=True)
        else:
            if not 1 <= args.limit <= 200: raise ValueError('Result limit must be 1..200')
            release = select_release(db, args.release)
            result = dict(release=release or 'all', results=query(db, args.operation, args.value, release, args.limit),
                limits='Static exports, explicit claims, bounded replay metadata and unscoped document navigation. Names are not proven roles. Resource adapters are not indexed.')
            if args.operation == 'function':
                result['unresolved_export_candidates'] = [dict(r) for r in db.execute(
                    'SELECT DISTINCT source_sha,address,hint,artifact,reason FROM unresolved WHERE address=? AND (? IS NULL OR source_sha=?) LIMIT ?',
                    (address(args.value), release, release, args.limit))]
        print(json.dumps(result, ensure_ascii=False))
    finally: db.close()


if __name__ == '__main__': main()
