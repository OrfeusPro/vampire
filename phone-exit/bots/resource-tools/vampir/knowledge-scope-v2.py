"""Selected Ghidra rows checked from source; SQLite is discovery, never proof.

This module does not build the legacy index, inventory history, assign roles,
run native code or write facts.  Its final receipt describes only consumed
inputs and explicitly selected source/address rows.
"""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import sys
import time
from types import ModuleType, SimpleNamespace

HERE = Path(__file__).resolve().parent
RECIPE = 'knowledge-scope-v2'
FORMAT = 'research-scope-validations-v2'
SHA = re.compile(r'[0-9a-f]{64}')
MAX_JSON = 32 * 1024 * 1024
MAX_PSEUDOCODE = 4 * 1024 * 1024
MAX_CANDIDATES = 256
PRIVATE_PARTS = {'private', 'capture', 'captures', 'private-captures', 'private_captures'}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def address(value):
    try:
        number = int(value, 16) if isinstance(value, str) else value
    except ValueError as error:
        raise ValueError('Invalid scoped address') from error
    if type(number) is not int or not 0 < number < 1 << 63:
        raise ValueError('Invalid scoped address')
    return hex(number)


def full_sha(value):
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ValueError('Full scoped SHA256 required')
    return value


def no_private(path):
    if any(part.lower() in PRIVATE_PARTS for part in Path(path).parts):
        raise ValueError('Private captures are outside the selected research scope')
    return Path(path)


def contained(path, folder):
    path, folder = no_private(path).resolve(), Path(folder).resolve()
    if not path.is_relative_to(folder):
        raise ValueError('Selected artifact path escapes its allowed directory')
    return path


def child(folder, name):
    if not isinstance(name, str) or not name or ':' in name or '\x00' in name:
        raise ValueError('Invalid receipt output path')
    relative = PurePosixPath(name.replace('\\', '/'))
    if relative.is_absolute() or '..' in relative.parts or '.' in relative.parts:
        raise ValueError('Receipt output path escapes completion directory')
    return contained(Path(folder) / Path(*relative.parts), folder)


def receipt_for(report):
    report = Path(report)
    return report.parent.parent / 'provenance.json' if report.name == 'bootstrap.json' else report.parent / 'provenance.json'


def pointer(path, sha):
    return dict(path=str(Path(path).resolve()), sha256=full_sha(sha))


def _unique_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('Duplicate JSON object key in selected input')
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON input')))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('Invalid selected JSON input') from error


class Scope:
    @classmethod
    def open(cls, root, knowledge, source_sha256, ordered_explicit_addresses, recipe_tools=None,
            *, question_id=None, source_store=None):
        return cls(root, knowledge, source_sha256, ordered_explicit_addresses, recipe_tools,
            question_id=question_id, source_store=source_store)

    def __init__(self, root, knowledge, source_sha256, ordered_explicit_addresses, recipe_tools=None,
            *, question_id=None, source_store=None):
        self.root, self.knowledge = Path(root).resolve(), Path(knowledge).resolve()
        self.source_sha256 = full_sha(source_sha256)
        self.addresses = [address(value) for value in ordered_explicit_addresses]
        if not 1 <= len(self.addresses) <= 32 or len(set(self.addresses)) != len(self.addresses):
            raise ValueError('Scoped ordered address budget is 1..32 unique addresses')
        if question_id is not None and (not isinstance(question_id, str) or not question_id.strip()):
            raise ValueError('Explicit question ID required')
        self.question_id, self.context = question_id, []
        self._files, self._json, self._admitted, self._hints = {}, {}, {}, []
        self.checked_variants, self.functions = {}, []
        self.metrics = dict(sha_reads=0, sha_bytes=0, read_cache_hits=0, json_parses=0,
            json_cache_hits=0, scoped_pe_builds=0, scoped_pe_cache_hits=0,
            discovery_queries=0, candidate_reports=0, selected_pseudocode_reads=0,
            global_historical_pseudocode_reads=0, barrier_reads=0, barrier_bytes=0,
            barrier_seconds=0)
        self.pin(__file__, kind='tool')
        for filename, expected in (recipe_tools or {}).items():
            self.pin(filename, expected, kind='tool')
        self.pin(sys.executable, kind='runtime')
        for name in ('_sqlite3', '_hashlib', '_json', '_struct'):
            filename = getattr(sys.modules.get(name), '__file__', None)
            if filename and Path(filename).is_file():
                self.pin(filename, kind='runtime')
        runtime_dirs = (Path(sys.base_prefix), Path(sys.base_prefix) / 'DLLs')
        runtime_names = (f'python{sys.version_info.major}{sys.version_info.minor}.dll',
            'python3.dll', 'sqlite3.dll', 'libcrypto-3.dll')
        for directory in runtime_dirs:
            for name in runtime_names:
                path = directory / name
                if path.is_file():
                    self.pin(path, kind='runtime')
        self.runtime = dict(python=sys.version, implementation=sys.implementation.name,
            sqlite=sqlite3.sqlite_version)
        self._bindings = self._load('update-bindings')
        self._pe = self._load('extract-native-enums')
        struct_runtime = getattr(sys.modules.get('_struct'), '__file__', None)
        if struct_runtime and Path(struct_runtime).is_file():
            self.pin(struct_runtime, kind='runtime')
        self.source_store = source_store or self._bindings.SourceStore(SimpleNamespace(digest=digest), self.root)
        if Path(self.source_store.root).resolve() != self.root:
            raise ValueError('Shared SourceStore belongs to another resource root')
        self.source_path = contained(self.root / 'client-code-snapshots' / self.source_sha256 /
            'ProjectRED-Win64-Shipping.exe', self.root / 'client-code-snapshots')
        # Missing discovery rows must not earn an unchecked source declaration.
        self.source_store.source(self.source_sha256)

    def _load(self, name):
        path = HERE / (name + '.py')
        raw = self._read(path, None, 'tool', MAX_JSON)
        module = ModuleType('scope_v2_' + name.replace('-', '_'))
        module.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        return module

    def _allowed(self, path, kind):
        path = no_private(path).resolve()
        if kind not in ('tool', 'runtime') and not any(path.is_relative_to(folder)
                for folder in (self.root, self.knowledge, HERE.parents[2])):
            raise ValueError('Scoped input is outside resource/project directories')
        return path

    def _read(self, path, expected, kind, budget):
        path = self._allowed(path, kind)
        if expected is not None:
            full_sha(expected)
        if path in self._files:
            row = self._files[path]
            if expected is not None and row['sha256'] != expected:
                raise ValueError('Selected input SHA conflicts with an already pinned input')
            self.metrics['read_cache_hits'] += 1
            return row['raw']
        with path.open('rb') as stream:
            raw = stream.read(budget + 1)
        if len(raw) > budget:
            raise ValueError('Selected input exceeds bounded ' + kind + ' budget')
        actual = hashlib.sha256(raw).hexdigest()
        if expected is not None and actual != expected:
            raise ValueError('Selected input SHA differs: ' + str(path))
        self._files[path] = dict(sha256=actual, raw=raw, kind=kind)
        self.metrics['sha_reads'] += 1
        self.metrics['sha_bytes'] += len(raw)
        if kind == 'pseudocode':
            self.metrics['selected_pseudocode_reads'] += 1
        return raw

    def pin(self, path, sha256=None, *, kind='context'):
        # Runtime binaries can exceed the JSON budget; they are never parsed.
        self._read(path, sha256, kind, 256 * 1024 * 1024 if kind == 'runtime' else MAX_JSON)
        path = Path(path).resolve()
        return pointer(path, self._files[path]['sha256'])

    def json(self, path, sha256=None, *, kind='context'):
        raw = self._read(path, sha256, kind, MAX_JSON)
        path = Path(path).resolve()
        if path not in self._json:
            self._json[path] = _unique_json(raw)
            self.metrics['json_parses'] += 1
        else:
            self.metrics['json_cache_hits'] += 1
        return copy.deepcopy(self._json[path])

    def _pointer(self, value, kind):
        if not isinstance(value, dict) or set(value) != {'path', 'sha256'}:
            raise ValueError('Explicit checked ' + kind + ' pointer required')
        return self.pin(value['path'], full_sha(value['sha256']), kind=kind)

    def _source(self):
        raw = self.source_store.source(self.source_sha256)
        images = getattr(self.source_store, '_scoped_v2_pe_images', None)
        if images is None:
            images = self.source_store._scoped_v2_pe_images = {}
        key = (self.source_sha256, self._files[HERE / 'extract-native-enums.py']['sha256'])
        if key not in images:
            existing = getattr(self.source_store, '_images', {}).get(self.source_sha256)
            images[key] = existing.pe if existing is not None else self._pe.PE(raw)
            self.metrics['scoped_pe_builds'] += existing is None
        else:
            self.metrics['scoped_pe_cache_hits'] += 1
        return raw, images[key]

    def _check_bytes(self, at, data):
        raw, pe = self._source()
        rva = int(at, 16) - pe.base
        matches = []
        for section in pe.sections:
            delta = rva - section['rva']
            if 0 <= delta and delta + len(data) <= section['raw_size']:
                matches.append(section['raw'] + delta)
        if len(matches) != 1:
            raise ValueError('Selected instruction address is not uniquely file-backed')
        offset = matches[0]
        if raw[offset:offset + len(data)] != data:
            raise ValueError('Selected instruction bytes differ from exact source EXE')

    def _report_path(self, path):
        path = contained(path, self.root / 'ghidra')
        relative = path.relative_to(self.root / 'ghidra')
        if len(relative.parts) < 3 or path.name not in ('functions.json', 'details.json', 'bootstrap.json'):
            raise ValueError('Unsupported scoped export location')
        if not (relative.parts[0].startswith('export-') or
                relative.parts[0] in ('request-exports', 'release-comparisons')):
            raise ValueError('Unreviewed scoped export family')
        return path

    def discover_candidates(self, legacy_read_only_index=None, explicit_export_pointers=()):
        """Read only selected metadata. DB bodies/status/names are never consumed."""
        result = []
        if legacy_read_only_index is not None and Path(legacy_read_only_index).is_file():
            path = Path(legacy_read_only_index).resolve()
            connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
            try:
                connection.execute('PRAGMA query_only=ON')
                connection.execute('PRAGMA trusted_schema=OFF')
                steps = 0
                def budget():
                    nonlocal steps
                    steps += 1
                    return steps > 10000
                connection.set_progress_handler(budget, 1000)
                if connection.execute('PRAGMA user_version').fetchone()[0] not in (1, 2):
                    raise ValueError('Unsupported discovery index schema')
                marks = ','.join('?' for _ in self.addresses)
                rows = connection.execute('SELECT DISTINCT a.path,a.sha,a.receipt,a.receipt_sha '
                    'FROM observations o JOIN artifacts a ON a.path=o.artifact '
                    f'WHERE o.source_sha=? AND o.address IN ({marks}) LIMIT ?',
                    [self.source_sha256, *self.addresses, MAX_CANDIDATES + 1]).fetchall()
                self.metrics['discovery_queries'] += 1
                if len(rows) > MAX_CANDIDATES:
                    raise ValueError('Selected candidate discovery budget exceeded')
                for report, sha, receipt, receipt_sha in rows:
                    if receipt is None or receipt_sha is None:
                        result.append(dict(report=pointer(report, sha), receipt=None))
                    else:
                        result.append(dict(report=pointer(report, sha), receipt=pointer(receipt, receipt_sha)))
            except sqlite3.Error as error:
                raise ValueError('Selected candidate discovery failed; requires discovery') from error
            finally:
                connection.close()
        for value in explicit_export_pointers:
            if not isinstance(value, dict) or 'report' not in value:
                raise ValueError('Explicit export hint requires report/receipt pointers')
            result.append(copy.deepcopy(value))
        unique = {}
        for value in result:
            if set(value) != {'report', 'receipt'}:
                raise ValueError('Unknown selected export hint fields')
            report = value['report']
            self._report_path(report['path'])
            key = str(Path(report['path']).resolve())
            if key in unique and canonical(unique[key]) != canonical(value):
                raise ValueError('Conflicting discovery pointers for selected report')
            unique[key] = value
        if len(unique) > MAX_CANDIDATES:
            raise ValueError('Selected candidate discovery budget exceeded')
        self.metrics['candidate_reports'] = len(unique)
        return list(unique.values())

    def admit_export_rows(self, report_pointer, completion_receipt_pointer, exact_source_addresses=None):
        selected = self.addresses if exact_source_addresses is None else [address(x) for x in exact_source_addresses]
        if not selected or len(set(selected)) != len(selected) or not set(selected) <= set(self.addresses):
            raise ValueError('Admission addresses must be inside the explicit ordered scope')
        report = self._report_path(report_pointer['path'])
        if completion_receipt_pointer is None:
            raise ValueError('Selected report has no completion receipt; requires discovery')
        expected_receipt = receipt_for(report).resolve()
        if Path(completion_receipt_pointer['path']).resolve() != expected_receipt:
            raise ValueError('Selected completion receipt location differs')
        contained(expected_receipt, self.root / 'ghidra')
        receipt_pin = self._pointer(completion_receipt_pointer, 'receipt')
        receipt = self.json(expected_receipt, receipt_pin['sha256'], kind='receipt')
        if not isinstance(receipt, dict) or receipt.get('schema', 1) != 1 or not isinstance(receipt.get('files'), dict):
            raise ValueError('Unsupported selected completion receipt schema')
        files = {}
        for filename, expected in receipt['files'].items():
            target = child(expected_receipt.parent, filename)
            if target in files:
                raise ValueError('Duplicate normalized completion output path')
            files[target] = full_sha(expected)
        if report not in files:
            raise ValueError('Completion receipt does not pin the selected report')
        if full_sha(report_pointer['sha256']) != files[report]:
            raise ValueError('Selected report pointer differs from completion receipt')
        self._pointer(report_pointer, 'report')
        data = self.json(report, files[report], kind='report')
        if not isinstance(data, dict):
            raise ValueError('Selected report is not an object')
        rows = []
        if 'pairs' in data:
            if not isinstance(data['pairs'], list):
                raise ValueError('Invalid comparison pairs')
            for side in ('old', 'new'):
                full_sha(data.get(side + '_source_sha256'))
                if side + '_source_sha256' in receipt and receipt[side + '_source_sha256'] != data[side + '_source_sha256']:
                    raise ValueError('Completion comparison source differs')
            for pair in data['pairs']:
                for side in ('old', 'new'):
                    rows.append((data[side + '_source_sha256'], pair[side], pair.get('old_analyst_name', ''), side))
        elif isinstance(data.get('functions'), list):
            sha = full_sha(data.get('new_source_sha256', data.get('source_sha256')))
            if 'source_sha256' in data and data['source_sha256'] != sha:
                raise ValueError('Conflicting selected report source fields')
            rows = [(sha, row, row.get('name', ''), '') for row in data['functions']]
        else:
            raise ValueError('Unsupported selected Ghidra export schema')
        if 'source_sha256' in receipt and receipt['source_sha256'] != self.source_sha256:
            raise ValueError('Completion receipt source SHA differs from selected side')
        if 'source' in receipt and 'source_sha256' in receipt:
            if Path(receipt['source']).resolve() != self.source_path:
                raise ValueError('Completion receipt source path differs')
        admitted = []
        saw_source = any(sha == self.source_sha256 for sha, _, _, _ in rows)
        if not saw_source:
            raise ValueError('Selected report belongs to another source/comparison side')
        for ordinal, (sha, row, name, side) in enumerate(rows):
            if sha != self.source_sha256:
                continue
            at = address(row['address'])
            if at not in selected:
                continue
            validated = self._admit_row(report, files, row, name, side, ordinal, receipt_pin)
            admitted.append(validated)
        by_address = {}
        for row in admitted:
            by_address.setdefault(row['address'], set()).add(row.get('variant'))
        if any(len(values) > 1 for values in by_address.values()):
            raise ValueError('Conflicting duplicate selected observations in one report')
        key = (str(report), tuple(selected))
        self._admitted[key] = copy.deepcopy(admitted)
        return admitted

    def _admit_row(self, report, files, row, name, side, ordinal, receipt_pin):
        at = address(row['address'])
        base = dict(source_sha=self.source_sha256, address=at, artifact=str(report),
            artifact_sha256=files[report], receipt=receipt_pin, ordinal=ordinal, side=side)
        if row.get('function_missing') is True or row.get('skipped') == 'body_budget':
            return dict(**base, completed=False, variant=None, pseudocode=None, body_json=None,
                message='Export body budget exceeded' if row.get('skipped') == 'body_budget' else 'Function missing in selected export')
        completed = row.get('decompilation_completed', row.get('completed'))
        if type(completed) is not bool:
            raise ValueError('Selected row lacks explicit decompiler status')
        pseudo_name = row.get('pseudocode_file', at + '.c' if report.name == 'bootstrap.json' else None)
        pseudo, pseudo_text, pseudo_sha = None, '', None
        if pseudo_name:
            pseudo = child(report.parent, pseudo_name)
            if pseudo not in files:
                raise ValueError('Selected pseudocode is not pinned by completion receipt')
            pseudo_sha = files[pseudo]
            pseudo_text = self._read(pseudo, pseudo_sha, 'pseudocode', MAX_PSEUDOCODE).decode('utf-8-sig')
        if completed and pseudo is None:
            raise ValueError('Completed selected decompilation lacks pseudocode')
        instructions = row.get('instructions', [])
        if not isinstance(instructions, list) or len(instructions) > 65536:
            raise ValueError('Selected instruction count budget exceeded')
        message = row.get('message', '')
        if not isinstance(message, str):
            raise ValueError('Invalid selected decompiler message')
        starts = {address(value) for value in row.get('decompiler_block_starts', [])}
        covered, spans, byte_count = set(), [], 0
        for instruction in instructions:
            location = address(instruction['address'])
            if location in covered:
                raise ValueError('Duplicate selected instruction address')
            covered.add(location)
            try:
                raw = bytes.fromhex(instruction['bytes'])
            except (TypeError, ValueError) as error:
                raise ValueError('Invalid selected instruction bytes') from error
            if not 1 <= len(raw) <= 15:
                raise ValueError('Selected x64 instruction byte length differs')
            self._check_bytes(location, raw)
            begin = int(location, 16)
            spans.append((begin, begin + len(raw)))
            byte_count += len(raw)
        if byte_count > 65536:
            raise ValueError('Selected function instruction byte budget exceeded')
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise ValueError('Overlapping selected instruction spans')
        problems = []
        if not instructions or at not in covered:
            problems.append('Selected function entry/instructions missing')
        if row.get('block_coverage_complete') is False or not starts <= covered:
            problems.append('Decompiler basic blocks missing from selected instruction export')
        if row.get('direct_flow_coverage_complete') is False:
            problems.append('Selected direct flow coverage incomplete')
        if any(((len(raw := bytes.fromhex(ins['bytes'])) == 2 and 0x70 <= raw[0] <= 0x7f)
                or (len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f))
                and hex(int(ins['address'], 16) + len(raw)) not in covered for ins in instructions):
            problems.append('Native conditional fallthrough missing from selected export')
        if 'switch' in pseudo_text and not starts and any(re.fullmatch(r'JMP\s+[A-Z][A-Z0-9]*',
                ins.get('text', '')) and not ins.get('references') for ins in instructions):
            problems.append('Unresolved switch lacks block coverage evidence')
        if 'body_bytes' in row:
            if type(row['body_bytes']) is not int or row['body_bytes'] < 1:
                raise ValueError('Invalid selected function body extent')
            if byte_count > row['body_bytes']:
                problems.append('Instruction coverage exceeds selected function body')
        if problems:
            completed = False
            message += ' ' + '; '.join(problems)
        body = dict(instructions=copy.deepcopy(instructions), calls=copy.deepcopy(row.get('calls', [])),
            completed=completed, message=message)
        encoded = canonical(body).decode('utf-8')
        variant = hashlib.sha256((self.source_sha256 + at + (pseudo_sha or '') + encoded).encode()).hexdigest()
        display = str(name) + (' [comparison hint]' if side == 'new' and name else '')
        result = dict(**base, names=display or at, pseudocode=str(pseudo) if pseudo else None,
            pseudocode_sha256=pseudo_sha, completed=completed, message=message, variant=variant,
            body_json=encoded, instructions=body['instructions'], calls=body['calls'], observations=1)
        self.checked_variants[variant] = copy.deepcopy(result)
        return result

    def select(self, hints):
        hints = self.discover_candidates(None, hints)
        self._hints = copy.deepcopy(hints)
        by_address = {at: {} for at in self.addresses}
        unresolved = {at: [] for at in self.addresses}
        for hint in hints:
            if hint.get('receipt') is None:
                continue
            for row in self.admit_export_rows(hint['report'], hint['receipt']):
                if row['variant'] is None:
                    unresolved[row['address']].append(row)
                    continue
                variants = by_address[row['address']]
                if row['variant'] not in variants:
                    variants[row['variant']] = row
                else:
                    variants[row['variant']]['observations'] += 1
        functions = []
        for at in self.addresses:
            variants = list(by_address[at].values())
            usable = [row for row in variants if row['completed'] and row['pseudocode'] and row['instructions']]
            if len(variants) > 1:
                raise ValueError('Selected address has ambiguous checked variants: ' + at)
            state = 'ready' if usable else 'incomplete' if variants or unresolved[at] else 'candidate_missing_requires_discovery'
            functions.append(dict(address=at, state=state, variants=variants, unresolved=unresolved[at]))
        self.functions = copy.deepcopy(functions)
        return functions

    def pin_context(self, explicit_question=None, explicit_fact_ids=(), explicit_evidence_pointers=()):
        question = explicit_question or self.question_id
        if not isinstance(question, str) or not question.strip():
            raise ValueError('Explicit scoped question ID required')
        data = self.json(self.knowledge / 'questions.json', kind='registry')
        matches = [row for row in data['questions'] if row.get('id') == question]
        if len(matches) != 1:
            raise ValueError('Unknown or ambiguous scoped question ID')
        if self.question_id is not None and self.question_id != question:
            raise ValueError('Scoped question selection changed')
        self.question_id = question
        selected = [dict(kind='question', id=question, payload=matches[0],
            applicability='explicit_navigation_not_release_proof')]
        ids = list(explicit_fact_ids)
        if len(ids) != len(set(ids)) or len(ids) > 128:
            raise ValueError('Scoped fact IDs must be unique and bounded')
        if ids:
            facts = self.json(self.knowledge / 'releases' / self.source_sha256 / 'facts.json', kind='registry')
            if facts.get('source_sha256') != self.source_sha256:
                raise ValueError('Scoped fact registry source differs')
            for identifier in ids:
                found = [fact for fact in facts['facts'] if fact.get('id') == identifier]
                if len(found) != 1:
                    raise ValueError('Unknown or ambiguous explicit scoped fact ID')
                fact = found[0]
                if fact.get('source_sha256') != self.source_sha256 or fact.get('question') != question:
                    raise ValueError('Selected fact source/question differs')
                if not fact.get('addresses') or any(address(at) != at for at in fact['addresses']):
                    raise ValueError('Selected fact requires canonical addresses')
                for key in ('id', 'question', 'conclusion', 'method', 'unknown', 'next_check'):
                    if not isinstance(fact.get(key), str) or not fact[key].strip():
                        raise ValueError('Selected fact lacks ' + key)
                if not isinstance(fact.get('limits'), list) or not fact['limits'] or any(
                        not isinstance(value, str) or not value.strip() for value in fact['limits']):
                    raise ValueError('Selected fact lacks explicit limits')
                if not fact.get('evidence'):
                    raise ValueError('Selected fact lacks evidence')
                for evidence in fact['evidence']:
                    self._pointer(evidence, 'evidence')
                if fact['method'] == 'bounded_native' and not fact.get('checks'):
                    raise ValueError('Selected native fact lacks registered checks')
                for check in fact.get('checks', []):
                    checked = self.json(check['report'], full_sha(check['sha256']), kind='check')
                    if check.get('state') != 'passed' or checked.get('state') != 'passed' or \
                            checked.get('definition', {}).get('source_sha256') != self.source_sha256:
                        raise ValueError('Selected fact check state/source differs')
                selected.append(dict(kind='fact', id=identifier, payload=fact))
        for evidence in explicit_evidence_pointers:
            selected.append(dict(kind='evidence', pointer=self._pointer(evidence, 'evidence')))
        self.context = selected
        return copy.deepcopy(selected)

    def add_outputs(self, new_export_receipts):
        """Validate new collector pointers; caller owns its sidecar/index writes."""
        return self.select(self.discover_candidates(None, [*self._hints, *new_export_receipts]))

    def finish_barrier(self):
        started = time.perf_counter()
        self.source_store.validate()
        for path, row in self._files.items():
            if digest(path) != row['sha256']:
                raise ValueError('Selected input changed during scoped validation: ' + str(path))
            self.metrics['barrier_reads'] += 1
            self.metrics['barrier_bytes'] += len(row['raw'])
        self.metrics['barrier_seconds'] += round(time.perf_counter() - started, 6)
        inputs = [dict(path=str(path), sha256=row['sha256'], kind=row['kind'])
            for path, row in sorted(self._files.items(), key=lambda item: str(item[0]))]
        for sha in sorted(self.source_store._sources):
            path = self.root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe'
            inputs.append(dict(path=str(path), sha256=sha, kind='source'))
        declaration = dict(schema=2, recipe=RECIPE, format=FORMAT, source_sha256=self.source_sha256,
            source=str(self.source_path), ordered_addresses=list(self.addresses), question_id=self.question_id,
            selected_context=copy.deepcopy(self.context),
            inputs={row['path']:row['sha256'] for row in inputs}, consumed_materials=inputs,
            selected_functions=copy.deepcopy(self.functions), runtime=copy.deepcopy(self.runtime),
            validation_scope='selected_materials_only', global_history_verified=False,
            coverage=dict(selected_source_addresses_only=True, global_history_checked=False,
                unselected_report_outputs_checked=False, role_transfer=False,
                client_semantics_proven=False, online_admission=False))
        return dict(**declaration, validation_sha256=hashlib.sha256(canonical(declaration)).hexdigest(),
            metrics=dict(self.metrics, source_store=dict(self.source_store.metrics)))
