"""Authenticated PAK names bound to existing exact record/CSV reports; no native replay."""
import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
RECIPE = 'resource-directory-v1'
LIMIT = 32 * 1024 * 1024
SHA = re.compile('[0-9a-f]{64}')


def rule(index, args):
    path = Path(args.knowledge)/'resource-directory-engine.json'
    if not path.is_file():
        return None
    with path.open('rb') as stream:
        raw = stream.read(8193)
    value = json.loads(raw)
    if (len(raw) > 8192 or not isinstance(value, dict)
            or set(value) != {'schema', 'recipe', 'key_proof'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['recipe'] != RECIPE):
        raise ValueError('Unknown resource directory recipe')
    pointer=value['key_proof']
    if (not isinstance(pointer,dict) or set(pointer)!={'path','sha256'}
            or not isinstance(pointer['path'],str) or not Path(pointer['path']).is_absolute()
            or not isinstance(pointer['sha256'],str) or not SHA.fullmatch(pointer['sha256'])):
        raise ValueError('Resource directory key proof requires an exact pointer')
    return value


def enabled(index, args):
    return rule(index, args) is not None


def _runtime(index):
    import cryptography.hazmat.bindings._rust as rust
    distribution = importlib.metadata.distribution('cryptography')
    return dict(portable=index.extension('stage-action-tools-v1').runtime(index),
        native=index.extension('update-native-harness').runtime_inputs(),
        cryptography=dict(version=distribution.version,
            record_sha256=hashlib.sha256((distribution.read_text('RECORD') or '').encode()).hexdigest(),
            binary=dict(path=str(Path(rust.__file__).resolve()),sha256=index.digest(Path(rust.__file__)))))


class Scope:
    def __init__(self, index, args):
        self.index, self.args = index, args
        self.owner = getattr(args, 'resource_owner', None)
        if self.owner is None:
            raise ValueError('Resource directory requires an open resource SHA owner')
        self.owner.check(index, args)
        self.root = Path(args.root).resolve()
        self.workflow = index.extension('research-workflow')
        self.format = index.extension('resource-directory-format-v1')
        self.core = index.extension('recover-pak-game-config')
        self.csv = index.extension('resource-csv-v3')
        self.rules = {str(HERE/name):self.owner.digest(HERE/name) for name in (
            'resource-directory-v1.py', 'resource-directory-format-v1.py',
            'recover-pak-game-config.py', 'resource-csv-v3.py', 'stage-action-tools-v1.py')}
        self.configuration = rule(index, args)
        if self.configuration is None:
            raise ValueError('Resource directory selector is missing')
        selector = Path(args.knowledge)/'resource-directory-engine.json'
        raw=selector.read_bytes()
        if len(raw)>8192 or json.loads(raw)!=self.configuration:
            raise ValueError('Resource directory selector changed during preparation')
        self.rules[str(selector.resolve())] = self.owner.remember(selector,raw)
        self.runtime = _runtime(index)
        for path, sha in self.runtime['portable']['files'].items():
            self.owner.expect(path, sha)
        binary = self.runtime['cryptography']['binary']
        self.owner.expect(binary['path'], binary['sha256'])
        self.owner.final_checks.append(self.validate_runtime)
        self.key = None
        self.key_source = None
        self.metrics = dict(archives=0, cache_hits=0, cache_writes=0,
            static_key_recoveries=0, bound_csv=0, unmatched_csv=0)

    def validate_runtime(self):
        if _runtime(self.index) != self.runtime:
            raise ValueError('Resource directory runtime changed')

    def read(self, pointer):
        if (not isinstance(pointer, dict) or set(pointer) != {'path', 'sha256'}
                or not isinstance(pointer['path'], str) or not Path(pointer['path']).is_absolute()
                or not isinstance(pointer['sha256'], str) or not SHA.fullmatch(pointer['sha256'])):
            raise ValueError('Resource directory requires an exact manifest pointer')
        path = Path(pointer['path']).resolve()
        if (not path.is_relative_to(self.root) or path.name != 'manifest.json'
                or path.parent.name != pointer['sha256']):
            raise ValueError('Resource directory manifest outside immutable library')
        with path.open('rb') as stream:
            raw = stream.read(LIMIT+1)
        if len(raw) > LIMIT or self.owner.remember(pointer['path'], raw) != pointer['sha256']:
            raise ValueError('Resource directory manifest changed or exceeds budget')
        return json.loads(raw.decode('utf-8-sig'))

    def candidate_key(self):
        if self.key is not None:
            return self.key
        proof = self.read(self.configuration['key_proof'])
        sha = proof.get('key_candidate_source_sha256', proof.get('exe_sha256'))
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise ValueError('Resource key proof needs a full historical source SHA')
        path = self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        with path.open('rb') as stream:
            raw = stream.read(512*1024*1024+1)
        if len(raw) > 512*1024*1024 or self.owner.remember(path, raw) != sha:
            raise ValueError('Historical key source changed or exceeds budget')
        sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
        import capstone
        if capstone.__version__ != '5.0.6':
            raise ValueError('Pinned directory disassembler required')
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        self.key = self.format.key_from_proof(proof, raw, decoder)
        self.key_source = dict(path=str(path),sha256=sha)
        self.metrics['static_key_recoveries'] += 1
        return self.key

    def directory(self, archive):
        key = self.candidate_key()
        size = archive.stat().st_size
        with archive.open('rb') as stream:
            stream.seek(max(0, size-512))
            tail = stream.read()
            marker = tail.rfind(struct.pack('<I', 0x5a6f12e1))
            if (marker < 17 or marker+44 > len(tail) or tail[marker-17:marker-1] != bytes(16)
                    or tail[marker-1] != 1 or struct.unpack_from('<i',tail,marker+4)[0] != 11):
                raise ValueError('Unsupported authenticated PAK directory footer')
            limit = max(0, size-512)+marker-17
            offset, count = struct.unpack_from('<QQ',tail,marker+8)
            main_info = dict(offset=offset,size=count,sha1=tail[marker+24:marker+44].hex())
            main = self.core.read_verified_index(stream, main_info, key, limit)
            metadata, encoded = self.core.parse_main(main)
            directory_info = metadata['side_indexes']['full_directory']
            raw = self.core.read_verified_index(stream, directory_info, key, limit)
            directory = self.core.parse_directory(raw, metadata['entry_count'])
        return metadata, encoded, directory, dict(main=main_info,directory=directory_info,
            decrypted_directory_sha256=hashlib.sha256(raw).hexdigest(),
            encoded_entries_sha256=hashlib.sha256(encoded).hexdigest())

    def process(self, row, record_pointer, csv_pointer):
        self.owner.check(self.index, self.args)
        self.metrics['archives'] += 1
        record = self.read(record_pointer)
        csv = self.csv.load_checked(self.index, self.args, csv_pointer)
        archive = Path(row['path']).resolve()
        current = row.get('current') or {}
        if (csv['record_index'] != record_pointer or csv['source']['path'] != str(archive)
                or csv['source']['sha256'] != current.get('sha256')
                or record['source']['sha256'] != current.get('sha256')
                or current.get('size') != archive.stat().st_size):
            raise ValueError('Resource directory archive/CSV/record identity differs')
        self.owner.expect(archive,current['sha256'])
        metadata, encoded, directory, proof = self.directory(archive)
        records = {entry['offset']:entry for entry in record['entries']}
        if len(records) != len(record['entries']):
            raise ValueError('Resource record offsets are ambiguous')
        identities, by_offset, names_seen, path_gaps = [], {}, set(), []
        for entry in directory['entries']:
            prefix = self.format.entry_prefix(encoded,entry['encoded_entry_offset'])
            if not 0 <= prefix['offset'] < record['index_offset']:
                raise ValueError('Directory record position outside archive data')
            found = records.get(prefix['offset'])
            if found is not None and any(prefix[key] != found[key]
                    for key in ('bytes','uncompressed','method','encrypted')):
                raise ValueError('Authenticated directory and record prefix disagree')
            try:
                canonical=self.format.canonical_path(metadata['mount'],entry['path'])
            except ValueError:
                canonical=None
                path_gaps.append(dict(path=entry['path'],reason='unsupported_logical_path_form'))
            identity = dict(path=entry['path'],canonical_path=canonical,
                encoded_entry_offset=entry['encoded_entry_offset'],**prefix)
            if canonical is not None and canonical in names_seen:
                raise ValueError('Authenticated directory names are ambiguous')
            if canonical is not None:names_seen.add(canonical)
            if found is not None:
                identity['record_entry'] = found['entry']
                identity['decoded_sha256'] = found.get('decoded_sha256')
            identities.append(identity)
            by_offset.setdefault(prefix['offset'],[]).append(identity)
        bindings, unmatched = [], []
        for table in csv['tables']:
            names = by_offset.get(table['offset'],[])
            if len(names) > 1:
                raise ValueError('Several authenticated names refer to one CSV record')
            if not names or names[0]['canonical_path'] is None:
                unmatched.append(dict(entry=table['entry'],offset=table['offset'],sha256=table['sha256'],
                    reason='csv_record_not_named_in_authenticated_directory' if not names else 'unsupported_logical_path_form'))
                continue
            name = names[0]
            found = records.get(table['offset'])
            if found is None or found['entry'] != table['entry'] or name['uncompressed'] != table['bytes']:
                raise ValueError('Named CSV entry/size differs from checked payload')
            if found.get('decoded_sha256') and found['decoded_sha256']!=table['sha256']:
                raise ValueError('Named CSV decoded SHA differs from record evidence')
            bindings.append(dict(table,internal_path=name['path'],canonical_path=name['canonical_path'],
                mount_point=metadata['mount'],directory_identity_verified=True))
        inputs = dict(recipe=RECIPE,source=csv['source'],record_index=record_pointer,current_csv=csv_pointer,
            key_proof=self.configuration['key_proof'],key_source=self.key_source,rules=self.rules,runtime=self.runtime)
        result = dict(schema=1,recipe=RECIPE,inputs=inputs,proof=proof,mount_point=metadata['mount'],
            directory_entries=identities,csv_bindings=bindings,unmatched_csv=unmatched,path_gaps=path_gaps,
            state='partial' if unmatched or path_gaps else 'bound',authoritative_directory_for_archive=True,
            path_hash_side_index_verified=False,key_binding_in_current_exe_verified=False,
            compatibility='not_established',runtime_activated=False)
        raw = self.workflow.canonical(result)
        if len(raw) > LIMIT:
            raise ValueError('Named resource report exceeds budget')
        identity = hashlib.sha256(self.workflow.canonical(inputs)).hexdigest()
        cache = self.root/'knowledge/resource-comparison-cache-v3'/('directory-'+identity+'.json')
        cached = self.owner.cached(cache)
        if cached is not None:
            if self.read(cached) != result:
                raise ValueError('Cached resource directory result differs from authenticated input')
            pointer = cached
            self.metrics['cache_hits'] += 1
        else:
            path = self.workflow.snapshot(self.root,'resource-directory-v1-results',result)
            pointer = dict(path=str(path),sha256=self.owner.remember(path,raw))
            self.owner.defer(cache,pointer)
            self.metrics['cache_writes'] += 1
        self.metrics['bound_csv'] += len(bindings)
        self.metrics['unmatched_csv'] += len(unmatched)
        return dict(report=pointer,state=result['state'],bound_csv=len(bindings),unmatched_csv=len(unmatched),
            path_gaps=len(path_gaps),directory_entries=len(identities),authoritative_directory_for_archive=True)


def process(index, args, row, record_pointer, csv_pointer):
    value = getattr(args,'resource_directory_v1_scope',None)
    if value is None or value.owner is not getattr(args,'resource_owner',None):
        if value is not None:value.key=None
        value = Scope(index,args)
        args.resource_directory_v1_scope = value
    return value.process(row,record_pointer,csv_pointer)


def close(args):
    value = getattr(args,'resource_directory_v1_scope',None)
    if value is None:
        return None
    value.key = None
    return copy.deepcopy(value.metrics)
