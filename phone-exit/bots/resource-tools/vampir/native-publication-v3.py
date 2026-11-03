"""Кэш проверок одного прохода и явный перенос квитанций publication v2.

Рецепт v3 хранит собственный guard и namespace. Снимок прежнего semantic
контракта сохраняется целиком; новый алгоритм не выдаётся за старый v2.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('publication_v3_parent', HERE/'native-publication-v2.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
CATEGORY = 'native-publication-v3'
RECIPE = 'native-publication-memo-v3'


def guard_inputs(index):
    return {str(HERE/name): index.digest(HERE/name)
        for name in ('native-publication-v3.py', 'update-native-drivers-v3.py')}


def begin(index, args, sha):
    return Session(index, args, sha)


class Session(BASE.Session):
    def __init__(self, index, args, sha):
        self._aliases, self._row_memo, self._tools_memo = {}, {}, {}
        self._tool_models, self._v3_pending = {}, {}
        self.memo_metrics = dict(memo_row_hits=0, memo_tools_hits=0,
            memo_digest_hits=0, v2_bridges=0, v3_hits=0)
        super().__init__(index, args, sha)
        self.memo_guard = guard_inputs(index)
        for path, expected in self.memo_guard.items():
            if self.actual(path) != expected:
                raise ValueError('Publication v3 recipe guard changed')

    def actual(self, path):
        lexical = str(Path(path).absolute())
        p = Path(path).resolve()
        if lexical in self._aliases and self._aliases[lexical] != p:
            raise ValueError('Publication v3 path alias changed')
        self._aliases[lexical] = p
        previous = self.files.get(str(p))
        if previous is not None:
            self.memo_metrics['memo_digest_hits'] += 1
            return previous
        return super().actual(p)

    def _tools(self, family, model):
        observed = self._tool_models.setdefault(family, [])
        if family in self._tools_memo and any(item is model for item in observed):
            self.memo_metrics['memo_tools_hits'] += 1
            return copy.deepcopy(self._tools_memo[family])
        value = super()._tools(family, model)
        if family in self._tools_memo and value != self._tools_memo[family]:
            raise ValueError('Publication v3 family validator tools differ between models')
        self._tools_memo[family] = copy.deepcopy(value)
        observed.append(model)
        return copy.deepcopy(value)

    def _row(self, family, sha, tool=None):
        descriptor = self._descriptor(family)
        path = self.root/'knowledge'/descriptor['index_relative_path']/'index.json'
        current = self.mutable(path)
        if tool is not None:
            self._tools(family, tool)
        key = (family, sha, current)
        if key in self._row_memo:
            self.memo_metrics['memo_row_hits'] += 1
            return copy.deepcopy(self._row_memo[key])
        value = super()._row(family, sha, tool)
        self._row_memo[key] = copy.deepcopy(value)
        return copy.deepcopy(value)

    def mutable(self, path, *, owned_write=False):
        value = super().mutable(path, owned_write=owned_write)
        if owned_write:
            # The publisher can repair its own row. Re-run the actual selected
            # validator after that write instead of keeping a stale decision.
            self._row_memo.clear()
        return value

    def _envelope(self, snapshot):
        return dict(schema=3, recipe=RECIPE, memo_guard=self.memo_guard,
            parent_snapshot=snapshot)

    def _cache_path(self, snapshot):
        return self.root/'knowledge/native-publication-cache-v3'/(BASE.fingerprint(self._envelope(snapshot))+'.json')

    def _read_pointer(self, path):
        raw = Path(path).read_bytes()
        if self.actual(path) != hashlib.sha256(raw).hexdigest():
            raise ValueError('Publication v3 pointer changed while reading')
        value = json.loads(raw)
        self._pointer(value)
        return value

    def _v2_basis(self, snapshot):
        path = self.root/'knowledge/native-publication-cache-v2'/(BASE.fingerprint(snapshot)+'.json')
        pointer = self._read_pointer(path)
        return dict(method='checked_v2_receipt', cache=dict(path=str(path), sha256=self.actual(path)),
            receipt=copy.deepcopy(pointer))

    def _check_basis(self, basis, snapshot):
        if not isinstance(basis, dict):
            raise ValueError('Publication v3 validation basis differs')
        if basis.get('method') == 'checked_v2_receipt':
            if set(basis) != {'method', 'cache', 'receipt'}:
                raise ValueError('Publication v3 bridge provenance differs')
            path, expected = self._pointer(basis['cache'])
            wanted = self.root/'knowledge/native-publication-cache-v2'/(BASE.fingerprint(snapshot)+'.json')
            if path != wanted.resolve() or self.actual(path) != expected:
                raise ValueError('Publication v3 bridge cache differs')
            if self._read_pointer(path) != basis['receipt']:
                raise ValueError('Publication v3 bridge receipt pointer differs')
            value = self.common.checked(self.root, basis['receipt'], BASE.CATEGORY)
            if self.actual(basis['receipt']['path']) != basis['receipt']['sha256']:
                raise ValueError('Publication v3 bridge receipt changed')
            if (value.get('schema') != BASE.SCHEMA or value.get('key') != BASE.fingerprint(snapshot)
                    or value.get('inputs') != snapshot or value.get('validation_method') != 'full_adapter_publish'
                    or value.get('runtime_activated') is not False
                    or value.get('migration_provenance', {}).get('method') != 'full_frozen_adapter_publish'
                    or value.get('migration_provenance', {}).get('final_barriers_passed') is not True):
                raise ValueError('Publication v3 bridge lacks exact completed v2 evidence')
        elif basis.get('method') == 'full_frozen_adapter_publish':
            if basis.get('final_barriers_passed') is not True or not isinstance(basis.get('files'), dict):
                raise ValueError('Publication v3 full validation provenance differs')
        else:
            raise ValueError('Unknown publication v3 validation basis')

    def _cached(self, snapshot):
        path = self._cache_path(snapshot)
        if path.is_file():
            pointer = self._read_pointer(path)
            value = self.common.checked(self.root, pointer, CATEGORY)
            if self.actual(pointer['path']) != pointer['sha256']:
                raise ValueError('Publication v3 receipt changed')
            envelope = self._envelope(snapshot)
            if (set(value) != {'schema', 'key', 'inputs', 'validation_basis', 'runtime_activated'}
                    or value['schema'] != 3 or value['key'] != BASE.fingerprint(envelope)
                    or value['inputs'] != envelope or value['runtime_activated'] is not False):
                raise ValueError('Publication v3 validation receipt differs')
            self._check_basis(value['validation_basis'], snapshot)
            self.memo_metrics['v3_hits'] += 1
            return True
        if super()._cached(snapshot):
            basis = self._v2_basis(snapshot)
            self._check_basis(basis, snapshot)
            self._v3_pending[BASE.fingerprint(self._envelope(snapshot))] = (copy.deepcopy(snapshot), basis)
            self.memo_metrics['v2_bridges'] += 1
            return True
        return False

    def publish(self, spec, tool, declaration, outcome):
        result = super().publish(spec, tool, declaration, outcome)
        # A new full frozen validation also earns only a v3 receipt. Its v2
        # snapshot is a comparison object, not an old-algorithm attestation.
        for key, snapshot in self.pending.items():
            basis = copy.deepcopy(self.migration_inputs[key])
            basis['method'] = 'full_frozen_adapter_publish'
            self._v3_pending[BASE.fingerprint(self._envelope(snapshot))] = (copy.deepcopy(snapshot), basis)
        self.pending.clear()
        return result

    def _check_aliases(self):
        if any(Path(lexical).resolve() != path for lexical, path in self._aliases.items()):
            raise ValueError('Publication v3 path alias changed before final barrier')

    def finish(self):
        if self.finished:
            raise ValueError('Publication cache session already finished')
        if guard_inputs(self.index) != self.memo_guard:
            raise ValueError('Publication v3 recipe guard changed during update')
        # tools() can discover newly created optional dependencies; fresh maps
        # from every participating model must still match the initial closure.
        for family, models in self._tool_models.items():
            for model in models:
                if BASE.Session._tools(self, family, model) != self._tools_memo[family]:
                    raise ValueError('Publication v3 validator dependency set changed')
        self._check_aliases()
        result = super().finish()  # Fresh full file/registry/runtime/source barriers.
        self._check_aliases()
        if guard_inputs(self.index) != self.memo_guard:
            raise ValueError('Publication v3 recipe guard changed after final barrier')
        for key, (snapshot, basis) in self._v3_pending.items():
            value = dict(schema=3, key=key, inputs=self._envelope(snapshot),
                validation_basis=basis, runtime_activated=False)
            pointer = self.common.receipt(self.root, CATEGORY, value)
            self.workflow.atomic(self._cache_path(snapshot), self.workflow.canonical(pointer))
            self.metrics['receipts_written'] += 1
        return dict(result, **self.memo_metrics, receipts_written=self.metrics['receipts_written'])
