"""Консервативный поиск resource cache hints без чтения historical blobs.

Отрицательный результат оставляет архив в очереди. Положительный — только повод
выполнить прежнюю полную проверку ключа, manifest и outputs. Discovery никогда
не подтверждает готовность и не используется при исполнении journal.stage.
"""
from pathlib import Path
import time


class Candidates:
    def __init__(self, index, args):
        self.index, self.args = index, args
        self._rows = None
        self.metrics = dict(discovery_reads=0, discovery_seconds=0,
            passed_resource_hints=0, invalid_hints=0, material_scans_avoided=0)

    def _discover(self):
        self._rows = {}
        started = time.perf_counter()
        directory = (self.args.root / 'knowledge/update-stages').resolve()
        for cache in sorted((self.args.root / 'knowledge/update-stage-cache').glob('*.json')):
            try:
                pointer = self.index.read_json(cache)
                self.metrics['discovery_reads'] += 1
                filename = pointer.get('report')
                if not isinstance(filename, str):
                    continue
                path = Path(filename).resolve()
                if not path.is_relative_to(directory):
                    continue
                entry = self.index.read_json(path)
                self.metrics['discovery_reads'] += 1
                inputs = entry.get('inputs') or {}
                archive = inputs.get('archive')
                if (entry.get('state') != 'completed'
                        or entry.get('result', {}).get('state') != 'passed'
                        or not isinstance(archive, str) or not entry.get('outputs')):
                    continue
                self._rows.setdefault(str(Path(archive).resolve()), []).append(inputs)
                self.metrics['passed_resource_hints'] += 1
            except (OSError, ValueError, TypeError, AttributeError):
                # An unreadable hint cannot hide a failed check: the archive
                # remains pending and Journal performs its authoritative lookup.
                self.metrics['invalid_hints'] += 1
        self.metrics['discovery_seconds'] = round(time.perf_counter() - started, 6)

    def possible(self, row, tools, *, source_sha=None, audit_sha=None):
        if self._rows is None:
            self._discover()
        def material(value):
            return None if value is None else {
                key: value.get(key) for key in ('sha256', 'size', 'pak_version')}
        archive = str(Path(row['path']).resolve())
        for candidate in self._rows.get(archive, []):
            if (candidate.get('current') == material(row.get('current'))
                    and candidate.get('baseline') == material(row.get('baseline'))
                    and candidate.get('cached_index') == (row.get('cached_index') or {})
                    and candidate.get('tools') == tools
                    and ('config_source_sha256' not in candidate
                         or candidate['config_source_sha256'] == source_sha)
                    and ('incomplete_material_audit_sha256' not in candidate
                         or candidate['incomplete_material_audit_sha256'] == audit_sha)):
                return True
        self.metrics['material_scans_avoided'] += 1
        return False
