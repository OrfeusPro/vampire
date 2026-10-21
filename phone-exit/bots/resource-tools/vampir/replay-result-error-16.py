"""Reuse the complete native result mapper for the newly observed LoginResult 16."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('result16_mapper', HERE / 'replay-result-error-text.py')
mapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mapper)


def build(*, source_snapshot=None):
    root = mapper.native.ROOT
    manifest = json.loads((root / 'ghidra/entry-manifest.json').read_text('utf-8'))
    source = Path(manifest['source']) if source_snapshot is None else Path(source_snapshot)
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['source_sha256']: raise ValueError('Client changed')
    image = mapper.native.Image(raw)
    cases = [mapper.Replay(raw, image).execute(code) for code in (0, 16, 58)]
    if {c['code']: c['key'] for c in cases} != {0: 'Success', 16: 'InvalidState', 58: 'BlockedIp'}:
        raise ValueError('Result mapper keys changed')
    index = root / 'table-study/index.json'
    record = next(r for r in json.loads(index.read_text('utf-8'))['tables'] if r['file'] == 'ProjectRED-Windows-6106.csv')
    path = index.parent / record['file']
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != record['sha256']: raise ValueError('Error table changed')
    rows = list(csv.DictReader(io.StringIO(data.decode('utf-8-sig'))))
    matches = [(i + 1, row) for i, row in enumerate(rows) if row['Key'] == 'InvalidState']
    if len(matches) != 1: raise ValueError('Result 16 localization is not unique')
    return dict(source=str(source), source_sha256=manifest['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        mapper_tool_sha256=hashlib.sha256((HERE / 'replay-result-error-text.py').read_bytes()).hexdigest(),
        cases=cases, localization=dict(path=str(path), sha256=record['sha256'],
            provenance=record, index_sha256=hashlib.sha256(index.read_bytes()).hexdigest(),
            data_row=matches[0][0], row=matches[0][1]),
        limitations=['Actual complete mapper entry/return for codes 0/16/58; original mapper and bounded FString hook reused.',
                     'Reached instructions and literal source bytes retained; no game launch, process memory or network.',
                     'InvalidState does not identify which account/session/client state is invalid or prescribe a remedy.',
                     'Static localization join, not rendered popup or executed server code.'])


if __name__ == '__main__':
    report = build()
    path = mapper.native.ROOT / 'code-clues/result-error-16-replay.json'
    path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        keys={c['code']: c['key'] for c in report['cases']}, localization_data_row=report['localization']['data_row'])))
