"""Execute the distinct lobby mapper for the newly observed server error."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('lobby_result_mapper',HERE/'replay-result-error-text.py')
mapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(mapper)
# Same verified ABI/constructor fixture, different source function/domain.
mapper.ENTRY=0x1458050e0


def build():
    root=mapper.native.ROOT
    manifest=json.loads((root/'ghidra/entry-manifest.json').read_text('utf-8'))
    raw=Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=manifest['source_sha256']:raise ValueError('Client changed')
    cases=[mapper.Replay(raw,mapper.native.Image(raw)).execute(code) for code in (0,10036,10048)]
    if {case['code']:case['key'] for case in cases}!={0:'Success',10036:'IsInspect',10048:'BlockedInfo'}:
        raise ValueError('Lobby mapper labels changed')
    keys={case['key'] for case in cases if case['key']}
    index_path=root/'table-study/index.json'
    table=next(t for t in json.loads(index_path.read_text('utf-8'))['tables'] if t['file']=='ProjectRED-Windows-6106.csv')
    path=index_path.parent/table['file'];data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=table['sha256']:raise ValueError('Error table changed')
    rows=list(csv.DictReader(io.StringIO(data.decode('utf-8-sig'))))
    found=[dict(data_row=i+1,row=row) for i,row in enumerate(rows) if row['Key'] in keys]
    if len([row for row in found if row['row']['Key']=='IsInspect'])!=1:
        raise ValueError('Maintenance localization is not unique')
    return dict(source=manifest['source'],source_sha256=manifest['source_sha256'],entry=hex(mapper.ENTRY),
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        mapper_tool_sha256=hashlib.sha256((HERE/'replay-result-error-text.py').read_bytes()).hexdigest(),
        cases=cases,localization=dict(path=str(path),sha256=table['sha256'],matches=found),
        limits=['Complete native lobby mapper entry/return; the existing bounded FString constructor hook is reused.',
            'Table overrides and popup rendering are not executed. A label does not prove the server cause.',
            'No authentication, network connection, game process or retry.'])


if __name__=='__main__':
    value=build();path=mapper.native.ROOT/'code-clues/lobby-result-error-replay.json'
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        keys={case['code']:case['key'] for case in value['cases']},localization=value['localization']['matches'])))
