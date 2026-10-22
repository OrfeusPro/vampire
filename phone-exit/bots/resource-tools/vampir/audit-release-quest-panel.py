"""Verify selected early quest/tutorial rows against current extracted CSV. No game IO."""
import csv
import importlib.util
import io
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SHA='98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
TABLES='release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/record-indexes/a4dd6f81f00ad3c4c84b560ca008960315aa5a84655860a517c4d69c16e98896/65fc8722324efe5d0988c9d81420e89db5c309db2eb5de5d4552b16fe1022016/table-snapshots/54728d7a6bef3dfa8ea916b45f29fd1ec972e5e1a5ec1a25688b9a654ca1f7f2/manifest.json'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def run():
    native=load('quest_panel_native',HERE/'build-native-entry-code.py')
    audit=load('quest_panel_audit',HERE/'audit-client-release.py')
    root=native.ROOT
    snapshot=root/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'
    if audit.sha256(snapshot)!=SHA:raise ValueError('Current source changed')
    manifest=root/TABLES
    if audit.sha256(manifest)!=manifest.parent.name:raise ValueError('Table manifest changed')
    tables=json.loads(manifest.read_text('utf-8'));archive=Path(tables['source']['path'])
    before=archive.stat()
    if audit.sha256(archive)!=tables['source']['sha256']:raise ValueError('Installed table archive changed')
    after=archive.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
        raise ValueError('Archive changed during audit')
    graph_path=root/'quest-graph/index.json'
    graph=json.loads(graph_path.read_text('utf-8'))
    selected=(('Quest','110110'),('QuestTask','110110040'),('Tutorial','1001'),
        ('TutorialStep','1001002'),('TutorialUI','QuestPanel_PanelTouch'),('TutorialStep_Name_en','1001002'))
    rows=[];queue=[]
    for name,identity in selected:
        old=graph['sources'][name]
        candidates=[t for t in tables['tables'] if t['sha256']==old['sha256']
            or t.get('unique_schema_candidate')==old['file']]
        if len(candidates)!=1:
            queue.append(dict(table=name,reason='ambiguous_table_candidate',count=len(candidates)));continue
        current=candidates[0];old_path=root/'table-study'/old['file'];current_path=Path(current['file'])
        if audit.sha256(old_path)!=old['sha256'] or audit.sha256(current_path)!=current['sha256']:
            raise ValueError('Quest CSV changed')
        key=old['header'][0]
        def find(path):
            matches=[(i,row) for i,row in enumerate(csv.DictReader(io.StringIO(path.read_text('utf-8-sig'))),2)
                if row.get(key)==identity]
            if len(matches)!=1:return None
            return matches[0]
        previous,now=find(old_path),find(current_path)
        if previous is None or now is None:
            queue.append(dict(table=name,reason='missing_or_ambiguous_row',identity=identity));continue
        changed=[k for k,v in previous[1].items() if now[1].get(k)!=v]
        rows.append(dict(table=name,identity=identity,entry=current['entry'],
            file=str(current_path),sha256=current['sha256'],csv_record=now[0],row=now[1],
            previous=dict(file=str(old_path),sha256=old['sha256'],csv_record=previous[0]),
            changed_fields=changed,identity_proven_by_schema=False))
    report=dict(source_sha256=SHA,tool_sha256=audit.sha256(Path(__file__)),
        archive=tables['source'],table_manifest=dict(path=str(manifest),sha256=audit.sha256(manifest)),
        previous_graph=dict(path=str(graph_path),sha256=audit.sha256(graph_path)),rows=rows,queue=queue,
        limits=['Selected row candidates matched by exact SHA or unique historical schema candidate; not a whole-table identity claim.',
            'No active quest, tutorial step, UI visibility, current UI package bytes or action handler is established.',
            'No extraction, authentication, game commands or capture contents are used.'])
    path=audit.save_snapshot(root/'code-clues/release-quest-panel-audit',report)
    return path,report


if __name__=='__main__':
    path,r=run()
    print(json.dumps(dict(report=str(path),rows=len(r['rows']),queue=r['queue'],
        changed=[dict(table=v['table'],fields=v['changed_fields']) for v in r['rows'] if v['changed_fields']])))
