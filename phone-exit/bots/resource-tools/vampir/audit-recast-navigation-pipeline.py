"""Independent stage geometry/admission checks plus one-VM pipeline replays."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
project_audit=load('pipeline_project_audit','audit-recast-projection.py')
query_audit=load('pipeline_query_audit','audit-recast-linked-path.py')
straight_audit=load('pipeline_line_audit','audit-recast-straight-path.py')

def check_result(raws,case):
    result=case['result'];assert result['movement_verified'] is False
    for point,projection in [(case['start'],result['start_projection']),(case['end'],result['end_projection'])]:
        project_audit.check_projection(raws,dict(point=point,extents=case['extents'],grid=case['grid'],options=case['options'],
            name=case['name'],result=projection),1e-6)
    start=result['start_projection'];end=result['end_projection'];query=result['corridor_query'];line=result['line']
    if start['polygon'] is None or end['polygon'] is None:
        assert result['stage']=='projection_missing' and query is None and line is None;return
    assert query is not None
    if start['polygon']==end['polygon']:
        assert query['corridor']==[start['polygon']] and query['segment_costs']==[0.] and query['total_cost']==0.
    else:
        query_audit.check_corridor(raws,dict(start=start['polygon'],end=end['polygon'],kind='pipeline',name=case['name'],
            options=case['options'],state=case['state'],result=query),endpoint_positions=[start['point_nav'],end['point_nav']])
    if query['status']&0x40:
        assert result['stage']=='partial_corridor' and line is None;return
    assert result['stage']=='line_built' and line is not None and line['options']==case['straight_options']
    scene=dict(corridor=query['corridor'],start=start['point_nav'],end=end['point_nav'],kind='pipeline',state=case['state'],results=[line])
    if straight_audit.equal(start['point_nav'],end['point_nav']):
        assert line['status']==0x40000000 and len(line['points'])==1
        assert line['points'][0]['flags']==2 and line['points'][0]['polygon'] is None
        assert math.dist(line['points'][0]['point_nav'],start['point_nav'])<1e-6
    elif line['options']==0:straight_audit.check_scene(raws,scene)
    else:
        expected=straight_audit.model_path(raws,scene)
        straight_audit.on_ordered_polyline([p['point_nav'] for p in line['points']],expected)
        assert line['points'][0]['flags']&1 and line['points'][-1]['flags']&2
        assert math.dist(line['points'][0]['point_nav'],start['point_nav'])<1e-6 and math.dist(line['points'][-1]['point_nav'],end['point_nav'])<1e-6

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-navigation-pipeline-evidence.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256'];sources={}
    for file,digest in report['input_reports'].items():
        raw=(root/'code-clues'/file).read_bytes();assert sha(raw)==digest;sources[file]=json.loads(raw);assert sources[file]['sha256']==report['sha256']
    for file,digest in report['dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    for fragment in report['fragments']:
        off=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva'];assert sha(exe[off:off+size])==fragment['sha256']
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    em=load('pipeline_audit_native','recast-navigation-pipeline.py').NavigationPipelineEmulator(root)
    assert report['epsilon_initializer']==em.initialized_epsilon
    buffers={}
    def read(tile):
        file=tile['buffer_file']
        if file not in buffers:
            raw=(root/'maps/navigation-study/tile-buffer-hypothesis-97'/file).read_bytes();assert sha(raw)==tile['buffer_sha256'];buffers[file]=raw
        raw=buffers[file][tile['offset']:tile['offset']+tile['length']];assert sha(raw)==tile['sha256'];return raw
    scenes=sources['recast-straight-path-evidence.json']['scenes']
    for case in report['cases']:
        scene=scenes[case['scene']];source=sources[scene['source_report']];original=source['cases'][scene['source_case']];tiles={t['id']:t for t in source['tiles']}
        if scene['kind']=='internal':raw=read(tiles[original['tile']]);raws=[raw,raw]
        else:raws=[read(tiles[t]) for t in original['selection']['tiles']]
        assert case['options']==dict(scene['options'],exclude=65535 if case['name']=='all_flags_excluded' else scene['options']['exclude'])
        assert case['connected']==(case['name']!='disconnected') and case['extents']==[25.,50.,25.]
        assert case['grid']==dict(origin=[0.,0.,0.],widths=[1000.,1000.])
        assert case['straight_options']==(1 if case['name']=='area_crossings' else 0)
        start=[scene['start'][0],scene['start'][1]+20.,scene['start'][2]];end=[scene['end'][0],scene['end'][1]-20.,scene['end'][2]]
        if case['name']=='start_outside':start=[scene['start'][0]+10000.,scene['start'][1],scene['start'][2]+10000.]
        if case['name']=='end_outside':end=[scene['end'][0]+10000.,scene['end'][1],scene['end'][2]+10000.]
        if case['name']=='same_polygon':start=end=scene['start']
        assert case['start']==start and case['end']==end
        check_result(raws,case)
        em.prepare_pair(raws,**case['options'])
        if case['connected']:
            if scene['kind']=='external':em.connect_external(original['selection']['side'])
            elif scene['kind']=='special':em.connect_special(original['selection']['side'],same_tile=original['selection']['same_tile'])
        em.configure_grid(**case['grid'])
        assert em.navigate(case['start'],case['end'],case['extents'],case['straight_options'])==case['result']
        assert em.snapshot()==case['state']
    result=dict(source_report_sha256=sha(report_raw),native_replays=len(report['cases']),
        audit_dependencies={file:sha((HERE/file).read_bytes()) for file in ['audit-recast-navigation-pipeline.py','audit-recast-projection.py','audit-recast-linked-path.py','audit-recast-straight-path.py']},
        independent_projection_corridor_cost_and_line_checked=True,same_vm_pipeline=True,
        stages=report['summary']['stages'],routes_verified=0,navigation_ready=False)
    (path.parent/'recast-navigation-pipeline-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
