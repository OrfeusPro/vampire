"""Verify exact serialized parameters, all tile bounds and native case replays."""
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def check_grid_record(raw,record,origin,widths):
    x,z=struct.unpack_from('<ii',raw,8);b=struct.unpack_from('<6d',raw,40)
    for mode,o,w in [('candidate',origin,widths),('rounded',[0.,0.,0.],[1000.,1000.])]:
        r=record[mode];assert r['grid']==[x,z] and r['horizontal_bounds']==[b[0],b[2],b[3],b[5]]
        deltas=[abs(b[0]-(o[0]+x*w[0])),abs(b[3]-(o[0]+(x+1)*w[0])),
            abs(b[2]-(o[2]+z*w[1])),abs(b[5]-(o[2]+(z+1)*w[1]))]
        assert r['max_error']==max(deltas)
        indices=[math.floor((b[0]-o[0])/w[0]),math.floor((b[2]-o[2])/w[1])]
        assert r['minimum_maps_to']==indices and r['minimum_grid_mismatch']==(indices!=[x,z])

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    path=root/'code-clues/recast-grid-parameter-evidence.json';report_raw=path.read_bytes();report=json.loads(report_raw)
    exe=Path(report['source']).read_bytes();assert sha(exe)==report['sha256'];inputs={}
    for file,digest in report['input_reports'].items():
        raw=(root/file).read_bytes();assert sha(raw)==digest;inputs[file]=json.loads(raw)
    for file,digest in report['dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    actor=report['actor_export'];actor_raw=(root/'maps/navigation-study/level'/actor['file']).read_bytes();assert sha(actor_raw)==actor['export']['sha256']
    parameter_source=inputs['maps/navigation-study/level/nav-parameter-candidates.json']
    assert report['parameter_candidate'] in parameter_source['candidates'] and actor==parameter_source['source']
    block=report['serialized_parameter_block'];raw=bytes.fromhex(block['raw_hex']);assert actor_raw[block['offset']:]==raw
    values=struct.unpack('<iIi5d2i6d',raw);assert values[:3]==(26,104,0)
    origin=list(values[3:6]);widths=list(values[6:8]);params=list(values[10:16])
    assert report['selected_grid']==dict(origin=origin,widths=widths)
    assert report['selected_height']==params[2] and report['selected_quantization']==params[3:]
    for page in report['native_pages']:assert sha(exe[page['file_offset']:page['file_offset']+4096])==page['sha256']
    index=inputs['maps/navigation-study/tile-buffer-hypothesis-97/index.json'];grid=inputs['maps/navigation-study/geometry-hypothesis-97/grid-inventory.json']
    assert len(report['tile_comparisons'])==len(grid['tiles']);packages=[]
    for p in index['packages']:
        raw=(root/'maps/navigation-study/tile-buffer-hypothesis-97'/p['buffer_file']).read_bytes();assert sha(raw)==p['buffer_sha256'];packages.append(raw)
    raws={}
    for ti,(record,row) in enumerate(zip(report['tile_comparisons'],grid['tiles'])):
        source=row['sources'][0];pi=source['package_index'];item=index['packages'][pi]['records'][source['tile_index']]
        raw=packages[pi][item['buffer_offset']:item['buffer_offset']+item['actual_memory_size']]
        assert record['tile']==ti and sha(raw)==record['sha256']==row['buffer_hashes'][0]==item['tile_sha256']
        check_grid_record(raw,record,origin,widths);raws[ti]=raw
    em=load('grid_parameters_replay','recast-navigation-pipeline.py').NavigationPipelineEmulator(root)
    pipeline=inputs['code-clues/recast-navigation-pipeline-evidence.json'];scenes=inputs['code-clues/recast-straight-path-evidence.json']['scenes']
    query=inputs['code-clues/recast-path-query-evidence.json'];linked=inputs['code-clues/recast-linked-path-evidence.json']
    assert len(report['cases'])==len(pipeline['cases'])
    for i,(case,previous) in enumerate(zip(report['cases'],pipeline['cases'])):
        assert case['pipeline_case']==i and case['options']==dict(previous['options'],height=params[2],quantization=params[3:])
        scene=scenes[previous['scene']];source=query if scene['kind']=='internal' else linked;original=source['cases'][scene['source_case']]
        if scene['kind']=='internal':
            tile=next(t for t in source['tiles'] if t['id']==original['tile']);record=index['packages'][tile['package_index']]['records'][tile['record_index']]
            raw=packages[tile['package_index']][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']];assert sha(raw)==tile['sha256'];pair=[raw,raw]
        else:pair=[raws[t] for t in original['selection']['tiles']]
        assert case['same_result_as_rounded']==(case['result']==previous['result'])
        assert case['same_links_as_rounded']==(case['state']==previous['state'])
        # All stage outputs are identical here, hence inherit the independently
        # audited projected geometry/cost/line of the pinned prior report.
        assert case['same_result_as_rounded'] and case['same_links_as_rounded']
        em.prepare_pair(pair,**case['options'])
        if previous['connected']:
            if scene['kind']=='external':em.connect_external(original['selection']['side'])
            elif scene['kind']=='special':em.connect_special(original['selection']['side'],same_tile=original['selection']['same_tile'])
        em.configure_grid(origin,widths)
        assert em.navigate(previous['start'],previous['end'],previous['extents'],previous['straight_options'])==case['result']
        assert em.snapshot()==case['state']
    summary=report['summary']
    assert summary['candidate_max_boundary_error']==max(r['candidate']['max_error'] for r in report['tile_comparisons'])
    assert summary['rounded_max_boundary_error']==max(r['rounded']['max_error'] for r in report['tile_comparisons'])
    for key,mode in [('candidate_minimum_grid_mismatches','candidate'),('rounded_minimum_grid_mismatches','rounded')]:assert summary[key]==sum(r[mode]['minimum_grid_mismatch'] for r in report['tile_comparisons'])
    prior_audit_path=root/'code-clues/recast-navigation-pipeline-audit.json';prior_audit_raw=prior_audit_path.read_bytes();prior_audit=json.loads(prior_audit_raw)
    assert prior_audit['source_report_sha256']==report['input_reports']['code-clues/recast-navigation-pipeline-evidence.json']
    for file,digest in prior_audit['audit_dependencies'].items():assert sha((HERE/file).read_bytes())==digest
    result=dict(source_report_sha256=sha(report_raw),prior_pipeline_audit_sha256=sha(prior_audit_raw),tiles_checked=len(raws),
        native_replays=len(report['cases']),all_prior_stage_outputs_unchanged=True,parameter_boundary_verified=False,
        runtime_parameter_selection_verified=False,routes_verified=0,navigation_ready=False)
    (path.parent/'recast-grid-parameter-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result
if __name__=='__main__':main()
