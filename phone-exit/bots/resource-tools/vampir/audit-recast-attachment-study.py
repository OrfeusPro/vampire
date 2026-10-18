"""Audit every local attachment graph and repeat selected native scenarios."""
import hashlib,importlib.util,itertools,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';read=lambda path:json.loads(path.read_bytes())
    path=study/'special-links/attachment-study.json';report=read(path)
    bv_bytes=(study/'special-links/bv-priority-study.json').read_bytes();bv=json.loads(bv_bytes)
    assert report['source_bv_study_sha256']==sha(bv_bytes)
    native=Path(report['source']).read_bytes();assert sha(native)==report['sha256']==bv['sha256']
    assert report['emulator_sha256']==sha((HERE/'recast-attachment-emulator.py').read_bytes())
    for file,digest in bv['model_sha256'].items():assert sha((HERE/file).read_bytes())==digest
    for proof in [report,bv]:
        for fragment in proof['fragments']:
            start=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva'];assert sha(native[start:start+size])==fragment['sha256']
        for page in proof['native_pages']:assert sha(native[page['file_offset']:page['file_offset']+4096])==page['sha256']
    params_path=study/'level/nav-parameter-candidates.json';assert sha(params_path.read_bytes())==bv['source_parameter_report_sha256']
    assert read(params_path)['candidates'][0]['parameter_doubles_raw'][3:]==report['quantization_candidate']==bv['quantization_candidate']
    point_bytes=(study/'special-links/index.json').read_bytes();points=json.loads(point_bytes)
    grid_bytes=(study/'geometry-hypothesis-97/grid-inventory.json').read_bytes();grid=json.loads(grid_bytes)
    assert sha(point_bytes)==report['source_special_report_sha256']==bv['source_special_report_sha256']
    assert sha(grid_bytes)==report['source_grid_report_sha256']==bv['source_grid_report_sha256']
    baseline_path=study/'special-links/nearest-candidates.json';assert sha(baseline_path.read_bytes())==bv['source_baseline_sha256']
    baseline=read(baseline_path);index_bytes=(study/'tile-buffer-hypothesis-97/index.json').read_bytes();index=json.loads(index_bytes)
    assert sha(index_bytes)==baseline['source_buffer_report_sha256']
    packages=[]
    for package in index['packages']:
        raw=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes();assert sha(raw)==package['buffer_sha256'];packages.append(raw)
    def tile_raw(tile):
        origin=grid['tiles'][tile]['sources'][0];package=index['packages'][origin['package_index']];record=package['records'][origin['tile_index']]
        raw=packages[origin['package_index']][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
        assert sha(raw)==grid['tiles'][tile]['buffer_hashes'][0];return raw
    assert len(report['cases'])==len(points['links'])==62
    steps={0:(1,0),1:(1,1),2:(0,1),3:(-1,1),4:(-1,0),5:(-1,-1),6:(0,-1),7:(1,-1),128:(0,0)}
    for case,point,old in zip(report['cases'],points['links'],baseline['links']):
        assert case['id']==point['id']==old['id'] and case['source_tile']==point['tile'] and case['special_polygon']==point['polygon']
        grid_point=grid['tiles'][point['tile']]['grid'];step=steps[point['side_raw']];expected=[grid_point[0]+step[0],grid_point[1]+step[1]]
        assert case['expected_target_grid']==expected
        assert case['target_tiles']==[c['tile'] for c in old['end_candidates'] if grid['tiles'][c['tile']]['grid']==expected]
    assert len(report['modes'])==7
    orders={tuple(m['order']) for m in bv['modes'] if 'order' in m};assert orders==set(itertools.permutations([10,11,63]))
    pairs_checked=0;replays=[]
    for mode in report['modes']:
        assert mode['priorities']==next(m['priorities'] for m in bv['modes'] if m['name']==mode['name'])
        both=matched=starts=0
        for case,row in zip(report['cases'],mode['links']):
            assert row['id']==case['id'] and [p['target_tile'] for p in row['pairs']]==case['target_tiles']
            source_raw=tile_raw(case['source_tile']);assert sha(source_raw)==case['source_tile_sha256']
            for pair in row['pairs']:
                target_raw=tile_raw(pair['target_tile']);assert sha(target_raw)==pair['target_tile_sha256'];state=pair['result']
                assert state['attachment_verified'] is False and state['native_attachment_executed'] is True and state['cluster_links_enabled'] is False
                for stage in ['start_state','end_state']:
                    links=state[stage]['links'];assert len({tuple(sorted(l.items())) for l in links})==len(links)
                    for link in links:
                        assert link['source_tile_index'] in [0,1] and link['target_tile_index'] in [0,1]
                        for field,index_field in [('source_polygon','source_tile_index'),('target_polygon','target_tile_index')]:
                            raw=[source_raw,target_raw][link[index_field]];assert 0<=link[field]<struct.unpack_from('<H',raw,4)[0]
                        reverse=[l for l in links if l['source_tile_index']==link['target_tile_index'] and l['source_polygon']==link['target_polygon'] and l['target_tile_index']==link['source_tile_index'] and l['target_polygon']==link['source_polygon']]
                        assert reverse
                connected=lambda stage,edge:any(l['source_tile_index']==0 and l['source_polygon']==case['special_polygon'] and l['edge_raw']==edge for l in state[stage]['links'])
                assert pair['start_connected']==connected('start_state',0)
                assert pair['end_connected']==connected('end_state',1)
                assert pair['matches_baked_vertices']==(pair['start_connected'] and pair['end_connected'] and state['end_state']['vertices_nav']==case['baked_vertices'])
                pairs_checked+=1
            starts+=any(p['start_connected'] for p in row['pairs']);both+=any(p['start_connected'] and p['end_connected'] for p in row['pairs']);matched+=any(p['matches_baked_vertices'] for p in row['pairs'])
        assert mode['summary']==dict(start_connected=starts,both_connected=both,both_connected_matching_baked=matched)
        for i in [0,20,40,61]:
            case=report['cases'][i];row=mode['links'][i]
            if row['pairs']:replays.append((case,row['pairs'][0],mode['priorities']))
    spec=importlib.util.spec_from_file_location('attachment_audit_native',HERE/'recast-attachment-emulator.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);emulator=module.AttachmentEmulator(root)
    for case,pair,priorities in replays:
        result=emulator.attach(tile_raw(case['source_tile']),tile_raw(pair['target_tile']),report['quantization_candidate'],priorities,case['special_index'],case['side_raw'],case['source_tile']==pair['target_tile'])
        assert result==pair['result']
    result=dict(source_report_sha256=sha(path.read_bytes()),all_native_pairs_checked=pairs_checked,native_replays=len(replays),
        best_baked_match_scenarios=[m['name'] for m in report['modes'] if m['summary']['both_connected_matching_baked']==61],
        routes_verified=0,navigation_ready=False)
    (path.parent/'attachment-study-audit.json').write_text(json.dumps(result,indent=2),'utf-8');print(json.dumps(result));return result

if __name__=='__main__':main()
