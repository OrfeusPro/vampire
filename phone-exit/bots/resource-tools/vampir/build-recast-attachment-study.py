"""Execute native start/end attachment for explicit candidate priority scenarios."""
import hashlib,importlib.util,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';read=lambda path:json.loads(path.read_bytes())
    spec=importlib.util.spec_from_file_location('full_attachment_study',HERE/'recast-attachment-emulator.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    emulator=module.AttachmentEmulator(root)
    bv_path=study/'special-links/bv-priority-study.json';bv_bytes=bv_path.read_bytes();bv=json.loads(bv_bytes)
    for file,digest in bv['model_sha256'].items():
        if sha((HERE/file).read_bytes())!=digest:raise ValueError('Changed BV study model')
    point_bytes=(study/'special-links/index.json').read_bytes();points=json.loads(point_bytes)
    if sha(point_bytes)!=bv['source_special_report_sha256']:raise ValueError('Changed special points')
    grid_bytes=(study/'geometry-hypothesis-97/grid-inventory.json').read_bytes();grid=json.loads(grid_bytes)
    if sha(grid_bytes)!=bv['source_grid_report_sha256']:raise ValueError('Changed grid')
    baseline_bytes=(study/'special-links/nearest-candidates.json').read_bytes();baseline=json.loads(baseline_bytes)
    if sha(baseline_bytes)!=bv['source_baseline_sha256']:raise ValueError('Changed query baseline')
    index_bytes=(study/'tile-buffer-hypothesis-97/index.json').read_bytes();index=json.loads(index_bytes)
    if sha(index_bytes)!=baseline['source_buffer_report_sha256']:raise ValueError('Changed buffers report')
    packages=[]
    for package in index['packages']:
        raw=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes()
        if sha(raw)!=package['buffer_sha256']:raise ValueError('Changed buffers')
        packages.append(raw)
    def tile_raw(tile):
        row=grid['tiles'][tile];origin=row['sources'][0];package=index['packages'][origin['package_index']];record=package['records'][origin['tile_index']]
        raw=packages[origin['package_index']][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
        if sha(raw)!=row['buffer_hashes'][0]:raise ValueError('Changed attachment tile')
        return raw
    cases=[]
    for p,previous in zip(points['links'],baseline['links']):
        if p['id']!=previous['id']:raise ValueError('Changed point order')
        grid_point=grid['tiles'][p['tile']]['grid'];side=p['side_raw']
        step=(0,0) if side==128 else module.base.base.parent.SIDE_STEPS[side]
        expected_grid=[grid_point[0]+step[0],grid_point[1]+step[1]]
        targets=[c['tile'] for c in previous['end_candidates'] if grid['tiles'][c['tile']]['grid']==expected_grid]
        cases.append(dict(id=p['id'],source_tile=p['tile'],source_tile_sha256=grid['tiles'][p['tile']]['buffer_hashes'][0],
            special_index=p['index'],special_polygon=p['polygon'],side_raw=side,expected_target_grid=expected_grid,
            target_tiles=targets,baked_vertices=p['baked_vertex_nav']))
    results=[];executions=0
    for mode in bv['modes']:
        if mode['priorities'] is None:continue
        rows=[]
        for case in cases:
            owner=tile_raw(case['source_tile']);pairs=[]
            for tile in case['target_tiles']:
                target=tile_raw(tile);result=emulator.attach(owner,target,bv['quantization_candidate'],mode['priorities'],case['special_index'],case['side_raw'],tile==case['source_tile'])
                source_links=lambda state:[l for l in state['links'] if l['source_tile_index']==0 and l['source_polygon']==case['special_polygon']]
                start=any(l['edge_raw']==0 for l in source_links(result['start_state']))
                end=any(l['edge_raw']==1 for l in source_links(result['end_state']))
                pairs.append(dict(target_tile=tile,target_tile_sha256=sha(target),start_connected=start,end_connected=end,
                    matches_baked_vertices=start and end and result['end_state']['vertices_nav']==case['baked_vertices'],result=result))
                executions+=1
            rows.append(dict(id=case['id'],pairs=pairs))
        summary=dict(start_connected=sum(any(p['start_connected'] for p in row['pairs']) for row in rows),
            both_connected=sum(any(p['start_connected'] and p['end_connected'] for p in row['pairs']) for row in rows),
            both_connected_matching_baked=sum(any(p['matches_baked_vertices'] for p in row['pairs']) for row in rows))
        results.append(dict(name=mode['name'],priorities=mode['priorities'],summary=summary,links=rows))
    rows={r['address']:r for f in emulator.attachment_fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [(0x14523dafd,'jbe','0x14523db66'),(0x14523db60,'ja','0x14523dbf8'),
        (0x14523f61c,'cmp','byte ptr [rbx + 0x4a], al'),(0x14523f649,'je','0x14523f8db'),
        (0x14523f6be,'je','0x14523f6f6'),(0x14523f6f4,'jbe','0x14523f768'),
        (0x14523f728,'je','0x14523f8db'),(0x14523f762,'ja','0x14523f8db'),
        (0x14523dbbe,'call','0x14524faf0'),(0x14523dbf3,'call','0x14524faf0'),
        (0x14523f7cc,'call','0x14524faf0'),(0x14523f82d,'call','0x14524faf0'),
        (0x14523f832,'cmp','byte ptr [rsp + 0xe0], 0'),(0x14524fc32,'mov','dword ptr [rsi], r10d')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed attachment anchor '+hex(address))
        anchors.append(row)
    source=read(root/'code-clues/native-enums.json')
    report=dict(source=source['source'],sha256=source['sha256'],source_bv_study_sha256=sha(bv_bytes),
        source_special_report_sha256=sha(point_bytes),source_grid_report_sha256=sha(grid_bytes),
        emulator_sha256=sha((HERE/'recast-attachment-emulator.py').read_bytes()),quantization_candidate=bv['quantization_candidate'],
        anchors=anchors,fragments=emulator.attachment_fragments,native_pages=list(emulator.pages.values()),cases=cases,modes=results,
        summary=dict(points=len(cases),target_pairs=sum(len(c['target_tiles']) for c in cases),modes=len(results),native_pair_executions=executions,
            link_pool_capacity=emulator.link_capacity,cluster_links_enabled=False,routes_verified=0,navigation_ready=False),
        limitations=['Priority arrays and quantization are explicit hypotheses from the BV study, not recovered active runtime settings.',
            'Target grid selected with stored side and candidate-union grid; runtime load order/active coverage remain unverified.',
            'Local tile copies reset polygon heads and use a bounded preallocated link pool with synthetic references; cluster linking is disabled.',
            'Native endpoint attachment is executed under these inputs; no in-game traversability or available route is proven.'])
    path=study/'special-links/attachment-study.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],results=[dict(name=m['name'],**m['summary']) for m in results],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
