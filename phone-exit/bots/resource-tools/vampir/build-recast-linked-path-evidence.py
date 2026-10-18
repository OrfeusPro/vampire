"""Provenance-bound external and special link corridor scenarios."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('linked_evidence_emu',HERE/'recast-linked-path-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.LinkedPathEmulator(root)
    study=root/'maps/navigation-study';files={}
    def read(relative):
        raw=(study/relative).read_bytes();files[relative]=sha(raw);return json.loads(raw)
    grid=read('geometry-hypothesis-97/grid-inventory.json');index=read('tile-buffer-hypothesis-97/index.json')
    graph_report=read('external-graph-height-35.0/index.json');graph=read('external-graph-height-35.0/graph.json')
    assert files['external-graph-height-35.0/graph.json']==graph_report['graph']['sha256']
    assert files['geometry-hypothesis-97/grid-inventory.json']==graph_report['source_grid_report_sha256']
    assert files['tile-buffer-hypothesis-97/index.json']==graph_report['source_buffer_report_sha256']
    attachment=read('special-links/attachment-study.json');mode=next(m for m in attachment['modes'] if m['name']=='priority_11_63_10')
    assert files['geometry-hypothesis-97/grid-inventory.json']==attachment['source_grid_report_sha256']
    buffers={};tiles={};raws={}
    def tile(tid):
        if tid in raws:return raws[tid]
        row=grid['tiles'][tid];origin=row['sources'][0];pi=origin['package_index'];package=index['packages'][pi];record=package['records'][origin['tile_index']]
        if pi not in buffers:
            buffers[pi]=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes()
            assert sha(buffers[pi])==package['buffer_sha256']
        raw=buffers[pi][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
        assert sha(raw)==row['buffer_hashes'][0]==record['tile_sha256']
        tiles[tid]=dict(id=tid,package_index=pi,record_index=origin['tile_index'],buffer_file=package['buffer_file'],
            buffer_sha256=package['buffer_sha256'],offset=record['buffer_offset'],length=len(raw),sha256=sha(raw))
        raws[tid]=raw;return raw
    cases=[];selections=[];categories={};seen=set()
    for row in graph:
        for connection in row['connections']:
            a=row['tile_id'];p,edge,b,q,low,high=connection;pair=tuple(sorted([a,b]))
            if pair in seen:continue
            source=tile(a);target=tile(b);sections=module.parent.parent.tile_sections(source)
            side=struct.unpack_from('<H',source,sections[16]+32*p+16+2*edge)[0]&255
            if side not in [0,2,4,6]:raise ValueError('Unexpected source boundary side')
            if any(raw[module.parent.parent.tile_sections(raw)[16]+32*i+31]>=64 for raw in [source,target] for i in range(struct.unpack_from('<H',raw,4)[0])):continue
            vertices=struct.unpack_from('<6H',source,sections[16]+32*p+4);count=source[sections[16]+32*p+30]
            axis=2 if side in [0,4] else 0
            a_pos=struct.unpack_from('<3d',source,88+24*vertices[edge])[axis];b_pos=struct.unpack_from('<3d',source,88+24*vertices[(edge+1)%count])[axis]
            partial=abs(low-min(a_pos,b_pos))>1e-6 or abs(high-max(a_pos,b_pos))>1e-6
            category=str(side)+('_partial' if partial else '_full')
            if categories.get(category,0)>=3:continue
            categories[category]=categories.get(category,0)+1;seen.add(pair)
            selections.append(dict(kind='external',tiles=[a,b],side=side,start=[0,p],end=[1,q],source_connection=connection,category=category))
            if len(selections)==24:break
        if len(selections)==24:break
    for sel in selections:
        for direction in ['forward','reverse','disconnected','excluded']:
            start,end=(sel['end'],sel['start']) if direction=='reverse' else (sel['start'],sel['end'])
            options=dict(height=35.,quantization=attachment['quantization_candidate'],priorities=[0]*64,
                travel=[1.]*64,entering=[0.]*64,include=65535,exclude=65535 if direction=='excluded' else 0,node_capacity=512)
            em.prepare_pair([tile(t) for t in sel['tiles']],**options)
            connected=direction!='disconnected'
            if connected:em.connect_external(sel['side'])
            state=em.snapshot();result=em.search_prepared(start,end)
            cases.append(dict(kind='external',name=direction,selection=sel,options=options,connected=connected,start=start,end=end,state=state,result=result))
    unavailable=[];special_count=0
    for source_case,previous in zip(attachment['cases'],mode['links']):
        assert source_case['id']==previous['id']
        pair=next((p for p in previous['pairs'] if p['start_connected'] and p['end_connected'] and p['matches_baked_vertices']),None)
        if pair is None:
            unavailable.append(dict(id=source_case['id'],reason='No attachment matching baked endpoints in the explicit priority scenario'));continue
        ids=[source_case['source_tile'],pair['target_tile']];same=ids[0]==ids[1]
        sel=dict(kind='special',id=source_case['id'],tiles=ids,side=source_case['side_raw'],same_tile=same,
            special_polygon=source_case['special_polygon'],special_index=source_case['special_index'],attachment_mode=mode['name'])
        options=dict(height=35.,quantization=attachment['quantization_candidate'],priorities=mode['priorities'],
            travel=[1.]*64,entering=[0.]*64,include=65535,exclude=0,node_capacity=512)
        em.prepare_pair([tile(t) for t in ids],**options);em.connect_special(sel['side'],same_tile=same);state=em.snapshot()
        special=[0,sel['special_polygon']]
        starts=[l['target'] for l in state['links'] if l['source']==special and l['edge']==0]
        ends=[l['target'] for l in state['links'] if l['source']==special and l['edge']==1]
        if len(starts)!=1 or len(ends)!=1:raise ValueError('Special attachment mismatch')
        sel['start']=starts[0];sel['end']=ends[0];special_count+=1
        for direction in ['forward','reverse']:
            start,end=(sel['end'],sel['start']) if direction=='reverse' else (sel['start'],sel['end'])
            em.prepare_pair([tile(t) for t in ids],**options);em.connect_special(sel['side'],same_tile=same)
            state=em.snapshot();result=em.search_prepared(start,end)
            cases.append(dict(kind='special',name=direction,selection=sel,options=options,connected=True,start=start,end=end,state=state,result=result))
    dependencies=['recast-linked-path-emulator.py','recast-path-query-emulator.py','recast-portal-emulator.py']
    report=dict(source=json.loads((root/'code-clues/native-enums.json').read_bytes())['source'],sha256=sha(em.data),
        input_reports=files,dependencies={file:sha((HERE/file).read_bytes()) for file in dependencies},
        fragments=em.query_fragments+em.linked_fragments+em.fragments,native_pages=list(em.pages.values()),
        internal_block_sha256=sha(em.data[em.image.offset(0x523c6c1):em.image.offset(0x523c6c1)+0xb9]),
        tiles=list(tiles.values()),external_selections=selections,unavailable_special=unavailable,cases=cases,
        summary=dict(native_cases=len(cases),external_pairs=len(selections),external_categories=categories,
            attached_special_points=special_count,unavailable_special_points=len(unavailable),
            complete_corridors=sum(not c['result']['status']&0x40 for c in cases),
            corridors_using_special=sum([0,c['selection']['special_polygon']] in c['result']['corridor'] for c in cases if c['kind']=='special'),
            routes_verified=0,navigation_ready=False),
        limitations=['Two candidate tiles only; archive layout97/propertyoffset14, active versions/load order, height35 and quantization/priorities remain explicit hypotheses.',
            'Full native external matching/link allocation/interval quantization, special start/end attachment, and query execute in bounded scratch.',
            'External temporary malloc/free384bytes and hash memset are bounded replacements; cookie checks skipped; all other allocations forbidden.',
            '512nodes/heap/output; each tile<=256polys/512vertices/1536static links plus64runtime links; external results max16 per edge.',
            'Cluster links disabled; query custom-link callback is null, so runtime object permission/activation is not proved.',
            'Only priority_11_63_10 from prior attachment study; available special links in a live mesh are not inferred.',
            'Polygon centers are explicit endpoints; no point projection, funnel, controller movement or character traversability.'])
    path=root/'code-clues/recast-linked-path-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
