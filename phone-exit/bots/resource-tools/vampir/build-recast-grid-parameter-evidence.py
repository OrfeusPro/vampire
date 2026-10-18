"""Check serialized parameter candidate against every tile and native pipeline.

Whole-export/property boundary and effective runtime settings remain unproved.
Agreement with geometry is evidence of consistency, not active selection.
"""
import hashlib
import importlib.util
import json
import math
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def grid_comparison(raw,origin,widths):
    grid=list(struct.unpack_from('<ii',raw,8));bounds=list(struct.unpack_from('<6d',raw,40))
    predicted=[origin[axis]+(grid[j]+delta)*widths[j] for delta in [0,1] for j,axis in enumerate([0,2])]
    observed=[bounds[0],bounds[2],bounds[3],bounds[5]]
    error=max(abs(a-b) for a,b in zip(predicted,observed))
    mapped_min=[math.floor((bounds[axis]-origin[axis])/widths[j]) for j,axis in enumerate([0,2])]
    return dict(grid=grid,horizontal_bounds=observed,max_error=error,minimum_maps_to=mapped_min,
        minimum_grid_mismatch=mapped_min!=grid)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';inputs={}
    def read(path):
        raw=(root/path).read_bytes();inputs[path]=sha(raw);return json.loads(raw)
    parameters=read('maps/navigation-study/level/nav-parameter-candidates.json')
    level=read('maps/navigation-study/level/index.json')
    grid=read('maps/navigation-study/geometry-hypothesis-97/grid-inventory.json')
    buffers_index=read('maps/navigation-study/tile-buffer-hypothesis-97/index.json')
    pipeline=read('code-clues/recast-navigation-pipeline-evidence.json')
    scenes=read('code-clues/recast-straight-path-evidence.json')
    path_source=read('code-clues/recast-path-query-evidence.json');linked=read('code-clues/recast-linked-path-evidence.json')
    assert inputs['maps/navigation-study/level/index.json']==parameters['source_level_report_sha256']
    if len(parameters['candidates'])!=1:raise ValueError('Ambiguous parameter candidate')
    candidate=parameters['candidates'][0];entry=parameters['source'];actor=(study/'level'/entry['file']).read_bytes()
    assert sha(actor)==entry['export']['sha256']
    if candidate['property_boundary_verified'] or candidate['tile_count']!=0:raise ValueError('Unexpected parameter scope')
    position=candidate['offset'];values=struct.unpack_from('<iIi5d2i6d',actor,position)
    assert values[:3]==(26,104,0) and position+108==len(actor)
    origin=list(values[3:6]);widths=list(values[6:8]);native_parameters=list(values[10:16])
    assert origin==candidate['origin_raw'] and widths==candidate['tile_widths_raw'] and native_parameters==candidate['parameter_doubles_raw']
    packages=[]
    for package in buffers_index['packages']:
        raw=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes();assert sha(raw)==package['buffer_sha256'];packages.append(raw)
    comparisons=[];raw_tiles={}
    for ti,row in enumerate(grid['tiles']):
        source=row['sources'][0];pi=source['package_index'];record=buffers_index['packages'][pi]['records'][source['tile_index']]
        raw=packages[pi][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
        assert sha(raw)==row['buffer_hashes'][0]==record['tile_sha256'];raw_tiles[ti]=raw
        exact=grid_comparison(raw,origin,widths);rounded=grid_comparison(raw,[0.,0.,0.],[1000.,1000.])
        assert exact['grid']==row['grid']
        comparisons.append(dict(tile=ti,sha256=sha(raw),candidate=exact,rounded=rounded))
    module_spec=importlib.util.spec_from_file_location('grid_pipeline',HERE/'recast-navigation-pipeline.py')
    module=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(module);em=module.NavigationPipelineEmulator(root)
    sources={'recast-path-query-evidence.json':path_source,'recast-linked-path-evidence.json':linked};cases=[]
    for previous in pipeline['cases']:
        scene=scenes['scenes'][previous['scene']];source=sources[scene['source_report']];case=source['cases'][scene['source_case']]
        if scene['kind']=='internal':
            tile=next(t for t in source['tiles'] if t['id']==case['tile']);pi=tile['package_index'];record=buffers_index['packages'][pi]['records'][tile['record_index']]
            raw=packages[pi][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']];assert sha(raw)==tile['sha256'];raws=[raw,raw]
        else:raws=[raw_tiles[t] for t in case['selection']['tiles']]
        options=dict(previous['options'],height=native_parameters[2],quantization=native_parameters[3:])
        em.prepare_pair(raws,**options)
        if previous['connected']:
            if scene['kind']=='external':em.connect_external(case['selection']['side'])
            elif scene['kind']=='special':em.connect_special(case['selection']['side'],same_tile=case['selection']['same_tile'])
        em.configure_grid(origin,widths)
        result=em.navigate(previous['start'],previous['end'],previous['extents'],previous['straight_options'])
        cases.append(dict(pipeline_case=len(cases),options=options,result=result,state=em.snapshot(),
            same_result_as_rounded=result==previous['result'],same_links_as_rounded=em.snapshot()==previous['state']))
    report=dict(source=linked['source'],sha256=sha(em.data),input_reports=inputs,
        dependencies={file:sha((HERE/file).read_bytes()) for file in ['build-recast-grid-parameter-evidence.py','recast-navigation-pipeline.py',
            'recast-projection-emulator.py','recast-straight-path-emulator.py','recast-linked-path-emulator.py','recast-path-query-emulator.py','recast-portal-emulator.py']},
        actor_export=entry,parameter_candidate=candidate,serialized_parameter_block=dict(offset=position,raw_hex=actor[position:].hex()),
        selected_grid=dict(origin=origin,widths=widths),selected_height=native_parameters[2],selected_quantization=native_parameters[3:],
        tile_comparisons=comparisons,cases=cases,native_pages=list(em.pages.values()),
        summary=dict(candidate_tiles=len(comparisons),candidate_max_boundary_error=max(r['candidate']['max_error'] for r in comparisons),
            rounded_max_boundary_error=max(r['rounded']['max_error'] for r in comparisons),
            candidate_minimum_grid_mismatches=sum(r['candidate']['minimum_grid_mismatch'] for r in comparisons),
            rounded_minimum_grid_mismatches=sum(r['rounded']['minimum_grid_mismatch'] for r in comparisons),
            native_pipeline_cases=len(cases),changed_pipeline_results=sum(not c['same_result_as_rounded'] for c in cases),
            changed_constructed_links=sum(not c['same_links_as_rounded'] for c in cases),
            runtime_parameter_selection_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Parameter block is an exact cooked export suffix, but UObject property boundary/inheritance serializer dispatch and runtime overrides remain unproved.',
            'All geometry is the deduplicated candidate union, not an active runtime set. Grid-boundary agreement does not prove package load order.',
            'The comparison replaces only origin/widths/height/quantization; explicit filter/priorities/hashmask0/TLS/callback restrictions remain synthetic.',
            '380 previous finite-extent pipeline cases do not test every seam point or live coordinate; no character movement.'])
    path=root/'code-clues/recast-grid-parameter-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report
if __name__=='__main__':main()
