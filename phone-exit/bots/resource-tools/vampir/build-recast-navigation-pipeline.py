"""Build one-VM navigation pipeline evidence from pinned real tile scenes."""
import hashlib
import importlib.util
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('pipeline_evidence',HERE/'recast-navigation-pipeline.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.NavigationPipelineEmulator(root)
    names=['recast-straight-path-evidence.json','recast-path-query-evidence.json','recast-linked-path-evidence.json']
    sources={};digests={}
    for name in names:
        raw=(root/'code-clues'/name).read_bytes();sources[name]=json.loads(raw);digests[name]=sha(raw)
    buffers={};cases=[]
    def read(tile):
        file=tile['buffer_file']
        if file not in buffers:
            buffers[file]=(root/'maps/navigation-study/tile-buffer-hypothesis-97'/file).read_bytes();assert sha(buffers[file])==tile['buffer_sha256']
        raw=buffers[file][tile['offset']:tile['offset']+tile['length']];assert sha(raw)==tile['sha256'];return raw
    def run(scene_index,name,raws,scene,source_case,**changes):
        options=dict(scene['options']);options.update(changes.get('options',{}))
        em.prepare_pair(raws,**options)
        connected=changes.get('connected',True)
        selection=source_case.get('selection')
        if connected:
            if scene['kind']=='external':em.connect_external(selection['side'])
            elif scene['kind']=='special':em.connect_special(selection['side'],same_tile=selection['same_tile'])
        grid=dict(origin=[0.,0.,0.],widths=[1000.,1000.]);em.configure_grid(**grid)
        start=changes.get('start',[scene['start'][0],scene['start'][1]+20.,scene['start'][2]])
        end=changes.get('end',[scene['end'][0],scene['end'][1]-20.,scene['end'][2]])
        extents=[25.,50.,25.];straight_option=changes.get('straight_options',0)
        result=em.navigate(start,end,extents,straight_option)
        cases.append(dict(scene=scene_index,name=name,options=options,connected=connected,grid=grid,start=start,end=end,
            extents=extents,straight_options=straight_option,state=em.snapshot(),result=result))
    for si,scene in enumerate(sources[names[0]]['scenes']):
        source=sources[scene['source_report']];case=source['cases'][scene['source_case']];tiles={t['id']:t for t in source['tiles']}
        if scene['kind']=='internal':raw=read(tiles[case['tile']]);raws=[raw,raw]
        else:raws=[read(tiles[t]) for t in case['selection']['tiles']]
        run(si,'baseline',raws,scene,case)
        if scene['kind']=='external' and case['name']=='forward':
            run(si,'disconnected',raws,scene,case,connected=False)
            run(si,'all_flags_excluded',raws,scene,case,options=dict(exclude=65535))
            run(si,'start_outside',[*raws],scene,case,start=[scene['start'][0]+10000.,scene['start'][1],scene['start'][2]+10000.])
            run(si,'end_outside',[*raws],scene,case,end=[scene['end'][0]+10000.,scene['end'][1],scene['end'][2]+10000.])
            run(si,'same_polygon',raws,scene,case,start=scene['start'],end=scene['start'])
            run(si,'area_crossings',raws,scene,case,straight_options=1)
    report=dict(source=sources[names[0]]['source'],sha256=sha(em.data),input_reports=digests,
        dependencies={file:sha((HERE/file).read_bytes()) for file in ['recast-navigation-pipeline.py','recast-projection-emulator.py',
            'recast-straight-path-emulator.py','recast-linked-path-emulator.py','recast-path-query-emulator.py','recast-portal-emulator.py']},
        fragments=em.projection_fragments+em.straight_fragments+em.query_fragments+em.linked_fragments+em.fragments,
        native_pages=list(em.pages.values()),epsilon_initializer=em.initialized_epsilon,cases=cases,
        summary=dict(native_scenarios=len(cases),upstream_scenes=len(sources[names[0]]['scenes']),
            stages={stage:sum(c['result']['stage']==stage for c in cases) for stage in sorted({c['result']['stage'] for c in cases})},
            lines_with_special_points=sum(any(p['flags']&4 for p in c['result']['line']['points']) for c in cases if c['result']['line']),
            same_vm_pipeline=True,routes_verified=0,navigation_ready=False),
        limitations=['Analysis composition of reviewed routines, not execution of the entire recovered gameplay caller14569bcf0.',
            'All stages use the same explicit query/filter and two loaded tiles; gameplay caller filter selection is a separate prior proof, not applied here.',
            'Synthetic grid/TLS/initialized epsilon, explicit costs/height/priorities/callback restrictions remain the same as upstream evidence.',
            'Navigation coordinates and endpoint offsets are explicit inputs, not observed player coordinates; no movement commands.',
            'Missing projection or partial corridor intentionally produces no target line; this is analysis policy, not recovered client UI behavior.',
            'Active world/tile coverage, effective filters, runtime special permissions and character traversability remain unverified.'])
    path=root/'code-clues/recast-navigation-pipeline-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report
if __name__=='__main__':main()
