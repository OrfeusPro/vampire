"""Run native funnel on verified single-tile/external/special corridors."""
import hashlib
import importlib.util
import json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('straight_evidence_emu',HERE/'recast-straight-path-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.StraightPathEmulator(root)
    inputs={};reports={}
    for name in ['recast-path-query-evidence.json','recast-linked-path-evidence.json']:
        raw=(root/'code-clues'/name).read_bytes();inputs[name]=sha(raw);reports[name]=json.loads(raw)
    folder=root/'maps/navigation-study/tile-buffer-hypothesis-97';buffers={};scenes=[]
    def read(tile):
        file=tile['buffer_file']
        if file not in buffers:
            buffers[file]=(folder/file).read_bytes();assert sha(buffers[file])==tile['buffer_sha256']
        offset=tile.get('offset',tile.get('buffer_offset'));raw=buffers[file][offset:offset+tile['length']]
        assert sha(raw)==tile['sha256'];return raw
    def execute(source_name,case_index,case,raws,kind,options,selection,corridor,start_ref,end_ref):
        em.prepare_pair(raws,**options)
        if kind=='external':em.connect_external(selection['side'])
        elif kind=='special':em.connect_special(selection['side'],same_tile=selection['same_tile'])
        start=em.centers_pair[start_ref[0]][start_ref[1]];end=em.centers_pair[end_ref[0]][end_ref[1]]
        state=em.snapshot();results=[]
        for option in [0,1]:
            em.counts={};result=em.straight(corridor,start,end,option)
            if result['status']!=0x40000000:raise ValueError('Native straight-path failure')
            results.append(result)
        scenes.append(dict(source_report=source_name,source_case=case_index,kind=kind,options=options,
            corridor=corridor,start=start,end=end,state=state,results=results))
    name='recast-path-query-evidence.json';report=reports[name];tiles={t['id']:t for t in report['tiles']}
    for ci,case in enumerate(report['cases']):
        if case['name'] not in ['forward','reverse']:continue
        raw=read(tiles[case['tile']]);options=dict(height=35.,quantization=[.025,.051,.051],priorities=[0]*64,
            travel=[1.]*64,entering=[0.]*64,include=65535,exclude=0,node_capacity=512)
        execute(name,ci,case,[raw,raw],'internal',options,None,[[0,p] for p in case['result']['corridor']],[0,case['start']],[0,case['end']])
    name='recast-linked-path-evidence.json';report=reports[name];tiles={t['id']:t for t in report['tiles']}
    for ci,case in enumerate(report['cases']):
        if case['name'] not in ['forward','reverse']:continue
        execute(name,ci,case,[read(tiles[i]) for i in case['selection']['tiles']],case['kind'],case['options'],case['selection'],
            case['result']['corridor'],case['start'],case['end'])
    report=dict(source=report['source'],sha256=sha(em.data),input_reports=inputs,
        dependencies={file:sha((HERE/file).read_bytes()) for file in ['recast-straight-path-emulator.py','recast-linked-path-emulator.py','recast-path-query-emulator.py','recast-portal-emulator.py']},
        fragments=em.straight_fragments+em.query_fragments+em.linked_fragments+em.fragments,native_pages=list(em.pages.values()),
        epsilon_initializer=em.initialized_epsilon,synthetic_environment=dict(gs_base=em.teb,tls_vector=em.teb+0x1000,
            tls_block=em.tls,tls_index=0,epoch_offset=0x101184,tls_epoch=0,static_guard_epoch=0,
            static_values={hex(a):dict(size=size,raw_hex=raw.hex()) for a,(size,raw) in em.static_values.items()}),
        scenes=scenes,summary=dict(scenes=len(scenes),native_cases=sum(len(s['results']) for s in scenes),
            internal_scenes=sum(s['kind']=='internal' for s in scenes),external_scenes=sum(s['kind']=='external' for s in scenes),
            special_scenes=sum(s['kind']=='special' for s in scenes),
            ordinary_paths_with_turns=sum(len(s['results'][0]['points'])>2 for s in scenes if s['kind']!='special'),
            special_flags=sum(bool(p['flags']&4) for s in scenes for r in s['results'] for p in r['points']),
            straight_path_executed=True,routes_verified=0,navigation_ready=False),
        limitations=['Native 145248b20/portal/endpoint clamp/funnel/output execute; all source corridors are pinned upstream offline scenarios.',
            'Initialized TLS/CRT state is synthetic: index0/epoch0/guard0 and exact client initializer epsilon. CRT initialization itself is not executed.',
            'Options0 and1 only; callback permissions/cluster links disabled,512output slots; allocation forbidden, endpoint clamp cookie skipped.',
            'Input endpoints are original polygon vertex centers; native endpoint clamp is run, no live character position or controller movement.',
            'Active mesh/grid/filter/cost/link availability remain unverified. Special path flags do not prove jump/teleport gameplay semantics.'])
    path=root/'code-clues/recast-straight-path-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
