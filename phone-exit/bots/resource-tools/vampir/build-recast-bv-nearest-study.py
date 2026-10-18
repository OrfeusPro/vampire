"""Compare BV and all area-priority orders; none is declared active runtime state."""
import hashlib,importlib.util,itertools,json,math,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def bv_triangle():
    fixture=load('bv_triangle_fixture','build-recast-portal-evidence.py')
    raw=bytearray(fixture.triangle_tile());struct.pack_into('<H',raw,24,1)
    struct.pack_into('<6d',raw,40,0,0,0,1,0,1)
    raw[208:208]=struct.pack('<6Hi',0,0,0,1,0,1,0)
    return bytes(raw)

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';read=lambda path:json.loads(path.read_bytes())
    module=load('bv_nearest_study','recast-bv-nearest-emulator.py');emulator=module.BVNearestEmulator(root)
    rows={r['address']:r for f in emulator.bv_fragments+emulator.nearest_fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1452b9771,'mov','qword ptr [rbp + 0x168], rax'),(0x1452b97b8,'mov','qword ptr [rbp + 0x170], rax'),
        (0x1452b97ff,'mov','qword ptr [rbp + 0x178], rax'),(0x1452b9b63,'lea','rdx, [rbp + 0x150]'),
        (0x1452b9b6a,'call','0x14524dd50'),(0x14524dd66,'movups','xmm1, xmmword ptr [rdx + 0x10]'),
        (0x14524dd6a,'movups','xmmword ptr [rcx + 0x10], xmm1'),(0x14524dd6e,'movups','xmm0, xmmword ptr [rdx + 0x20]'),
        (0x14524dd72,'movups','xmmword ptr [rcx + 0x20], xmm0'),(0x1452514db,'movzx','eax, byte ptr [rax + 0x26]'),
        (0x1452514ee,'movsd','xmm2, qword ptr [rcx + rax*8 + 0x18]'),(0x145251510,'and','r13w, cx'),
        (0x14525155b,'or','r12w, 1'),(0x145243c3e,'and','ecx, 0x3f'),
        (0x145243c41,'movzx','edx, byte ptr [rcx + r13 + 0x94]'),(0x145243c4a,'cmp','dl, sil'),
        (0x145243c4f,'movaps','xmm6, xmm7'),(0x145243c65,'cmp','dl, bpl'),
        (0x145243c68,'jne','0x145243cdd'),(0x145243c7f,'call','0x14523e360')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed BV/priority anchor '+hex(address))
        anchors.append(row)
    synthetic=[];raw=bv_triangle()
    for name,point,extent,expected in [('inside',[.75,0,.25],[.1,.1,.1],[.75,0,.25]),
        ('edge',[1.2,0,.25],[.3,1,.3],[1,0,.25]),('height_equal',[.75,.5,.25],[1,.5,1],[.75,0,.25]),
        ('height_rejected',[.75,.5001,.25],[1,.5,1],None)]:
        for preferred in [False,True]:
            emulator.load_tiles(raw,raw);result=emulator.query(point,extent,[1,1,1],[0]*64 if preferred else None)
            if not result['bv_used']:raise ValueError('Synthetic BV branch was not used')
            if expected is None:
                if result['polygon'] is not None:raise ValueError('Synthetic BV height exclusion failed')
            elif result['polygon']!=0 or math.dist(result['point_nav'],expected)>1e-12:raise ValueError('Synthetic BV nearest mismatch')
            synthetic.append(dict(name=name,point=point,extents=extent,expected=expected,result=result))
    parameter_path=study/'level/nav-parameter-candidates.json';parameter_bytes=parameter_path.read_bytes();parameters=json.loads(parameter_bytes)
    if len(parameters['candidates'])!=1:raise ValueError('Ambiguous parameter source')
    candidate=parameters['candidates'][0];quantization=candidate['parameter_doubles_raw'][3:]
    source_export=parameters['source'];export_bytes=(study/'level'/source_export['file']).read_bytes()
    if sha(export_bytes)!=source_export['export']['sha256']:raise ValueError('Changed parameter export')
    baseline_path=study/'special-links/nearest-candidates.json';baseline_bytes=baseline_path.read_bytes();baseline=json.loads(baseline_bytes)
    if read(study/'special-links/nearest-candidates-audit.json')['source_report_sha256']!=sha(baseline_bytes):raise ValueError('Changed baseline audit')
    point_bytes=(study/'special-links/index.json').read_bytes();points=json.loads(point_bytes)
    grid_bytes=(study/'geometry-hypothesis-97/grid-inventory.json').read_bytes();grid=json.loads(grid_bytes)
    if sha(point_bytes)!=baseline['source_special_report_sha256'] or sha(grid_bytes)!=baseline['source_grid_report_sha256']:raise ValueError('Changed nearest input')
    index_bytes=(study/'tile-buffer-hypothesis-97/index.json').read_bytes();index=json.loads(index_bytes)
    if sha(index_bytes)!=baseline['source_buffer_report_sha256']:raise ValueError('Changed buffer report')
    packages=[]
    for package in index['packages']:
        raw=(study/'tile-buffer-hypothesis-97'/package['buffer_file']).read_bytes()
        if sha(raw)!=package['buffer_sha256']:raise ValueError('Changed buffer')
        packages.append(raw)
    queries=[];areas=set()
    for point,previous in zip(points['links'],baseline['links']):
        if point['id']!=previous['id']:raise ValueError('Changed baseline point identity')
        for endpoint,tile in [(0,point['tile']),*((1,c['tile']) for c in previous['end_candidates'])]:
            origin=grid['tiles'][tile]['sources'][0];pi=origin['package_index'];record=index['packages'][pi]['records'][origin['tile_index']]
            raw=packages[pi][record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
            if sha(raw)!=grid['tiles'][tile]['buffer_hashes'][0]:raise ValueError('Changed query tile')
            pc,vc=struct.unpack_from('<HH',raw,4)
            areas.update(raw[88+24*vc+32*i+31] for i in range(pc) if raw[88+24*vc+32*i+31]<64)
            queries.append(dict(id=point['id'],endpoint=endpoint,tile=tile,source_tile_sha256=sha(raw),point=point['original_nav'][endpoint],
                extents=[point['horizontal_radius'],point['search_height'],point['horizontal_radius']],baked=point['baked_vertex_nav'][endpoint],raw=raw))
    if areas!={10,11,63}:raise ValueError('Review priority scenarios for changed area set')
    modes=[dict(name='bv_fallback',priorities=None),dict(name='bv_equal_priorities',priorities=[0]*64)]
    for order in itertools.permutations(sorted(areas)):
        priorities=[3]*64
        for rank,area in enumerate(order):priorities[area]=rank
        modes.append(dict(name='priority_'+'_'.join(map(str,order)),order=list(order),priorities=priorities))
    results=[]
    for mode in modes:
        outputs=[]
        for query in queries:
            raw=query['raw'];emulator.load_tiles(raw,raw);result=emulator.query(query['point'],query['extents'],quantization,mode['priorities'])
            radius=query['extents'][0];point=query['point'];closest=result['point_nav']
            accepted=result['polygon'] is not None and (closest[0]-point[0])**2+(closest[2]-point[2])**2<=radius**2
            outputs.append(dict(id=query['id'],endpoint=query['endpoint'],tile=query['tile'],result=result,radius_accepted=accepted,
                baked_vertex_distance=math.dist(closest,query['baked']) if result['polygon'] is not None else None))
        summary={}
        for endpoint,label in [(0,'start'),(1,'end')]:
            summary[label+'_with_candidate']=sum(any(r['id']==p['id'] and r['endpoint']==endpoint and r['radius_accepted'] for r in outputs) for p in points['links'])
            summary[label+'_matching_baked']=sum(any(r['id']==p['id'] and r['endpoint']==endpoint and r['radius_accepted'] and r['baked_vertex_distance']==0 for r in outputs) for p in points['links'])
        results.append(dict(**mode,summary=summary,queries=outputs))
    evidence_source=read(root/'code-clues/native-enums.json')
    report=dict(source=evidence_source['source'],sha256=evidence_source['sha256'],anchors=anchors,
        fragments=emulator.nearest_fragments+emulator.bv_fragments,native_pages=list(emulator.pages.values()),
        model_sha256={file:sha((HERE/file).read_bytes()) for file in ['recast-bv-nearest-emulator.py','recast-nearest-emulator.py','recast-portal-emulator.py']},
        source_baseline_sha256=sha(baseline_bytes),source_parameter_report_sha256=sha(parameter_bytes),
        source_special_report_sha256=sha(point_bytes),source_grid_report_sha256=sha(grid_bytes),
        quantization_candidate=quantization,parameter_property_boundary_verified=False,synthetics=synthetic,
        queries=[{k:v for k,v in q.items() if k!='raw'} for q in queries],modes=results,
        summary=dict(points=62,real_queries_per_mode=len(queries),modes=len(modes),native_calls=emulator.nearest_calls,
            synthetic_cases=len(synthetic),saturated_queries=sum(r['result']['capacity_saturated'] for mode in results for r in mode['queries']),
            runtime_priority_order_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Quantization comes from a parameter-stream candidate; property boundary and active runtime configuration remain unverified.',
            'All six strict priority orders are counterfactual inputs, not recovered runtime priorities or semantic area names.',
            'End tile selection is inherited from the no-BV study; no complete attachment/side dispatch/load order/active coverage verified.'])
    path=study/'special-links/bv-priority-study.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],results=[dict(name=m['name'],**m['summary']) for m in results],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
