"""Run native polygon corridors on bounded real tiles from the candidate export."""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('path_evidence_emu',HERE/'recast-path-query-emulator.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);em=module.PathQueryEmulator(root)
    folder=root/'maps/navigation-study/tile-buffer-hypothesis-97';manifest_raw=(folder/'index.json').read_bytes();manifest=json.loads(manifest_raw)
    tiles=[];cases=[];buffers={}
    for pi,package in enumerate(manifest['packages']):
        buf=(folder/package['buffer_file']).read_bytes()
        if sha(buf)!=package['buffer_sha256']:raise ValueError('Changed buffer file')
        for record in package['records']:
            raw=buf[record['buffer_offset']:record['buffer_offset']+record['actual_memory_size']]
            if sha(raw)!=record['tile_sha256']:raise ValueError('Changed tile')
            pc=struct.unpack_from('<H',raw,4)[0]
            if not 4<=pc<=64:continue
            sections=module.parent.tile_sections(raw)
            if any(raw[sections[16]+32*p+31]>=64 for p in range(pc)):continue
            em.prepare(raw,[1.]*64,[0.]*64,65535,0,512)
            reached={0};queue=[0]
            for p in queue:
                for n in em.adjacency[p]:
                    if n not in reached:reached.add(n);queue.append(n)
            if len(reached)<4:continue
            identifier=len(tiles);buffers[identifier]=raw
            tiles.append(dict(id=identifier,package_index=pi,record_index=record['index'],buffer_file=package['buffer_file'],
                buffer_sha256=package['buffer_sha256'],offset=record['buffer_offset'],length=len(raw),sha256=sha(raw),polygons=pc,
                last_reachable=queue[-1]))
            break
    if not tiles:raise ValueError('No suitable ordinary real tiles')
    def run(tile,name,start,end,**settings):
        result=em.search(buffers[tile['id']],start,end,**settings)
        cases.append(dict(tile=tile['id'],name=name,start=start,end=end,settings=settings,result=result))
    for tile in tiles:
        end=tile['last_reachable']
        run(tile,'forward',0,end);run(tile,'reverse',end,0);run(tile,'same_polygon',0,0)
    tile=tiles[0];end=tile['last_reachable']
    run(tile,'all_neighbor_flags_rejected',0,end,include=0)
    run(tile,'all_neighbor_flags_excluded',0,end,exclude=65535)
    run(tile,'one_node_capacity',0,end,node_capacity=1)
    run(tile,'zero_cost_limit',0,end,cost_limit=0.)
    run(tile,'scaled_travel',0,end,travel=[2.5]*64)
    run(tile,'area_dependent_costs',0,end,travel=[1.+i/16 for i in range(64)],entering=[i/8 for i in range(64)])
    # All pairs on the first actual tile exercise partial paths as well as routes.
    for start in range(tile['polygons']):
        for target in range(tile['polygons']):run(tile,'all_pairs',start,target)
    start=0x14523c6c1;end=0x14523c77a;offset=em.image.offset(start-em.image.pe.base)
    block=em.data[offset:offset+end-start]
    report=dict(source=str(json.loads((root/'code-clues/native-enums.json').read_text())['source']),sha256=sha(em.data),
        emulator_sha256=sha((HERE/'recast-path-query-emulator.py').read_bytes()),
        parent_emulator_sha256=sha((HERE/'recast-portal-emulator.py').read_bytes()),
        buffer_manifest_sha256=sha(manifest_raw),geometry_proof_sha256=sha(em.geometry_proof),
        fragments=em.query_fragments,internal_link_block=dict(begin=start,end_before_special_attachment=end,
            file_offset=offset,sha256=sha(block),raw_hex=block.hex()),
        native_pages=list(em.pages.values()),tiles=tiles,cases=cases,
        synthetic_inputs=dict(tile_salt=1,tile_bits=16,polygon_bits=24,tile_count=1,query_object_zero_except_recorded_fields=True,
            filter='Explicit 64 travel/entering arrays; include/exclude flags; heuristic minimum and scale=1; virtual filter disabled',
            node_capacity_default=512,output_capacity=512,hash_size=512,endpoint='Arithmetic polygon vertex centers; no point projection'),
        summary=dict(native_cases=len(cases),real_tiles=len(tiles),path_search_executed=True,
            external_links_executed=False,special_links_executed=False,routes_verified=0,navigation_ready=False),
        limitations=['Single explicit candidate tile per case; archive layout97/propertyoffset14 and active package coverage remain hypotheses.',
            'Native internal-link block and entire query execute. Query object/pool/filter are synthetic bounded inputs, not active runtime state.',
            'Only hash-table memset and query cookie check are replaced; allocation branch forbidden, no OS/game process calls.',
            'Polygon centers are synthetic endpoints; endpoint projection, straight path/funnel, external/special links and movement are not tested.',
            'Connectivity and returned corridor cost can be independently checked; global shortest-path optimality is not asserted.',
            'A local polygon corridor is not a verified route usable by a game character.'])
    path=root/'code-clues/recast-path-query-evidence.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()))));return report

if __name__=='__main__':main()
