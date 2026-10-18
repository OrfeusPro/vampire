"""Find a parameter-only mesh stream; property boundary remains a candidate."""
import hashlib,json,math,struct
from pathlib import Path


def decode_parameter_stream(raw):
    if len(raw)!=100:raise ValueError('Expected a parameter-only v26 mesh stream')
    values=struct.unpack('<i5d2i6d',raw)
    count=values[0];origin=list(values[1:4]);widths=list(values[4:6]);capacities=list(values[6:8]);parameters=list(values[8:])
    if count!=0:raise ValueError('Tile-bearing stream not decoded here')
    if not all(math.isfinite(x) for x in origin+widths+parameters):raise ValueError('Nonfinite navigation parameter')
    if not all(x>0 for x in widths+parameters[3:]) or not all(x>=0 for x in parameters[:3]) or not all(0<x<=2147483647 for x in capacities):raise ValueError('Invalid navigation dimensions/capacities')
    return dict(tile_count=count,origin_raw=origin,tile_widths_raw=widths,capacities_raw=capacities,
                parameter_doubles_raw=parameters,link_height_parameter_candidate=parameters[2])


def find_candidates(raw):
    result=[]
    for offset in range(min(4096,max(0,len(raw)-107))):
        version,length=struct.unpack_from('<iI',raw,offset)
        if version!=26 or length!=104 or offset+4+length!=len(raw):continue
        try:decoded=decode_parameter_stream(raw[offset+8:])
        except ValueError:continue
        result.append(dict(offset=offset,version=version,length=length,property_boundary_verified=False,**decoded))
    return result


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    level_path=root/'maps/navigation-study/level/index.json';level_bytes=level_path.read_bytes();level=json.loads(level_bytes)
    entries=[e for e in level['navigation_exports'] if e['export']['type']=='NnRecastNavMesh']
    if len(entries)!=1:raise ValueError('Ambiguous navigation actor')
    entry=entries[0];raw=(level_path.parent/entry['file']).read_bytes()
    if len(raw)!=entry['export']['size'] or hashlib.sha256(raw).hexdigest()!=entry['export']['sha256']:raise ValueError('Changed navigation actor export')
    proof_path=root/'code-clues/recast-portal-code.json';proof_bytes=proof_path.read_bytes();proof=json.loads(proof_bytes)
    exe=Path(proof['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=proof['sha256']:raise ValueError('Changed client EXE')
    for fragment in proof['fragments']:
        offset=fragment['file_offset'];size=fragment['end_rva']-fragment['begin_rva']
        if hashlib.sha256(exe[offset:offset+size]).hexdigest()!=fragment['sha256']:raise ValueError('Changed parameter/portal proof')
    report=dict(source_level_report_sha256=hashlib.sha256(level_bytes).hexdigest(),source=entry,
                portal_proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),candidates=find_candidates(raw),
                limitations=['Property boundary and inheritance dispatch of this cooked actor remain unverified.',
                             'Do not apply the candidate height parameter to an active runtime mesh without those bindings.',
                             'No external links, complete graph or traversable route certified.'])
    path=level_path.parent/'nav-parameter-candidates.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(candidates=report['candidates'],sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__=='__main__':main()
