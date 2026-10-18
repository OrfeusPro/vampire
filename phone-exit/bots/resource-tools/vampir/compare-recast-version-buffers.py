"""Compare all tile outputs for arbitrary97 and client-registered170 inputs."""
import hashlib
import json
from pathlib import Path
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main(root=Path('F:/PhoneExit Resources/Vampir')):
    study=root/'maps/navigation-study';reports=[];folders=[];source_hashes=[]
    defaults_raw=(root/'code-clues/recast-archive-defaults.json').read_bytes();defaults=json.loads(defaults_raw)
    assert defaults['summary']['registered_tile_key_version']==170
    for version in [97,170]:
        folder=study/f'tile-buffer-hypothesis-{version}';b=(folder/'index.json').read_bytes();r=json.loads(b)
        assert r['assumptions']['custom_version']==version;reports.append(r);folders.append(folder);source_hashes.append(sha(b))
    a,b=reports;assert a['source']==b['source'] and a['generated_index_sha256']==b['generated_index_sha256']==defaults['generated_index_sha256']
    assert len(a['packages'])==len(b['packages'])==34
    rows=[];tiles=0;size=0
    for old,new in zip(a['packages'],b['packages']):
        assert old['source_export']==new['source_export'] and old['source_file']==new['source_file'] and old['package']==new['package']
        raw_old=(folders[0]/old['buffer_file']).read_bytes();raw_new=(folders[1]/new['buffer_file']).read_bytes()
        assert sha(raw_old)==old['buffer_sha256'] and sha(raw_new)==new['buffer_sha256'] and raw_old==raw_new
        assert old['records']==new['records'] and old['bytes_consumed']==new['bytes_consumed']==new['export_size']
        rows.append(dict(package=new['package'],source_file=new['source_file'],source_export_sha256=new['source_export']['sha256'],
            buffer_sha256=new['buffer_sha256'],bytes=len(raw_new),tile_count=len(new['records']),all_buffer_and_record_bytes_equal=True))
        tiles+=len(new['records']);size+=len(raw_new)
    assert tiles==a['summary']['candidate_tiles']==b['summary']['candidate_tiles']==19098
    result=dict(source_report_sha256=source_hashes,source_defaults_sha256=sha(defaults_raw),
        tool_sha256=sha(Path(__file__).read_bytes()),packages=rows,
        summary=dict(packages_compared=34,tiles_compared=tiles,buffer_bytes_compared=size,all_outputs_equal=True,
            runtime_archive_propagation_verified=False,property_boundaries_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['Equality holds for these34stored exports and pinned codec at explicit97/170 inputs; it is not a universal version-equivalence claim.',
            'Package/property boundaries, flags, archive propagation, active versions and character traversal are not proved by equality.'])
    path=root/'code-clues/recast-version-buffer-comparison.json';path.write_text(json.dumps(result,indent=2),'utf-8')
    print(json.dumps(dict(**result['summary'],sha256=sha(path.read_bytes()))));return result
if __name__=='__main__':main()
