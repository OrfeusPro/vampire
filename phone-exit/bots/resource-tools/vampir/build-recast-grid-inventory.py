"""Inventory candidate grid/layer identities without selecting a runtime version."""
import collections,hashlib,json
from pathlib import Path


def inventory(observations):
    groups=collections.defaultdict(list)
    for entry in observations:
        grid=entry['grid_raw'];layer=entry['layer_raw']
        if len(grid)!=2 or not all(type(x) is int for x in grid) or type(layer) is not int:raise ValueError('Invalid grid identity')
        groups[tuple(grid)+(layer,)].append(entry)
    tiles=[];conflicts=[]
    for key,entries in sorted(groups.items()):
        hashes=sorted({e['source_tile_sha256'] for e in entries})
        row=dict(grid=list(key[:2]),layer=key[2],buffer_hashes=hashes,sources=entries)
        (tiles if len(hashes)==1 else conflicts).append(row)
    return dict(tiles=tiles,conflicts=conflicts,
                summary=dict(observations=sum(len(v) for v in groups.values()),grid_keys=len(groups),
                             identical_duplicate_occurrences=sum(len(v)-1 for v in groups.values() if len({e['source_tile_sha256'] for e in v})==1),
                             conflicting_grid_keys=len(conflicts),runtime_selection_verified=False,navigation_ready=False))


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    source_path=root/'maps/navigation-study/geometry-hypothesis-97/index.json';source_bytes=source_path.read_bytes();source=json.loads(source_bytes)
    observations=[];sides=collections.Counter();local_duplicates=[]
    for package_index,package in enumerate(source['packages']):
        raw=(source_path.parent/package['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=package['sha256']:raise ValueError('Changed geometry package')
        data=json.loads(raw);local=collections.Counter()
        for tile in data['tiles']:
            observations.append(dict(grid_raw=tile['grid_raw'],layer_raw=tile['layer_raw'],source_tile_sha256=tile['source_tile_sha256'],
                                     package_index=package_index,tile_index=tile['index']))
            local[tuple(tile['grid_raw'])+(tile['layer_raw'],)]+=1
            sides.update(e[2]&255 for e in tile['high_bit_edges_unresolved'])
        local_duplicates.extend(dict(package_index=package_index,grid=list(k),count=v) for k,v in local.items() if v>1)
    result=inventory(observations)
    result.update(source_geometry_report_sha256=hashlib.sha256(source_bytes).hexdigest(),
                  source_packages=source['packages'],high_bit_side_histogram=dict(sorted(sides.items())),within_package_duplicates=local_duplicates,
                  limitations=['Union of all stored candidate packages; active/runtime coverage remains unverified.',
                               'Identical buffers may share a grid identity; conflicting identities are quarantined without choosing a version.',
                               'Inventory does not construct cross-tile links or certify traversal.'])
    path=source_path.parent/'grid-inventory.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**result['summary'],side_histogram=dict(sides),within_package_duplicates=len(local_duplicates),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return result


if __name__=='__main__':main()
