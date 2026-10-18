"""Independently check candidate buffer provenance, ranges and per-tile hashes."""
import argparse,hashlib,json,struct
from pathlib import Path


def validate_package(raw,buffers,records):
    if len(raw)<30:raise ValueError('Truncated candidate export')
    version,length,count=struct.unpack_from('<iQi',raw,14)
    if version!=26 or length!=len(raw)-18 or count!=len(records):raise ValueError('Candidate envelope mismatch')
    source_cursor=30;buffer_cursor=0
    for i,tile in enumerate(records):
        size=tile['actual_memory_size'];end=tile['end'];start=tile['start']
        if tile['index']!=i or start!=source_cursor or tile['buffer_offset']!=buffer_cursor:raise ValueError('Tile range gap or overlap')
        if not (88<=size<=8*1024*1024 and start+8<=end<=len(raw) and buffer_cursor+size<=len(buffers)):raise ValueError('Tile bounds')
        if struct.unpack_from('<i',raw,start)[0]!=size or tile['stored_memory_size']!=size:raise ValueError('Tile size mismatch')
        cache=start+4+tile['stream_tile_bytes']
        if cache!=end-4 or struct.unpack_from('<i',raw,cache)[0]>=0 or tile['cache_memory_size']!=0:raise ValueError('Unsupported cache or bad stream boundary')
        data=buffers[buffer_cursor:buffer_cursor+size]
        if hashlib.sha256(data).hexdigest()!=tile['tile_sha256'] or data[:88].hex()!=tile['header']:raise ValueError('Tile buffer digest/header mismatch')
        source_cursor=end;buffer_cursor+=size
    if source_cursor!=len(raw) or buffer_cursor!=len(buffers):raise ValueError('Unaccounted bytes')
    return len(records)


def main(path):
    report=json.loads(path.read_text('utf-8'));root=path.parents[3]
    for relative,key in [('code-clues/recast-serialization-code.json','serialization_proof_sha256'),
                         ('maps/navigation-study/generated-chunks/index.json','generated_index_sha256')]:
        if hashlib.sha256((root/relative).read_bytes()).hexdigest()!=report[key]:raise ValueError('Changed source index/proof')
    source=report['source'];exe=Path(source['source']).read_bytes()
    if hashlib.sha256(exe).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    tiles=0
    for package in report['packages']:
        raw=(path.parent.parent/'generated-chunks'/package['source_file']).read_bytes()
        buffers=(path.parent/package['buffer_file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=package['source_export']['sha256'] or len(raw)!=package['source_export']['size']:raise ValueError('Changed export')
        if hashlib.sha256(buffers).hexdigest()!=package['buffer_sha256']:raise ValueError('Changed concatenated buffers')
        for page in package['pages']:
            offset=page['file_offset']
            if hashlib.sha256(exe[offset:offset+4096]).hexdigest()!=page['sha256']:raise ValueError('Changed emulated code page')
        tiles+=validate_package(raw,buffers,package['records'])
    if tiles!=report['summary']['candidate_tiles']:raise ValueError('Wrong tile total')
    print(json.dumps(dict(packages=len(report['packages']),candidate_tiles_verified=tiles,navigation_ready=False)))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('report',type=Path);args=parser.parse_args();main(args.report)
