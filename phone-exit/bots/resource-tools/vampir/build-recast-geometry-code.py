"""Verify native vertex/polygon layout and internal-neighbor link construction."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main():
    spec=importlib.util.spec_from_file_location('recast_geometry_native',HERE/'build-native-entry-code.py')
    n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    image=n.Image(data)
    roots={image.roots[image.containing(a)] for a in [0x145252290,0x1452ba8b0,0x14523c2a0]}
    opaque=(0x523cdd4,0x523ce30)
    functions=[f for f in image.ranges if image.roots[f] in roots and f[:2]!=opaque]
    fragments=n.decode_ranges(image,roots,functions);rows={r['address']:r for f in fragments for r in f['instructions']}
    anchors=[]
    for address,mnemonic,operands in [
        (0x14523c2bd,'cmp','word ptr [rdx], 7'),
        (0x14523c4a8,'lea','rdx, [r12 + 0x58]'),
        (0x14523c4bf,'movzx','ecx, word ptr [r12 + 6]'),
        (0x14523c4cb,'movzx','r8d, word ptr [r12 + 4]'),
        (0x14523c4dd,'lea','rcx, [rcx + rcx*2]'),
        (0x14523c4e7,'lea','r9, [rdx + rcx*8]'),
        (0x14523c4fd,'mov','qword ptr [r14 + 0x18], rdx'),
        (0x14523c505,'shl','r8, 5'),
        (0x14523c509,'mov','qword ptr [r14 + 0x10], r9'),
        (0x14523c6d7,'cmp','byte ptr [r9 + 0x1f], 0x40'),
        (0x14523c6dc,'mov','dword ptr [r9], 0xffffffff'),
        (0x14523c6e5,'movzx','eax, byte ptr [r9 + 0x1e]'),
        (0x14523c6f3,'lea','r10, [rax*2 + 0xe]'),
        (0x14523c700,'movzx','eax, word ptr [r9 + r10]'),
        (0x14523c705,'test','ax, ax'),
        (0x14523c708,'je','0x14523c75a'),
        (0x14523c70a,'js','0x14523c75a'),
        (0x14523c735,'movzx','eax, word ptr [r9 + r10]'),
        (0x14523c73a,'dec','rax'),
        (0x14523c73d,'or','rax, r11'),
        (0x14523c740,'mov','qword ptr [rcx], rax'),
        (0x14523c743,'mov','byte ptr [rcx + 0xc], r8b'),
        (0x145252509,'movzx','ecx, word ptr [rax + 4]'),
        (0x14525250d,'cmp','edi, ecx'),
        (0x145252580,'shl','rsi, 5'),
        (0x145252584,'add','rsi, qword ptr [rdi + r13 + 0x10]'),
        (0x145252597,'movzx','ecx, byte ptr [rsi + 0x1e]'),
        (0x1452525a0,'ja','0x145252d56'),
        (0x1452525c3,'mov','r8, qword ptr [rdi + r13 + 0x18]'),
        (0x1452526a4,'lea','r9, [rsi + 4]'),
        (0x1452526b9,'movzx','eax, word ptr [r9]'),
        (0x1452526c5,'lea','rax, [rax + rax*2]'),
        (0x1452526c9,'movups','xmm0, xmmword ptr [r8 + rax*8]'),
        (0x1452526ce,'mov','rax, qword ptr [r8 + rax*8 + 0x10]'),
        (0x145252741,'movsd','xmm0, qword ptr [rsp + rax + 0x90]'),
        (0x1452bacef,'add','rsi, 0x58'),
        (0x1452bb424,'mov','qword ptr [rdi], rax'),
        (0x1452bb468,'mov','qword ptr [rdi + 8], rax'),
        (0x1452bb4ae,'mov','qword ptr [rdi + 0x10], rax'),
        (0x1452bb4e4,'add','rdi, 0x18'),
        (0x1452bb503,'mov','rdi, qword ptr [rbp - 0x20]'),
        (0x1452bb507,'add','rdi, 6'),
        (0x1452bb90e,'mov','byte ptr [rdi + 0x18], al'),
        (0x1452bb944,'mov','byte ptr [rdi + 0x19], al'),
        (0x1452bb96d,'add','rdi, 0x20'),
    ]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed geometry anchor '+hex(address))
        anchors.append(row)
    literals=[]
    for address,text in [(0x145252311,"dtNavMeshQuery::raycast doesn't have valid navmesh!"),
                         (0x145252515,'dtNavMeshQuery::raycast tried to access invalid poly with ref:0x%X (polyIdx:%d, maxPolys:%d)!')]:
        row=rows[address];va=row['rip_references'][0];offset=image.offset(va-image.pe.base);raw=(text+'\0').encode('utf-16le')
        if data[offset:offset+len(raw)]!=raw:raise ValueError('Changed raycast identity')
        literals.append(dict(address=va,file_offset=offset,text=text,bytes=raw.hex()));anchors.append(row)
    begin,end=opaque;offset=image.offset(begin);raw=data[offset:offset+end-begin]
    if not any(f[:2]==opaque for f in image.ranges):raise ValueError('Changed opaque tail range')
    report=dict(source=source['source'],sha256=source['sha256'],fragments=fragments,anchors=anchors,literals=literals,
                opaque_tail=dict(begin_rva=begin,end_rva=end,file_offset=offset,sha256=hashlib.sha256(raw).hexdigest(),bytes=raw.hex(),decoded=False),
                layout=dict(header_size=88,header_version=7,polygon_count_offset=4,vertex_count_offset=6,
                            vertex_stride=24,vertex_format='<3d',polygon_stride=32,polygon_vertices_offset=4,
                            polygon_vertex_capacity=6,polygon_neighbors_offset=16,polygon_flags_offset=28,
                            polygon_vertex_count_offset=30,polygon_area_type_raw_offset=31,
                            surface_area_type_raw_max=63,internal_neighbor_min=1,internal_neighbor_max=32767,
                            internal_neighbor_index_bias=1,first_link_is_rebuilt=True),
                limitations=['Source buffers retain explicit property/custom-version hypotheses.',
                             'Add-tile tail is opaque, not claimed as a complete CFG.',
                             'High-bit neighbor words are excluded from internal links; their external matching is not decoded.',
                             'No coordinate conversion, active package selection, cross-tile graph or route verification.'])
    path=n.ROOT/'code-clues/recast-geometry-code.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()
