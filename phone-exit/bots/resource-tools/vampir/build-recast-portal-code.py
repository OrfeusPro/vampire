"""Pin external-edge matching, height sampling and serialized navigation parameters."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main():
    spec=importlib.util.spec_from_file_location('portal_native',HERE/'build-native-entry-code.py')
    n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'));data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    image=n.Image(data)
    functions=[0x14523f0e0,0x145243d60,0x14524c4d0,0x145240c20,0x14524dd50,
               0x1452b8ff0,0x1452bc8b0,0x1452b9210]
    fragments=n.decode_ranges(image,{image.roots[image.containing(a)] for a in functions})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x14523f1d0,'movzx','eax, word ptr [rax + 0xc]'),
        (0x14523f1d7,'jns','0x14523f4d6'),
        (0x14523f1dd,'movzx','ebp, al'),
        (0x14523f1e0,'cmp','r14d, -1'),
        (0x14523f299,'lea','eax, [rbp - 4]'),
        (0x14523f29c,'and','eax, 7'),
        (0x14523f2d0,'call','0x145243d60'),
        (0x14523f331,'mov','byte ptr [rcx + 0xc], r13b'),
        (0x14523f335,'mov','byte ptr [rcx + 0xd], bpl'),
        (0x14523f3c5,'mov','byte ptr [rcx + 0xe], al'),
        (0x14523f3dc,'mov','byte ptr [rcx + 0xf], al'),
        (0x145243f1b,'mov','eax, 0x8000'),
        (0x145243f2e,'or','r9w, ax'),
        (0x145244024,'cmp','word ptr [rdi + 0xc], r9w'),
        (0x145244068,'andps','xmm0, xmm3'),
        (0x14524406b,'comisd','xmm0, xmm2'),
        (0x14524406f,'ja','0x1452442a1'),
        (0x1452440e4,'movsd','xmm10, qword ptr [r10 + 0x10]'),
        (0x145244104,'comisd','xmm0, xmm2'),
        (0x145244108,'jb','0x14524429c'),
        (0x145244193,'mulsd','xmm0, xmm1'),
        (0x14524419c,'jb','0x1452442d0'),
        (0x1452441b2,'addsd','xmm0, xmm10'),
        (0x1452441bc,'mulsd','xmm0, xmm0'),
        (0x145244258,'call','0x14524c4d0'),
        (0x145244274,'call','0x14524c4d0'),
        (0x145244288,'comisd','xmm0, xmm10'),
        (0x14524428d,'jbe','0x1452442d0'),
        (0x14524c50f,'mov','r12, qword ptr [rcx + 0x28]'),
        (0x14524c543,'add','r8, qword ptr [rbx + 0x38]'),
        (0x14524c575,'mov','rax, qword ptr [rbx + 0x30]'),
        (0x14524c5ff,'call','0x145240c20'),
        (0x14524dd66,'movups','xmm1, xmmword ptr [rdx + 0x10]'),
        (0x14524dd6a,'movups','xmmword ptr [rcx + 0x10], xmm1'),
        (0x1452b901e,'mov','eax, dword ptr [rcx]'),
        (0x1452b9084,'mov','ecx, dword ptr [rdx]'),
        (0x1452b908a,'add','qword ptr [rax], 4'),
        (0x1452b906d,'call','qword ptr [rax + 0x28]'),
        (0x1452b9070,'mov','rbp, rax'),
        (0x1452b9167,'sub','ecx, ebp'),
        (0x1452b9107,'call','0x1452bc8b0'),
        (0x1452bc95f,'call','0x1452b9210'),
        (0x1452b940f,'mov','dword ptr [rsp + 0x34], eax'),
        (0x1452b949c,'mov','qword ptr [rbp + 0x180], rax'),
        (0x1452b95fe,'mov','dword ptr [rbp + 0x1a8], eax'),
        (0x1452b9643,'mov','dword ptr [rbp + 0x1ac], eax'),
        (0x1452b969c,'mov','qword ptr [rbp + 0x150], rax'),
        (0x1452b96e3,'mov','qword ptr [rbp + 0x158], rax'),
        (0x1452b972a,'mov','qword ptr [rbp + 0x160], rax'),
        (0x1452b9771,'mov','qword ptr [rbp + 0x168], rax'),
        (0x1452b97b8,'mov','qword ptr [rbp + 0x170], rax'),
        (0x1452b97ff,'mov','qword ptr [rbp + 0x178], rax'),
        (0x1452b9b63,'lea','rdx, [rbp + 0x150]'),
        (0x1452b9b6a,'call','0x14524dd50'),
    ]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed portal/parameter anchor '+hex(address))
        anchors.append(row)
    constants=[]
    for address,expected,kind in [(0x145243fc1,'00000040e17a843f','plane_and_overlap_epsilon'),
                                 (0x14523f17c,'000000000000f03f','unit_interval'),
                                 (0x14523f18d,'0000000000e06f40','interval_byte_scale')]:
        row=rows[address];va=row['rip_references'][0];offset=image.offset(va-image.pe.base);raw=data[offset:offset+8]
        if raw.hex()!=expected:raise ValueError('Changed portal constant')
        constants.append(dict(kind=kind,address=va,file_offset=offset,bytes=raw.hex(),value=struct.unpack('<d',raw)[0]));anchors.append(row)
    report=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,fragments=fragments,constants=constants,
                rules=dict(opposite_side='(side - 4) & 7',target_neighbor_word='0x8000 | opposite_side',
                           height_parameter_offset=16,outer_mesh_length_format='uint32',outer_length_includes_own_field=True,
                           parameter_stream_v26='int32 count; 5 double; 2 int32; 6 double'),
                limitations=['Native height matching can sample detail triangles; endpoint proximity alone is insufficient.',
                             'Actual property boundary/custom-version/runtime mesh parameters are not established by this code report.',
                             'No cross-tile links or traversable routes claimed.'])
    path=n.ROOT/'code-clues/recast-portal-code.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))
    return report


if __name__=='__main__':main()
