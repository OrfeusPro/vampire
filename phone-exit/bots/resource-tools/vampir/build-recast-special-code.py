"""Pin special-point fields and native attachment/filter consumers."""
import hashlib,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('special_native',HERE/'build-native-entry-code.py')
    n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'));data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    image=n.Image(data);functions=[0x1452ba8b0,0x14523da30,0x14523f590,0x145250990]
    fragments=n.decode_ranges(image,{image.roots[image.containing(a)] for a in functions});rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x1452bbead,'lea','rdi, [r14 + 0x20]'),(0x1452bc097,'lea','rdx, [rdi + 0x28]'),
        (0x1452bc0ed,'mov','byte ptr [rdi + 0x2b], al'),(0x1452bc123,'mov','byte ptr [rdi + 0x2a], al'),
        (0x1452bc15a,'cmp','eax, 0x61'),(0x1452bc17c,'mov','qword ptr [rdi + 0x20], rax'),
        (0x1452bc1bd,'lea','rdx, [rdi + 0x20]'),(0x1452bc1d1,'mov','qword ptr [rdx], rax'),
        (0x1452bc204,'add','rdi, 0x50'),(0x1452bc21f,'lea','rdi, [r14 + 0x38]'),
        (0x1452bc244,'mov','qword ptr [rdi], rax'),(0x1452bc27a,'add','rdi, 0x50'),
        (0x14523da53,'cmp','bp, word ptr [rax + 0x1a]'),(0x14523da70,'mov','rdi, qword ptr [rsi + 0x48]'),
        (0x14523da77,'movsd','xmm1, qword ptr [rdi + 0x30]'),(0x14523da7c,'movzx','ebx, word ptr [rdi + 0x48]'),
        (0x14523da80,'movsd','xmm0, qword ptr [rdi + 0x38]'),(0x14523da8d,'test','byte ptr [rdi + 0x4b], 0x40'),
        (0x14523daad,'lea','r9, [rsp + 0x58]'),(0x14523dabd,'call','0x145243b00'),
        (0x14523db1c,'call','0x145245510'),(0x14523db40,'subsd','xmm2, qword ptr [rdi]'),
        (0x14523db4b,'subsd','xmm1, qword ptr [rdi + 0x10]'),(0x14523db58,'addsd','xmm1, xmm2'),
        (0x14523db60,'ja','0x14523dbf8'),(0x14523db7a,'movsd','qword ptr [rax + rcx*8 + 0x10], xmm4'),
        (0x14523db80,'movups','xmmword ptr [rax + rcx*8], xmm3'),(0x14523dbfe,'add','r15, 0x50'),
        (0x14523f61c,'cmp','byte ptr [rbx + 0x4a], al'),(0x14523f625,'movzx','r15d, word ptr [rbx + 0x48]'),
        (0x14523f62a,'movzx','r8d, byte ptr [rbx + 0x4b]'),(0x14523f6a7,'lea','r8, [rbx + 0x18]'),
        (0x14523f6ae,'call','0x145243b00'),(0x14523f70a,'lea','r8, [rbx + 0x18]'),
        (0x14523f714,'call','0x145245510'),(0x1452509a9,'movzx','r11d, word ptr [r10 + 0x1c]'),
        (0x1452509d1,'movzx','eax, word ptr [r10 + 0x1a]'),
        (0x1452509e9,'mov','rdx, qword ptr [rax + rdx*8 + 0x40]'),
        (0x1452509ee,'test','rdx, rdx'),(0x1452509f1,'je','0x145250a03'),
        (0x1452509f6,'call','qword ptr [rax + 0x10]'),(0x145250a03,'mov','al, 1'),
    ]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed special-point anchor '+hex(address))
        anchors.append(row)
    report=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,fragments=fragments,
                layout=dict(stride=80,start=0,end=24,horizontal_radius=48,search_height=56,identifier=64,polygon=72,side=74,flags=75),
                limitations=['Native start/end attachment snaps polygon vertices after nearest-surface queries; raw endpoints are not final attachment nodes.',
                             'Zero identifier bypasses one optional virtual predicate; this is not proof of runtime availability.',
                             'Flag bits/one-way rules and component ID binding remain unresolved.'])
    path=root/'code-clues/recast-special-code.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8');print(json.dumps(dict(anchors=len(anchors),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()
