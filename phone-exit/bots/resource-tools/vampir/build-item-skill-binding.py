"""Verify SkillAcquire book parameter lookup in the client's learned-skill UI path."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def main():
    def load(name,file):
        s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
    n=load('book_native','build-native-entry-code.py');imports=load('book_imports','build-object-zero-init-code.py')
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'));d=Path(source['source']).read_bytes()
    if hashlib.sha256(d).hexdigest()!=source['sha256'] or n.capstone.__version__!='5.0.6':raise ValueError('Changed client or decoder')
    im=n.Image(d)
    addresses=[0x145aa2460,0x145a80590,0x145a88700,0x145bb1eb0,0x145bb9bd0,0x146375440,0x145a8ec10,0x145bc6470]
    fragments=n.decode_ranges(im,{im.roots[im.containing(a)] for a in addresses})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[];blobs=[]
    def check(a,m,o):
        r=rows[a]
        if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed book anchor '+hex(a))
        anchors.append(r)
    def blob(a,raw,role):
        off=im.offset(a-im.pe.base)
        if d[off:off+len(raw)]!=raw:raise ValueError('Changed book data '+role)
        blobs.append(dict(address=a,file_offset=off,bytes=raw.hex(),role=role))
    def literal(a,name,encoding='ascii'):
        r=rows[a]
        if r['mnemonic']!='lea':raise ValueError('Expected name LEA')
        blob(r['rip_references'][0],(name+'\0').encode(encoding),name);anchors.append(r)
    for a,name in [(0x145a8ecd5,'Item.csv'),(0x145a8ed60,'FRdItemInfoManagerTemplate::Load'),(0x145bc6535,'Skill.csv'),
                   (0x145aa2acb,'EffectParams'),(0x146375524,'ITEMCOMMONLIMIT_ALREADY_LEARNED')]:
        literal(a,name,'utf-16le' if a==0x146375524 else 'ascii')
    for a,m,o in [
        (0x145aa2ac2,'cmp','r14, 0xc'),(0x145aa2ad2,'call','0x1487a2e49'),
        (0x145aa2b0b,'call','0x141421150'),(0x145aa2b15,'lea','rdi, [rbx + 0x70]'),
        (0x145aa2b2c,'mov','dword ptr [rdi + 8], esi'),(0x145aa2b69,'call','0x1487a2e19'),
        (0x145a805a1,'call','0x145a88700'),(0x145a805ab,'call','0x145a883c0'),
        (0x145a805b5,'mov','qword ptr [rdi + 8], rax'),(0x145a88729,'lea','rax, [rip + 0x56c9fe0]'),
        (0x14637545c,'call','0x145a80590'),(0x146375499,'call','0x141482990'),
        (0x1463754a5,'cmp','byte ptr [rax + 0x68], 4'),(0x1463754a9,'jne','0x146375583'),
        (0x1463754b8,'cmp','byte ptr [rax + 0x50], 0x3a'),(0x1463754bc,'je','0x146375583'),
        (0x146375487,'xor','esi, esi'),(0x1463754cb,'cmp','dword ptr [rax + 0x78], esi'),
        (0x1463754d0,'mov','rcx, qword ptr [rax + 0x70]'),
        (0x1463754d9,'call','qword ptr [rip + 0x25d06d1]'),(0x1463754df,'mov','edx, eax'),
        (0x1463754e5,'call','0x145bb1eb0'),(0x1463754ee,'call','0x141482990'),
        (0x1463754f3,'test','rax, rax'),(0x1463754f6,'je','0x146375583'),
        (0x145bb1ec1,'call','0x145bb9bd0'),(0x145bb1ec6,'mov','edx, ebx'),
        (0x145bb1ecb,'call','0x145bb95d0'),(0x145bb1ed5,'mov','qword ptr [rdi + 8], rax'),
        (0x145bb9bf9,'lea','rax, [rip + 0x559d970]'),
        (0x146375513,'call','qword ptr [rdx + 8]'),(0x14637551b,'call','0x1455e3f00'),
        (0x146375522,'je','0x146375583')]:check(a,m,o)
    for a,pointer,role in [(0x14b152718,0x1499885e0,'Item secondary vtable'),(0x149988618,0x145a8ec10,'Item loader'),
                            (0x14b157578,0x1499b9a00,'Skill secondary vtable'),(0x1499b9a38,0x145bc6470,'Skill loader')]:
        blob(a,struct.pack('<Q',pointer),role)
    blob(0x141482990,bytes.fromhex('488b4108c3'),'handle pointer getter')
    # Leaf lookups include every branch up to the final ret, not just first early return.
    cs=n.capstone.Cs(n.capstone.CS_ARCH_X86,n.capstone.CS_MODE_64)
    for a,end in [(0x145a883c0,0x145a88436),(0x145bb95d0,0x145bb9646)]:
        off=im.offset(a-im.pe.base);raw=d[off:off+end-a];ins=list(cs.disasm(raw,a))
        if sum(x.size for x in ins)!=len(raw):raise ValueError('Incomplete leaf decode')
        blob(a,raw,'table lookup leaf')
    binding=imports.import_at(d,im,0x148945bb0)
    if (binding['dll'].lower(),binding['name'])!=('api-ms-win-crt-convert-l1-1-0.dll','_wtoi'):raise ValueError('Changed conversion import')
    types={r['value']:r['name'] for r in source['enums']['EItemType']}
    if types.get(31)!='EItemType::SkillBook' or types.get(58)!='EItemType::SkillAcquirePotion':raise ValueError('Changed item type')
    report=dict(source=source['source'],sha256=source['sha256'],field='Item.EffectParams',target='Skill.Id',
        effect_type=4,excluded_item_types=[58],relation_verified=True,acquisition_verified=False,
        anchors=anchors,data_anchors=blobs,conversion_import=binding,fragments=fragments,
        limitations=['Proves target lookup for the already-learned UI check; does not prove successful acquisition or all server restrictions.',
                     'Builder accepts only complete positive decimal IDs within signed int32; malformed/prefix _wtoi inputs are not promoted to links.'])
    path=n.ROOT/'code-clues/item-skill-binding.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),data_anchors=len(blobs),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()
