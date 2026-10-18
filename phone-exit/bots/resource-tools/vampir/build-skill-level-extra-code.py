"""Verify SkillLevel Resource and StackCount replacements; no runtime prediction."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def extra_at_level(skill,changes,level):
    if type(level) is not int or not 0<=level<=32767:raise ValueError('Invalid signed int16 level')
    selected=next((r for r in changes if r['SkillInfoId']==skill['Id'] and int(r['MinLevel'])<=level<=int(r['MaxLevel'])),None)
    values={};origins={}
    for field in ['Resource','StackCount']:
        key='Change'+field;raw=selected.get(key,'') if selected else ''
        use=raw!=''
        if field=='StackCount' and use:
            if not raw.isascii() or not raw.isdecimal() or not 0<=int(raw)<=255:raise ValueError('Invalid stack byte')
            use=int(raw)!=0
        values[field]=raw if use else skill.get(field,'')
        origins[field]=dict(table='SkillLevel' if use else 'Skill',field=key if use else field,provenance=(selected if use else skill).get('provenance'))
    return dict(values=values,origins=origins,runtime_verified=False)


def main():
    spec=importlib.util.spec_from_file_location('extra_native',HERE/'build-native-entry-code.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'));d=Path(source['source']).read_bytes()
    if hashlib.sha256(d).hexdigest()!=source['sha256'] or n.capstone.__version__!='5.0.6':raise ValueError('Changed client/decoder')
    im=n.Image(d);fragments=n.decode_ranges(im,{im.roots[im.containing(a)] for a in [0x145bc6470,0x145bc89c0,0x145bba6b0,0x145bba990]})
    rows={r['address']:r for f in fragments for r in f['instructions']};anchors=[];literals=[]
    for a,m,o in [
        (0x145bc7831,'lea','rdi, [rbx + 0xf8]'),(0x145bc7849,'mov','dword ptr [rdi + 8], esi'),
        (0x145bc7612,'mov','byte ptr [rbx + 0xd4], al'),
        (0x145bc900e,'lea','rbx, [rsi + 0x20]'),(0x145bc9023,'mov','dword ptr [rbx + 8], edi'),
        (0x145bc94f8,'mov','byte ptr [rsi + 0x78], al'),
        (0x145bba6d4,'call','0x145bb2570'),(0x145bba6f8,'cmp','dword ptr [rax + 0x18], ecx'),
        (0x145bba6fb,'jg','0x145bba702'),(0x145bba6fd,'cmp','dword ptr [rax + 0x1c], ecx'),
        (0x145bba700,'jge','0x145bba71d'),(0x145bba709,'jne','0x145bba6f5'),
        (0x145bba70b,'lea','rax, [rbx + 0xf8]'),(0x145bba71d,'cmp','dword ptr [rax + 0x28], 1'),
        (0x145bba721,'jle','0x145bba70b'),(0x145bba728,'add','rax, 0x20'),
        (0x145bba9b4,'call','0x145bb2570'),(0x145bba9d8,'cmp','dword ptr [rax + 0x18], ecx'),
        (0x145bba9db,'jg','0x145bba9e2'),(0x145bba9dd,'cmp','dword ptr [rax + 0x1c], ecx'),
        (0x145bba9e0,'jge','0x145bba9fd'),(0x145bba9e9,'jne','0x145bba9d5'),
        (0x145bba9fd,'movzx','eax, byte ptr [rax + 0x78]'),(0x145bbaa01,'test','al, al'),
        (0x145bbaa03,'jne','0x145bbaa0c'),(0x145bbaa05,'movzx','eax, byte ptr [rbx + 0xd4]')]:
        r=rows[a]
        if (r['mnemonic'],r['operands'])!=(m,o):raise ValueError('Changed extra level anchor '+hex(a))
        anchors.append(r)
    for a,name in [(0x145bc67c4,'Resource'),(0x145bc6746,'StackCount'),(0x145bc8b71,'ChangeResource'),(0x145bc8bfd,'ChangeStackCount')]:
        r=rows[a];o=im.offset(r['rip_references'][0]-im.pe.base);raw=name.encode()+b'\0'
        if r['mnemonic']!='lea' or d[o:o+len(raw)]!=raw:raise ValueError('Changed extra field')
        anchors.append(r);literals.append(dict(file_offset=o,bytes=raw.hex(),name=name))
    slots=[]
    for slot,target in [(0x138,0x145bba6b0),(0xd8,0x145bba990)]:
        a=0x1499b9440+slot;o=im.offset(a-im.pe.base);raw=struct.pack('<Q',target)
        if d[o:o+8]!=raw:raise ValueError('Changed extra getter slot')
        slots.append(dict(address=a,file_offset=o,bytes=raw.hex()))
    result=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,literals=literals,vtable_slots=slots,fragments=fragments,
        verified=dict(resource_replacement=True,stack_count_replacement=True,first_inclusive_range=True),
        limitations=['Getter field selection verified, not runtime effects or charge semantics.','Other Change fields and final cooldown/growth formulas remain outside this report.'])
    path=n.ROOT/'code-clues/skill-level-extra-code.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),literals=len(literals),slots=len(slots),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()
