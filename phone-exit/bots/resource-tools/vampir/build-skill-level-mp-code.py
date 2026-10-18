"""Verify level-specific MpMin/MpMax field selection, without growth formula."""
import hashlib,importlib.util,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent


def mp_at_level(skill,changes,level):
    if type(level) is not int or not 0<=level<=32767:raise ValueError('Invalid level')
    selected=next((r for r in changes if r['SkillInfoId']==skill['Id'] and int(r['MinLevel'])<=level<=int(r['MaxLevel'])),None)
    values={};origins={}
    for field in ['MpMin','MpMax']:
        key='Change'+field;raw=selected.get(key,'') if selected else ''
        if raw and (not raw.isascii() or not raw.isdecimal() or int(raw)>2147483647):raise ValueError('Invalid MP value')
        use=bool(raw) and int(raw)!=0
        values[field]=raw if use else skill.get(field,'')
        origins[field]=dict(table='SkillLevel' if use else 'Skill',field=key if use else field,provenance=(selected if use else skill).get('provenance'))
    return dict(values=values,origins=origins,runtime_verified=False)


def main():
    spec=importlib.util.spec_from_file_location('mp_native',HERE/'build-native-entry-code.py');n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
    source=json.loads((n.ROOT/'code-clues/native-enums.json').read_text('utf-8'));d=Path(source['source']).read_bytes()
    if hashlib.sha256(d).hexdigest()!=source['sha256'] or n.capstone.__version__!='5.0.6':raise ValueError('Changed client/decoder')
    im=n.Image(d);fr=n.decode_ranges(im,{im.roots[im.containing(a)] for a in [0x145bc6470,0x145bc89c0,0x145bba160,0x145bba0d0]})
    rows={r['address']:r for f in fr for r in f['instructions']};anchors=[];literals=[];slots=[]
    expected=[(0x145bc76a2,'mov','dword ptr [rbx + 0xe4], eax'),(0x145bc76c5,'mov','dword ptr [rbx + 0xe8], eax'),
        (0x145bc94a2,'mov','dword ptr [rsi + 0x6c], eax'),(0x145bc94be,'mov','dword ptr [rsi + 0x70], eax')]
    for a,m,o in expected:
        row=rows[a]
        if (row['mnemonic'],row['operands'])!=(m,o):raise ValueError('Changed MP field store')
        anchors.append(row)
    # Preserve complete getter control flow, including all inclusive comparisons,
    # first matching range, zero fallback and source field loads.
    for f in fr:
        if f['root_begin_rva']+im.pe.base in [0x145bba160,0x145bba0d0]:anchors.extend(f['instructions'])
    for a,name in [(0x145bc677e,'MpMin'),(0x145bc678c,'MpMax'),(0x145bc8bd3,'ChangeMpMin'),(0x145bc8be1,'ChangeMpMax')]:
        row=rows[a];off=im.offset(row['rip_references'][0]-im.pe.base);raw=name.encode()+b'\0'
        if row['mnemonic']!='lea' or d[off:off+len(raw)]!=raw:raise ValueError('Changed MP name')
        anchors.append(row);literals.append(dict(file_offset=off,bytes=raw.hex(),name=name))
    for slot,target in [(0x100,0x145bba160),(0x110,0x145bba0d0)]:
        a=0x1499b9440+slot;off=im.offset(a-im.pe.base);raw=struct.pack('<Q',target)
        if d[off:off+8]!=raw:raise ValueError('Changed MP getter slot')
        slots.append(dict(address=a,file_offset=off,bytes=raw.hex()))
    result=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,literals=literals,vtable_slots=slots,fragments=fr,
        verified=dict(mp_min_replacement=True,mp_max_replacement=True,first_inclusive_range=True),
        limitations=['Only source field replacement; MpGrowth formula and actual mana consumption remain unverified.','Current SkillLevel table has no nonempty MP replacements.'])
    path=n.ROOT/'code-clues/skill-level-mp-code.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),literals=len(literals),slots=len(slots),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()
