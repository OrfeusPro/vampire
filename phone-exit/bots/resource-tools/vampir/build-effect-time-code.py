"""Verify Effect time storage/converters. Runtime units and precedence remain unknown."""
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent


def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


def main():
    native=module('effect_time_native','build-native-entry-code.py')
    rates=module('effect_time_imports','build-loot-rate-evidence.py')
    source=json.loads((native.ROOT/'code-clues/native-enums.json').read_text('utf-8'))
    data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256'] or native.capstone.__version__!='5.0.6':
        raise ValueError('Changed native source/decoder')
    image=native.Image(data)
    roots={image.roots[image.containing(a)] for a in [0x145959c60,0x145975db0,0x1457f9f60]}
    fragments=native.decode_ranges(image,roots)
    rows={r['address']:r for f in fragments for r in f['instructions']}
    expected=[
        (0x14595a47b,'mov','dword ptr [rbx + 0x58], eax'),
        (0x14595a496,'call','0x1445efb80'),(0x14595a49b,'mov','eax, eax'),
        (0x14595a4a0,'mov','qword ptr [rbx + 0x60], rax'),
        (0x14595a4b9,'call','0x1445efb80'),(0x14595a4be,'mov','eax, eax'),
        (0x14595a4c3,'mov','qword ptr [rbx + 0x68], rax'),
        (0x14595a560,'call','0x1445efb80'),(0x14595a565,'mov','eax, eax'),
        (0x14595a56a,'mov','qword ptr [rbx + 0x80], rax'),
        (0x1459762e1,'mov','dword ptr [rdi + 0x58], eax'),
        (0x145976357,'call','0x1457f9f60'),(0x145976362,'mov','qword ptr [rdi + 0x60], rcx'),
        (0x1459763df,'mov','qword ptr [rdi + 0x68], rcx'),
        (0x14597656c,'mov','qword ptr [rdi + 0x80], rcx'),
        (0x145976424,'movss','dword ptr [rdi + 0x70], xmm0'),
        (0x1457f9fb0,'call','0x1445eaff0'),(0x1457f9fba,'mov','qword ptr [rbx], rax')]
    anchors=[]
    for a,mnemonic,operands in expected:
        row=rows[a]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):
            raise ValueError('Changed effect time anchor '+hex(a))
        anchors.append(row)
    literals=[]
    for a,name in [(0x1459762c9,'Duration'),(0x14597630c,'MinDuration'),
                   (0x145976389,'MaxDuration'),(0x145976406,'DurationGrowthRate'),
                   (0x145976516,'Period')]:
        row=rows[a];offset=image.offset(row['rip_references'][0]-image.pe.base);raw=name.encode()+b'\0'
        if data[offset:offset+len(raw)]!=raw:raise ValueError('Changed effect time literal')
        anchors.append(row);literals.append(dict(file_offset=offset,bytes=raw.hex(),name=name))
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    cs.detail=True
    leaves=[]
    for a,size in [(0x1445efb80,30),(0x1445eb6b0,22),(0x1445eaff0,17)]:
        o=image.offset(a-image.pe.base);raw=data[o:o+size]
        decoded=list(cs.disasm(raw,a))
        if sum(i.size for i in decoded)!=size:raise ValueError('Changed converter leaf')
        leaves.append(dict(address=a,file_offset=o,bytes=raw.hex(),
            instructions=[dict(address=i.address,mnemonic=i.mnemonic,operands=i.op_str) for i in decoded]))
    if leaves[0]['instructions'][-1]['operands']!='0x1445eb6b0':raise ValueError('Changed unsigned column converter')
    imports=rates.imports(image);import_checks=[]
    for address,iat,name in [(0x1445eb6bf,0x148945b98,'strtoul'),(0x1445eaffa,0x148945b78,'_atoi64')]:
        found=imports.get(iat)
        if found!={'dll':'api-ms-win-crt-convert-l1-1-0.dll','name':name}:
            raise ValueError('Changed converter import '+name)
        ins=next(cs.disasm(data[image.offset(address-image.pe.base):][:7],address))
        if ins.address+ins.size+ins.disp!=iat:raise ValueError('Changed converter thunk')
        import_checks.append(dict(address=address,iat=iat,**found))
    metadata=json.loads((native.ROOT/'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']
    meta=next(m for m in metadata if m['entry']==92);raw=(native.ROOT/'table-study'/meta['file']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=meta['sha256']:raise ValueError('Changed Effect CSV')
    reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))
    if reader.fieldnames!=meta['header']:raise ValueError('Changed Effect schema')
    records=list(reader)
    if len(records)!=meta['rows']:raise ValueError('Changed Effect count')
    fields={}
    for name in ['Duration','MinDuration','MaxDuration','Period']:
        values=[r[name] for r in records if r[name]!='']
        fields[name]=dict(nonempty=len(values),max_decimal=str(max(int(v) for v in values)),
            nondecimal_count=sum(not v.isdecimal() for v in values),
            above_uint32_count=sum(int(v)>4294967295 or int(v)<0 for v in values))
    differences=[dict(id=r['Id'],csv_record=i+2,Duration=r['Duration'],MinDuration=r['MinDuration'],MaxDuration=r['MaxDuration'])
        for i,r in enumerate(records) if r['Duration'] and r['MinDuration'] and r['MaxDuration']
        and not int(r['MinDuration'])<=int(r['Duration'])<=int(r['MaxDuration'])]
    result=dict(source=source['source'],sha256=source['sha256'],anchors=anchors,fragments=fragments,
        literals=literals,leaf_code=leaves,imports=import_checks,csv_source=meta,field_stats=fields,
        duration_outside_bounds=differences,
        storage=dict(Duration=dict(offset=0x58,bits=32),MinDuration=dict(offset=0x60,bits=64),
                     MaxDuration=dict(offset=0x68,bits=64),Period=dict(offset=0x80,bits=64)),
        initial_parse='strtoul → EAX zero-extended → 64-bit storage for MinDuration/MaxDuration/Period',
        modify_parse='_atoi64 → 64-bit storage for MinDuration/MaxDuration/Period',
        unit=None,field_precedence_verified=False,runtime_duration_verified=False,
        limitations=['Storage width and parser identity do not establish time units.',
            'Do not select Duration or Min/Max as actual runtime duration from numeric resemblance.',
            'Different conversion paths are not an observed error: installed CSV values fit unsigned32.',
            'SkillOperation.Param1→Effect remains an unverified candidate relation.'])
    path=native.ROOT/'code-clues/effect-time-code.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(anchors),duration_outside_bounds=len(differences),sha256=hashlib.sha256(path.read_bytes()).hexdigest())))


if __name__=='__main__':main()


