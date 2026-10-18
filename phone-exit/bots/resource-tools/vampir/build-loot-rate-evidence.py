"""Verify Windows CSV rate loaders and CRT atoi import; do not infer loot odds."""
import csv
import hashlib
import importlib.util
import io
import json
import struct
from decimal import Decimal
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('loot_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)


def imports(image):
    data=image.data;header=struct.unpack_from('<I',data,60)[0]
    rva,size=struct.unpack_from('<II',data,header+24+112+8)
    offset=image.offset(rva);result={}
    for pos in range(offset,offset+size,20):
        original,stamp,chain,name,first=struct.unpack_from('<IIIII',data,pos)
        if not any((original,stamp,chain,name,first)):break
        start=image.offset(name);dll=data[start:start+256].split(b'\0')[0].decode('ascii')
        for i in range(100000):
            value=struct.unpack_from('<Q',data,image.offset(original or first)+i*8)[0]
            if not value:break
            if value>>63:continue
            start=image.offset(value)+2
            result[image.pe.base+first+i*8]=dict(dll=dll,name=data[start:start+512].split(b'\0')[0].decode('ascii'))
    return result


def main():
    root=native.ROOT
    source=json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
    data=Path(source['source']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError('Changed EXE')
    if native.capstone.__version__!='5.0.6':raise ValueError('Use pinned Capstone5.0.6')
    image=native.Image(data)
    roots={image.roots[image.containing(a)] for a in [0x145b67fb0,0x145b6b950,0x145b70fc0]}
    fragments=native.decode_ranges(image,roots)
    rows={r['address']:r for f in fragments for r in f['instructions']}
    def check(address,mnemonic,operands):
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed instruction: '+hex(address))
        return row
    def literal(address,text):
        row=rows[address]
        if row['mnemonic']!='lea' or len(row['rip_references'])!=1:raise ValueError('Invalid literal instruction')
        off=image.offset(row['rip_references'][0]-image.pe.base)
        token=text.encode('ascii')+b'\0'
        if data[off:off+len(token)]!=token:raise ValueError('Changed literal: '+text)
        return dict(text=text,file_offset=off,bytes=token.hex(),instruction=row)
    metadata={t['entry']:t for t in json.loads((root/'table-study/index-pakchunk1-Windows.json').read_text('utf-8'))['tables']}
    tables=[]
    for name,entry,loader,file_ins,name_ins,rate_ins,stack_ins,parse_ins,store_ins,stack_offset,object_offset in [
        ('AreaReward',11,0x145b67fb0,0x145b68079,0x145b6810c,0x145b681e0,0x145b686e1,0x145b686ec,0x145b686f1,0x1c0,0x38),
        ('NpcReward',1415,0x145b6b950,0x145b6ba19,0x145b6baac,0x145b6bb9d,0x145b6c0d8,0x145b6c0e3,0x145b6c0e8,0x1d4,0x48),
        ('Reward',1475,0x145b70fc0,0x145b71086,0x145b7111b,0x145b7120a,0x145b717f6,0x145b71801,0x145b71806,0x192,0x50)]:
        field='Rate' if name=='Reward' else 'RewardRate'
        meta=metadata[entry];raw=(root/'table-study'/meta['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=meta['sha256']:raise ValueError('Changed CSV')
        records=list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'),newline='')))
        if len(records)!=meta['rows'] or field not in meta['header']:raise ValueError('Changed table schema')
        # Field-name array position is exactly the CSV column index.
        column=meta['header'].index(field)
        values=[Decimal(r[field]) for r in records if r[field]]
        tables.append(dict(name=name,entry=entry,csv_source=meta,loader=loader,field=field,column_index=column,
            filename=literal(file_ins,name+'.csv'),loader_name=literal(name_ins,'FRd'+name+'InfoManagerTemplate::Load'),
            field_literal=literal(rate_ins,field),column_index_read=check(stack_ins,'movzx',f'edx, word ptr [rbp + {hex(stack_offset)}]'),
            parse_call=check(parse_ins,'call','0x1445ef9f0'),
            store=check(store_ins,'mov',f'dword ptr [{"rbx" if name=="Reward" else "rsi"} + {hex(object_offset)}], eax'),
            object_offset=object_offset,storage_bits=32,raw_stats=dict(min=str(min(values)),max=str(max(values)),
                blank=sum(not r[field] for r in records),fractional=sum(v!=int(v) for v in values)),
            fractional_rows=[dict(csv_record=i+2,row=r) for i,r in enumerate(records) if r[field] and Decimal(r[field])!=int(Decimal(r[field]))]))
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    leaves=[]
    for address,length in [(0x1445ef9f0,30),(0x1445eb010,17)]:
        off=image.offset(address-image.pe.base);raw=data[off:off+length]
        decoded=[dict(address=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in decoder.disasm(raw,address)]
        if sum(len(bytes.fromhex(r['bytes'])) for r in decoded)!=length:raise ValueError('Leaf boundary changed')
        leaves.append(dict(address=address,file_offset=off,bytes=raw.hex(),instructions=decoded))
    # Import thunk is verified against PE import-name table, not guessed from atoi-like behavior.
    expected=['mov eax, dword ptr [rcx + 0x20]','mov r8, rcx','dec eax','cmp edx, eax','jbe 0x1445ef9ff','xor eax, eax','ret ',
              'mov ecx, edx','shl rcx, 5','add rcx, qword ptr [r8 + 0x28]','jmp 0x1445eb010']
    if [r['mnemonic']+' '+r['operands'] for r in leaves[0]['instructions']]!=expected:raise ValueError('CSV integer accessor changed')
    thunk=leaves[1]['instructions'][-1]
    if (thunk['address'],thunk['mnemonic'],thunk['operands'])!=(0x1445eb01a,'jmp','qword ptr [rip + 0x435abd7]'):raise ValueError('CRT thunk changed')
    imported=imports(image).get(0x148945bf8)
    if imported!={'dll':'api-ms-win-crt-convert-l1-1-0.dll','name':'atoi'}:raise ValueError('Unexpected converter import')
    report=dict(source=source['source'],sha256=source['sha256'],capstone=native.capstone.__version__,tables=tables,
        conversion=dict(import_slot=0x148945bf8,imported=imported,leaves=leaves,
            observation='CSV column accessor -> 32-byte string slot -> CRT atoi -> dword storage; no percentage scaling in this path'),
        fragments=fragments,chance_percent_verified=False,
        limitations=['Loader and field storage only; downstream evaluator/roll denominator/server modifiers not recovered.',
            'AreaReward filename is proven; GroupId->Area relationship remains unresolved.',
            'Fractional values are preserved raw; CRT atoi parses an integer prefix, not a floating-point percentage.',
            'This is Windows client evidence, not Android/server drop verification.'])
    out=root/'code-clues/loot-rate-evidence.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(tables=len(tables),fragments=len(fragments),conversion=imported,fields=[dict(name=t['name'],stats=t['raw_stats']) for t in tables]),ensure_ascii=False))
    return report


if __name__=='__main__':main()

