"""Source-bound localization links for Login+124; static evidence, no game IO."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('language_native',HERE/'build-native-entry-code.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
ADDRESSES=(0x1455709b0,0x145570240,0x14555cb50)
LITERALS=(0x1498a9830,0x1498a9890,0x1498a9bd0,0x1498a9c30,0x1494e0618,0x1494e0628,0x1494e0638)


def build():
    root=native.ROOT
    manifest=json.loads((root/'ghidra/entry-manifest.json').read_text('utf-8'))
    latest=json.loads((root/'ghidra/latest-export.json').read_text('utf-8'))
    export=Path(latest['output'])
    report=json.loads((export/'functions.json').read_text('utf-8'))
    raw=Path(manifest['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=manifest['source_sha256']:raise ValueError('Client changed')
    image=native.Image(raw)
    selected=[]
    for address in ADDRESSES:
        matches=[r for r in report['functions'] if int(r['address'],16)==address]
        if len(matches)!=1 or not matches[0]['completed']:raise ValueError('Required Ghidra export missing')
        entry=image.containing(address)
        if entry is None:raise ValueError('Missing unwind range')
        if address==0x145570240:
            # Reviewed prefix ends after the reverse-converter CALL. The full
            # unwind range contains switch data and is not a linear code range.
            begin=address-image.pe.base;end=0x145570344-image.pe.base
            section=raw[image.offset(begin):image.offset(begin)+end-begin]
            decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
            decoder.detail=True;instructions=[]
            for ins in decoder.disasm(section,address):
                refs=[ins.address+ins.size+op.mem.disp for op in ins.operands
                    if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
                instructions.append(dict(address=ins.address,bytes=ins.bytes.hex(),mnemonic=ins.mnemonic,
                    operands=ins.op_str,rip_references=refs))
            if sum(len(bytes.fromhex(r['bytes'])) for r in instructions)!=len(section):raise ValueError('Prefix decode incomplete')
            selected.append(dict(begin_rva=begin,end_rva=end,sha256=hashlib.sha256(section).hexdigest(),instructions=instructions))
        else:
            selected.extend(native.decode_ranges(image,{image.roots[entry]}))
    rows=[row for fragment in selected for row in fragment['instructions']]
    literals=[]
    for address in LITERALS:
        offset=image.offset(address-image.pe.base)
        data=raw[offset:offset+512]
        end=next(i for i in range(0,len(data),2) if data[i:i+2]==bytes(2))
        value=data[:end].decode('utf-16-le')
        refs=[row for row in rows if address in row['rip_references']]
        literals.append(dict(address=hex(address),file_offset=offset,text=value,
            bytes=data[:end+2].hex(),sha256=hashlib.sha256(data[:end+2]).hexdigest(),references=refs))
    stores=[row for row in rows if row['mnemonic']=='mov' and
        row['operands'].startswith('byte ptr [') and ' + 0x18],' in row['operands']]
    if not stores:raise ValueError('Expected byte store missing')
    return dict(source=manifest['source'],source_sha256=manifest['source_sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        export=str(export),export_report_sha256=hashlib.sha256((export/'functions.json').read_bytes()).hexdigest(),
        functions=[r for r in report['functions'] if int(r['address'],16) in ADDRESSES],
        literals=literals,byte18_stores=stores,fragments=selected,
        limits=['Static links only; no native scenario execution or live config read.',
            'Input language converter and configuration key helper remain separate unknowns.',
            'No evidence that language mismatch causes server Login error16.'])


if __name__=='__main__':
    value=build();path=native.ROOT/'code-clues/login-language-evidence.json'
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        literals=len(value['literals']),stores=value['byte18_stores'])))
