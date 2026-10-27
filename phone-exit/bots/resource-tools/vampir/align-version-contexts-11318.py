"""Explicit Version helper alignment and context candidates; replay is still required."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
OLD = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NEW = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
NAMES = ('version-prepare', 'version-nm-device', 'version-cpu', 'version-windows',
         'version-combiner', 'version-platform', 'version-prepare-nm',
         'version-prepare-system', 'version-prepare-combiner', 'version-prepare-platform')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def discover(root):
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    images = {}
    for sha in (OLD, NEW):
        raw = (root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('Alignment source SHA changed')
        images[sha] = native.Image(raw)
    contexts = {name: json.loads((HERE/'knowledge/native-contexts'/(name+'-11316.json')).read_text('utf-8')) for name in NAMES}
    wanted = {0x1467ce6a0, 0x1456d7be0, 0x1467cc380}
    for name in ('version-cpu', 'version-combiner'): wanted.update(int(v,16) for v in contexts[name]['functions'].values())
    wanted.add(int(contexts['version-windows']['function'],16))
    wanted.update(int(contexts['version-nm-device'][k],16) for k in ('wrapper','getter'))
    wanted.update(int(contexts['version-platform'][k],16) for k in ('selector','store','lookup'))
    if len(wanted) != 20: raise ValueError('Explicit Version root set changed')
    pairs = {}; candidates = {0x1467ce6a0:0x1467ceb70, 0x1456d7be0:0x1456d7fc0, 0x1467cc380:0x1467cc850}
    processed = {}; calls = {}; tails = set()
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64); decoder.detail = True
    def add(a,b): pairs.setdefault(a,set()).add(b)
    def canonical(rows):
        positions = {r['address']:i for i,r in enumerate(rows)}; result = []
        for row in rows:
            raw = bytearray.fromhex(row['bytes']); ins = next(decoder.disasm(raw,row['address']))
            edge = None
            if row['call'] or row['branch']:
                target = row['direct_target']
                if target is not None:
                    edge = ('local',positions[target]) if target in positions else ('external',)
                    raw[ins.imm_offset:ins.imm_offset+ins.imm_size] = bytes(ins.imm_size)
            if row['rip_references']: raw[ins.disp_offset:ins.disp_offset+ins.disp_size] = bytes(ins.disp_size)
            result.append((raw.hex(),edge))
        return result
    while True:
        pending = [(a,b) for a,b in candidates.items() if a in wanted and a not in processed]
        if not pending: break
        for old,new in pending:
            before = bindings.rows(native,images[OLD],old); after = bindings.rows(native,images[NEW],new)
            if canonical(before) != canonical(after): raise ValueError('Function/control shape changed at '+hex(old))
            processed[old] = new; add(old,new)
            for a,b in zip(before,after):
                add(a['address'],b['address'])
                if len(a['rip_references']) != len(b['rip_references']): raise ValueError('RIP reference arity changed')
                for x,y in zip(a['rip_references'],b['rip_references']): add(x,y)
                if a['direct_target'] is not None:
                    add(a['direct_target'],b['direct_target'])
                    if a['call'] and a['direct_target'] in wanted:
                        prior = candidates.setdefault(a['direct_target'],b['direct_target'])
                        if prior != b['direct_target']: raise ValueError('Helper caller binding is ambiguous')
                if a['call']:
                    calls[a['address']] = (b['address'],hex(b['direct_target']) if b['direct_target'] is not None else b['operands'])
                if b['mnemonic']=='jmp' and b['direct_target'] is not None and b['direct_target'] not in {r['address'] for r in after}:
                    tails.add(b['direct_target'])
    if set(processed) != wanted: raise ValueError('Unresolved declared roots: '+str([hex(v) for v in wanted-set(processed)]))
    # The send fixture is a real wrapper-table slot, not a guessed delta.
    old_table = int(contexts['version-prepare']['wrapper_table'],16)
    if len(pairs.get(old_table,())) != 1: raise ValueError('Wrapper table mapping is ambiguous')
    new_table = next(iter(pairs[old_table]))
    for slot in (0x38,0x48):
        values = [struct.unpack_from('<Q',im.data,im.offset(table-im.pe.base)+slot)[0]
                  for im,table in ((images[OLD],old_table),(images[NEW],new_table))]
        add(*values)
    return native, images, contexts, processed, pairs, calls, tails


def run(root, export=None):
    native, images, contexts, processed, pairs, calls, tails = discover(root)
    unique = {a:next(iter(v)) for a,v in pairs.items() if len(v)==1}
    report = dict(baseline_sha256=OLD,source_sha256=NEW,tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        roots={hex(a):hex(b) for a,b in processed.items()},tail_targets=[hex(v) for v in sorted(tails)],
        ambiguous={hex(a):[hex(v) for v in sorted(bs)] for a,bs in pairs.items() if len(bs)!=1},
        semantic_verification=False,network_used=False,profile_activation=False)
    if export:
        exports = {}; available = set()
        for item in export:
            item = Path(item).resolve()
            if not item.is_relative_to((root/'ghidra/request-exports'/NEW).resolve()) or item.name!='details.json':
                raise ValueError('Export outside current source library')
            data = json.loads(item.read_text('utf-8'))
            if data['new_source_sha256']!=NEW:raise ValueError('Export source differs')
            available.update(int(f['address'],16) for f in data['functions'] if f.get('decompilation_completed'))
            exports[item.parent.name] = hashlib.sha256(item.read_bytes()).hexdigest()
        if not set(processed.values()) <= available:
            raise ValueError('Export does not cover declared aligned roots')
        def address(value):
            at = int(value,16)
            if at in unique:return hex(unique[at])
            try:images[OLD].offset(at-images[OLD].pe.base)
            except ValueError:return value  # Explicit synthetic fixture address, outside PE.
            raise ValueError('Unreviewed/ambiguous context address '+value)
        def convert(value,key=None,parent=None):
            if key=='source_sha256':return NEW
            if key=='source':return str(root/'client-code-snapshots'/NEW/'ProjectRED-Win64-Shipping.exe')
            if key=='exports':return exports
            if key=='call_sites':
                result = {}
                for at,old in value.items():
                    site,target = calls[int(at,16)]
                    result[hex(site)] = dict(target=target) if isinstance(old,dict) else target
                return result
            if key=='wrapper_table_sha256':
                table = unique[int(parent['wrapper_table'],16)]; im = images[NEW]; off = im.offset(table-im.pe.base)
                return hashlib.sha256(im.data[off:off+0x50]).hexdigest()
            if isinstance(value,dict):return {k:convert(v,k,value) for k,v in value.items()}
            if isinstance(value,list):return [convert(v) for v in value]
            if isinstance(value,str) and re.fullmatch('0x[0-9a-fA-F]+',value):return address(value)
            return value
        generated = {}
        for name,old in contexts.items():
            current = convert(old); current['verify_whole_exports'] = True
            if 'prepare' in current:
                im=images[NEW]; pointer=int(current['globals']['tag_pointer'],16)
                literal=struct.unpack_from('<Q',im.data,im.offset(pointer-im.pe.base))[0]
                off=im.offset(literal-im.pe.base); tag=im.data[off:off+33]
                if not re.fullmatch(b'[0-9A-F]{32}\0',tag):raise ValueError('Current tag literal format differs')
                current['compiled_tag_source']=dict(literal=hex(literal),value=tag[:-1].decode('ascii'))
            target = HERE/'knowledge/native-contexts'/(name+'-11318.json')
            generated[target] = json.dumps(current,ensure_ascii=False,indent=2)+'\n'
        # Compute/validate the entire set before writing any candidate context.
        for path,content in generated.items():path.write_text(content,encoding='utf-8')
        report['contexts'] = [str(p) for p in generated]
    path = load('research-workflow').snapshot(root,'version-context-alignment-11318',report)
    return path,report


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--export',type=Path,action='append')
    args = parser.parse_args(); path,report = run(args.root,args.export)
    print(json.dumps(dict(report=str(path),roots=report['roots'],tail_targets=report['tail_targets'])))
