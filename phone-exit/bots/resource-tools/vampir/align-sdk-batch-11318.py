"""Bounded SDK/GMC2/NID candidate alignment; never authenticates or promotes runtime."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
OLD = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
NEW = 'd30708283d893756b0fc1ffe700344be1a41fe746683106704b01ce32611532c'
ROOTS = tuple(int(at, 16) for at in (
    '1411b05c0 1411b3260 1411b3290 1411b32c0 1411b5c10 '
    '14125b710 14125b740 14125b770 14125b7d0 1414266a0 1417619b0 '
    '14447cf10 14447d160 1444b1fe0 1444b3290 1444c4210 1444cf500 '
    '1444dee00 1444f8b10 1444fa180 1444fbbc0 144508210 144529d60 '
    '14452ac30 1445320c0 144532410 1450e3c80 1450f3e40 14560aed0 '
    '1456579d0 1445515c0 1450f2c80 1415e4460 144531900').split())
SCRIPTS = ('replay-sdk-defaults-11316', 'replay-sdk-overrides-11316',
           'replay-sdk-platform-11316', 'replay-gmc2-base-11316',
           'replay-gmc2-url-11316', 'replay-gmc2-headers-11316',
           'replay-gmc2-geo-11316', 'replay-nid-context-11316',
           'replay-nid-result-11316', 'audit-nid-result-11316',
           'nid-primitives-11316', 'replay-nid-primitives-11316')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(root, prior=None):
    native, bindings = load('build-native-entry-code'), load('update-bindings')
    images = {}
    for sha in (OLD, NEW):
        raw = (root / 'client-code-snapshots' / sha / 'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('SDK alignment source changed')
        images[sha] = native.Image(raw)
    decoder = native.capstone.Cs(native.capstone.CS_ARCH_X86, native.capstone.CS_MODE_64)
    decoder.detail = True
    cache = {}

    def rows(sha, at):
        key = (sha, at)
        if key not in cache:
            try:
                cache[key] = bindings.rows(native, images[sha], at)
            except ValueError:
                cache[key] = None
        return cache[key]

    def shape(items):
        if items is None:
            return None
        positions = {r['address']:n for n, r in enumerate(items)}
        result = []
        for row in items:
            raw = bytearray.fromhex(row['bytes'])
            ins = next(decoder.disasm(raw, row['address']))
            edge = None
            if row['call'] or row['branch']:
                target = row['direct_target']
                if target is not None:
                    edge = ('local', positions[target]) if target in positions else ('external',)
                    raw[ins.imm_offset:ins.imm_offset + ins.imm_size] = bytes(ins.imm_size)
            if row['rip_references']:
                raw[ins.disp_offset:ins.disp_offset + ins.disp_size] = bytes(ins.disp_size)
            result.append((raw.hex(), edge))
        return result

    hints = {}
    prior_candidates = {}
    if prior:
        report = json.loads(Path(prior).read_text('utf-8'))
        if (report['baseline_sha256'], report['source_sha256']) != (OLD, NEW):
            raise ValueError('SDK prior source differs')
        hints = {int(a, 16):int(b, 16) for a, b in report['roots'].items()}
        prior_candidates = report['candidates']
    # Caller-linked candidates from the completed Login batch are only hints;
    # their complete instruction/control shape is checked again below.
    before = json.loads((HERE / 'knowledge/native-contexts/login-prepare-sdk-11316.json').read_text('utf-8'))
    after = json.loads((HERE / 'knowledge/native-contexts/login-prepare-sdk-11318.json').read_text('utf-8'))
    for key in before['native_sdk']['functions']:
        hints[int(before['native_sdk']['functions'][key], 16)] = int(after['native_sdk']['functions'][key], 16)
    mapped, candidates, links, unknown = {}, {}, {}, {}

    def add(a, b):
        links.setdefault(a, set()).add(b)

    def bind(old, new, before, after):
        mapped[old] = new
        add(old, new)
        for a, b in zip(before, after):
            add(a['address'], b['address'])
            if len(a['rip_references']) != len(b['rip_references']):
                raise ValueError('SDK RIP arity changed')
            for x, y in zip(a['rip_references'], b['rip_references']):
                add(x, y)
            if a['direct_target'] is not None:
                add(a['direct_target'], b['direct_target'])

    def literal_matches(old, new):
        found = False
        for a, b in zip(rows(OLD, old), rows(NEW, new)):
            if a['mnemonic'] != 'lea' or not a['operands'].startswith('rdx,') or len(a['rip_references']) != 1:
                continue
            def literal(sha, at):
                image = images[sha];off = image.offset(at - image.pe.base)
                raw = image.data[off:off + 256]
                end = next((n for n in range(0, 254, 2) if raw[n:n + 2] == b'\0\0'), None)
                return raw[:end + 2] if end is not None else None
            x = literal(OLD, a['rip_references'][0]);y = literal(NEW, b['rip_references'][0])
            if not x or x == b'\0\0' or x != y:
                return False
            found = True
        return found

    for old in ROOTS:
        expected = shape(rows(OLD, old))
        if expected is None:
            unknown[hex(old)] = 'Baseline is not linearly decodable; needs bounded code/data proof'
            continue
        hits = []
        if old in hints:
            new = hints[old]
            if shape(rows(NEW, new)) == expected:
                hits = [new]
        elif hex(old) in prior_candidates:
            hits = [int(at, 16) for at in prior_candidates[hex(old)] if shape(rows(NEW, int(at, 16))) == expected]
        else:
            image = images[OLD]
            off = image.offset(old - image.pe.base)
            prefix = image.data[off:off + 4]
            for begin, end, unwind in images[NEW].ranges:
                current = begin + images[NEW].pe.base
                if abs(current - old) > 0x10000:
                    continue
                part = images[NEW].containing(current)
                if images[NEW].roots[part][0] != begin:
                    continue
                off = images[NEW].offset(begin)
                if images[NEW].data[off:off + 4] != prefix:
                    continue
                if shape(rows(NEW, current)) == expected:
                    hits.append(current)
        hits = sorted(set(hits))
        if len(hits) > 1 and old < 0x141300000:
            hits = [at for at in hits if literal_matches(old, at)]
        candidates[hex(old)] = [hex(at) for at in hits]
        if len(hits) != 1:
            unknown[hex(old)] = 'Missing or ambiguous complete instruction/control shape'
            continue
        bind(old, hits[0], rows(OLD, old), rows(NEW, hits[0]))
    # Identical JSON wrappers are disambiguated by the verified native caller.
    for old_text in list(unknown):
        old = int(old_text, 16);called = links.get(old, set())
        if len(called) == 1 and hex(next(iter(called))) in candidates.get(old_text, []):
            new = next(iter(called));bind(old, new, rows(OLD, old), rows(NEW, new));del unknown[old_text]
    # These two reviewed functions have inline RVA switch data. Compare every
    # exported code instruction and every declared table target independently;
    # neither the data nor a guessed linear decode is admitted as code.
    switches = []
    for old, run, site, count in ((0x144532410, 'run-cbdf156bd3fe', 0x144532435, 15),
                                  (0x1450e3c80, 'run-988ec3bf8f0a', 0x1450e45c6, 6)):
        document = json.loads((root / 'ghidra/request-exports' / OLD / run / 'details.json').read_text('utf-8'))
        function = next(f for f in document['functions'] if int(f['address'], 16) == old)
        if not function['decompilation_completed'] or not function['block_coverage_complete']:
            raise ValueError('Baseline SDK switch export incomplete')
        def decoded(at, encoded):
            ins = next(decoder.disasm(encoded, at))
            if ins.size != len(encoded):raise ValueError('SDK switch instruction boundary differs')
            call=ins.group(native.capstone.CS_GRP_CALL);branch=ins.group(native.capstone.CS_GRP_JUMP)
            target=ins.operands[0].imm if (call or branch) and ins.operands[0].type==native.capstone.x86.X86_OP_IMM else None
            refs=[ins.address+ins.size+op.mem.disp for op in ins.operands if op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP]
            return dict(address=at, bytes=encoded.hex(), call=call, branch=branch, direct_target=target,
                        rip_references=refs, mnemonic=ins.mnemonic, operands=ins.op_str)
        before=[]
        for row in function['instructions']:
            at=int(row['address'],16);raw=bytes.fromhex(row['bytes']);im=images[OLD];off=im.offset(at-im.pe.base)
            if im.data[off:off+len(raw)]!=raw:raise ValueError('Baseline SDK switch export bytes differ')
            before.append(decoded(at,raw))
        # Historical Ghidra blocks omit native conditional fallthroughs here.
        # Decode the complete code prefix through its last exported RET, stopping
        # before the explicitly checked padding/table. Never treat table data
        # as instructions or transfer the historical omission to the new source.
        code_end=max(row['address']+len(bytes.fromhex(row['bytes'])) for row in before)
        image=images[OLD];off=image.offset(old-image.pe.base);code=image.data[off:off+code_end-old]
        complete=list(decoder.disasm(code,old))
        if sum(ins.size for ins in complete)!=len(code) or complete[-1].mnemonic!='ret':
            raise ValueError('SDK switch complete code prefix differs')
        before=[decoded(ins.address,bytes(ins.bytes)) for ins in complete]
        matches=[];im=images[NEW];prefix=bytes.fromhex(before[0]['bytes'])
        for begin,end,unwind in im.ranges:
            new=begin+im.pe.base
            if abs(new-old)>0x10000 or im.roots[im.containing(new)][0]!=begin:continue
            off=im.offset(begin)
            if im.data[off:off+len(prefix)]!=prefix:continue
            after=[]
            try:
                for row in before:
                    at=new+row['address']-old;off=im.offset(at-im.pe.base)
                    after.append(decoded(at,im.data[off:off+len(bytes.fromhex(row['bytes']))]))
            except (ValueError,StopIteration):continue
            # The only non-RIP relocatable operand here is the fixed switch RVA.
            copies=[];tables=[]
            for items,entry in ((before,old),(after,new)):
                normalized=[dict(row) for row in items];row=next(r for r in normalized if r['address']==entry+site-old)
                ins=next(decoder.disasm(bytes.fromhex(row['bytes']),row['address']));raw=bytearray(ins.bytes)
                tables.append(im.pe.base+ins.operands[1].mem.disp)
                raw[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size);row['bytes']=raw.hex();copies.append(normalized)
            if shape(copies[0])!=shape(copies[1]):continue
            table_values=[]
            for sha,table,entry in zip((OLD,NEW),tables,(old,new)):
                image=images[sha];off=image.offset(table-image.pe.base)
                values=struct.unpack_from('<'+'I'*count,image.data,off)
                targets=[image.pe.base+v for v in values]
                allowed={r['address'] for r in (before if sha==OLD else after)}
                if not set(targets)<=allowed:break
                table_values.append([target-entry for target in targets])
            if len(table_values)!=2 or table_values[0]!=table_values[1]:continue
            matches.append((new,after,tables))
        if len(matches)!=1:
            unknown[hex(old)]='SDK inline-switch code/table comparison missing or ambiguous';continue
        new,after,tables=matches[0];bind(old,new,before,after);add(*tables)
        candidates[hex(old)]=[hex(new)];unknown.pop(hex(old),None)
        switches.append(dict(old=hex(old),current=hex(new),old_table=hex(tables[0]),table=hex(tables[1]),count=count,
                             instructions=len(after),source_export=run))
    # Repeated SDK initializers share text across subsystems. Bind the exact
    # global destination already observed in the consuming native function.
    for old_text in list(unknown):
        old=int(old_text,16)
        if old>=0x141300000:continue
        hits=[]
        before=rows(OLD,old)
        for current_text in candidates.get(old_text,[]):
            new=int(current_text,16);after=rows(NEW,new);matched=0;valid=True
            for a,b in zip(before,after):
                for x,y in zip(a['rip_references'],b['rip_references']):
                    known=links.get(x,set())
                    if len(known)==1:
                        matched+=1
                        if y not in known:valid=False
            if valid and matched:hits.append(new)
        if len(hits)==1:
            bind(old,hits[0],before,rows(NEW,hits[0]));candidates[old_text]=[hex(hits[0])];del unknown[old_text]
    referenced = {}
    for name in SCRIPTS:
        tree = ast.parse((HERE / (name + '.py')).read_text('utf-8'))
        values = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                  and isinstance(node.value, int) and 0x140000000 <= node.value < 0x150000000}
        referenced[name] = {hex(at):[hex(v) for v in sorted(links.get(at, ()))] for at in sorted(values)}
    report = dict(schema=1, source_sha256=NEW, baseline_sha256=OLD,
                  roots={hex(a):hex(b) for a, b in mapped.items()}, candidates=candidates,
                  unknown=unknown, script_addresses=referenced,
                  links={hex(a):[hex(v) for v in sorted(bs)] for a, bs in links.items()},
                  switches=switches,
                  tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  semantic_verification=False, network_used=False, profile_activated=False)
    path = load('research-workflow').snapshot(root, 'sdk-batch-alignment-11318', report)
    return path, report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('F:/PhoneExit Resources/Vampir'))
    parser.add_argument('--prior', type=Path)
    args = parser.parse_args()
    path, report = run(args.root, args.prior)
    print(json.dumps(dict(report=str(path), roots=report['roots'], unknown=report['unknown'])))
