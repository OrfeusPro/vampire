"""Bounded candidate lookup for three previously reviewed map functions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
OLD='c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'
NEW='98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'


def run():
    spec=importlib.util.spec_from_file_location('map_candidates_native',HERE/'build-native-entry-code.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    spec=importlib.util.spec_from_file_location('map_candidates_audit',HERE/'audit-client-release.py')
    audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
    images=[]
    for sha in (OLD,NEW):
        path=native.ROOT/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        data=path.read_bytes()
        if hashlib.sha256(data).hexdigest()!=sha:raise ValueError('Map candidate source differs')
        images.append(native.Image(data))
    old,new=images
    if native.capstone.__version__!='5.0.6':raise ValueError('Pinned Capstone required')
    cs=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64);cs.detail=True
    candidates=[]
    for address in (0x145aa53e0,0x1464bdfa0,0x1464cc9a0):
        begin=old.offset(address-old.pe.base)
        rows=[];size=0;mask=bytearray()
        for instruction in cs.disasm(old.data[begin:begin+160],address):
            local=bytearray([1]*instruction.size)
            if any(op.type==native.X86_OP_MEM and op.mem.base==native.X86_REG_RIP for op in instruction.operands):
                local[instruction.disp_offset:instruction.disp_offset+instruction.disp_size]=bytes(instruction.disp_size)
            if instruction.group(native.capstone.CS_GRP_CALL) or instruction.group(native.capstone.CS_GRP_JUMP):
                local[instruction.imm_offset:instruction.imm_offset+instruction.imm_size]=bytes(instruction.imm_size)
            rows.append(dict(address=hex(instruction.address),bytes=instruction.bytes.hex(),text=instruction.mnemonic+' '+instruction.op_str))
            mask.extend(local);size+=instruction.size
            if size>=128:break
        if size<128:raise ValueError('Map candidate prefix too short')
        source=old.data[begin:begin+size]
        pattern=b''.join(re.escape(bytes([byte])) if keep else b'.' for byte,keep in zip(source,mask))
        matches=[]
        for section in new.pe.sections:
            if section['name']!='.text':continue
            raw=section['raw'];body=new.data[raw:raw+section['raw_size']]
            for match in re.finditer(pattern,body,re.DOTALL):
                at=new.pe.address(raw+match.start());function=new.containing(at)
                if function is not None and new.pe.base+new.roots[function][0]==at:matches.append(hex(at))
                if len(matches)>16:raise ValueError('Ambiguous map candidate bound')
        candidates.append(dict(old_address=hex(address),prefix_bytes=source.hex(),mask=mask.hex(),
            instructions=rows,current_candidates=matches,role_transferred=False))
    report=dict(old_source_sha256=OLD,source_sha256=NEW,tool_sha256=audit.sha256(Path(__file__)),
        candidates=candidates,limits=['Only three explicit prefixes are scanned; direct-call/RIP displacements are masked.',
            'Matches are candidates at current unwind roots, not proof of unchanged function or projection semantics.',
            'No Ghidra, game or process IO; historical source and current source use full SHA checks.'])
    path=audit.save_snapshot(native.ROOT/'code-clues/release-map-projection-candidates',report)
    return path,report


if __name__=='__main__':
    path,r=run();print(json.dumps(dict(report=str(path),candidates=[(x['old_address'],x['current_candidates']) for x in r['candidates']])))
