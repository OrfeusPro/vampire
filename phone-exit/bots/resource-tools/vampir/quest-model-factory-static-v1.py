"""Source-bound factory instruction/switch anchors; no native factory execution."""
import hashlib
from pathlib import Path
import struct

SOURCE = '03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f'
FACTORY = 0x1455b8fe0
EXPORT_SHA = '73d25d522c42ddde2e947469c107dbef412d1b69f1cab76ea26fe242564c17f3'
INSTRUCTION_SHA = 'ab4b3321695b63845d3d856b109ea178255af55f92cd3a6f38d10aeb7d402939'
SWITCH_SHA = 'f7ad7aea05cb550bdbd0922ebf86660690953da1386079865f9236c62fef5bff'
COPY = '410f1007410f104f100f1146200f114e30'
COPY_LEAF = '0f10020f1141200f104a100f114930c3'
TABLES = (0x149906828,0x149906958,0x1499077c0,0x149907810,0x149907860,
    0x1499078b0,0x149907900,0x149907950,0x1499079a0,0x1499079f0,0x149907a40,
    0x149907a90,0x149907ae0,0x149907b30,0x149907b80,0x149907bd0,0x149907c20,
    0x149907c70,0x149907cc0,0x149907d10,0x149907d60,0x149907db0,0x149907e00)
HELPERS = {
    'case6_constructor': (0x1455ab5c0,'f7d5e141a072ce05c8256fd90fefd3ad7944b72b1450192b24e778d7ea4879c3'),
    'control_constructor': (0x1455a9330,'347d8cdab4ef98c6e3d243c626de1aec683418c01b6eccbf07b2f1653d7a696c'),
    'shared_move_release': (0x141473540,'8c28569ca35e106d285f78adb6b0df3f97eeff8ed9c5eabb265a64eb6124b7ac'),
}
CALLS = {0x1455b97a6:0x1455ab5c0,0x1455b97b1:0x1455a9330,
         0x1455b97c1:0x1455a9330,0x1455b9f8a:0x141473540,0x1455b9ff0:0x14546d9d0}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def expected():
    return dict(scope='exported_factory_flow_and_source_switch',source_sha256=SOURCE,
        instruction_count=1078,instruction_bytes=5147,instruction_sha256=INSTRUCTION_SHA,
        internal_direct_branches=108,fallthroughs=1024,exported_blocks_covered=True,
        switch_entries=31,switch_sha256=SWITCH_SHA,case6_entry='0x1455b9781',
        case6_constructor='0x1455ab5c0',case6_table='0x149907e00',
        control_constructor='0x1455a9330',shared_move_release='0x141473540',
        progress_copy32_start='0x1455b9fdc',progress_copy32_bytes=COPY,
        task_table_copy_slots=23,copy_leaf='0x1455cec10',
        helper_source_checks={role:dict(address=hex(address),instruction_sha256=sha)
                              for role,(address,sha) in HELPERS.items()},
        helper_exports_verified=False,native_execution=False,runtime_admitted=False,
        active_task_verified=False,network_used=False)


def validate(result):
    flags=('helper_exports_verified','native_execution','runtime_admitted','active_task_verified','network_used')
    if (not isinstance(result,dict) or result != expected()
            or any(result.get(key) is not False for key in flags)
            or result.get('exported_blocks_covered') is not True):
        raise ValueError('Quest factory static source scope or anchors differ')


def verify(index,root,context,exports,source):
    """Verify only the exact collected flow, tables and bounded helper bytes."""
    def require(ok,message):
        if not ok:
            raise ValueError('Quest factory static: '+message)
    root=Path(root).resolve()
    require(digest(source)==SOURCE and context.get('schema')==1
        and context.get('recipe')=='quest-model-factory-static-v1'
        and context.get('source_sha256')==SOURCE
        and Path(context['source']['path']).resolve()==root/'client-code-snapshots'/SOURCE/'ProjectRED-Win64-Shipping.exe'
        and context['source']['sha256']==SOURCE and context['export']['sha256']==EXPORT_SHA,
        'context source/export differs')
    candidates=[function for document in exports if document.get('new_source_sha256')==SOURCE
                for function in document.get('functions',[]) if function.get('address')==hex(FACTORY)]
    require(len(candidates)==1,'unique collected factory required')
    factory=candidates[0]
    require(all(factory.get(key) is True for key in ('decompilation_completed',
        'block_coverage_complete','direct_flow_coverage_complete'))
        and factory.get('linear_tail_scan')==dict(reason='linear_fragment_not_fully_decoded',
            state='deferred_to_ghidra',tail_models_applied=False)
        and factory.get('tail_call_models')==[], 'collected flow metadata differs')
    native=index.extension('build-native-entry-code')
    image=native.Image(source)
    base=image.pe.base
    def read(address,size):
        offset=image.offset(address-base)
        return source[offset:offset+size]
    fragment=image.containing(FACTORY)
    require(fragment is not None and image.roots[fragment][0]+base==FACTORY,'factory root differs')
    ranges=[(base+b,base+e) for (b,e,u),selected in image.roots.items() if selected==image.roots[fragment]]
    def inside(address,size=1):
        return any(begin<=address and address+size<=end for begin,end in ranges)
    decoder=native.capstone.Cs(native.capstone.CS_ARCH_X86,native.capstone.CS_MODE_64)
    decoder.detail=True
    rows={int(row['address'],16):row for row in factory['instructions']}
    require(len(rows)==len(factory['instructions'])==1078,'instruction set differs')
    decoded={}
    for address,row in rows.items():
        raw=bytes.fromhex(row['bytes'])
        require(inside(address,len(raw)) and read(address,len(raw))==raw,'source instruction differs')
        instructions=list(decoder.disasm(raw,address))
        require(len(instructions)==1 and instructions[0].size==len(raw),'instruction boundary differs')
        decoded[address]=instructions[0]
    code=b''.join(bytes.fromhex(rows[address]['bytes']) for address in sorted(rows))
    require(len(code)==factory.get('body_bytes')==5147 and digest(code)==INSTRUCTION_SHA,'code identity differs')
    branches,fallthroughs=0,0
    for address,ins in decoded.items():
        jump=ins.group(native.capstone.CS_GRP_JUMP)
        if jump and ins.operands[0].type==native.X86_OP_IMM and inside(ins.operands[0].imm):
            require(ins.operands[0].imm in rows,'internal direct branch missing')
            branches+=1
        if not (jump and ins.mnemonic=='jmp') and ins.mnemonic not in ('ret','int3'):
            require(address+ins.size in rows,'exported fallthrough missing')
            fallthroughs+=1
    require((branches,fallthroughs)==(108,1024)
        and all(int(address,16) in rows for address in factory['decompiler_block_starts']),
        'exported flow/block inventory differs')
    for address,target in CALLS.items():
        ins=decoded[address]
        require(ins.mnemonic=='call' and len(ins.operands)==1
            and ins.operands[0].type==native.X86_OP_IMM and ins.operands[0].imm==target,
            'factory helper call target differs')
    anchors={0x1455b900c:'0fb64208',0x1455b9027:'83f81e',0x1455b902a:'0f87d7110000',
        0x1455b9030:'488d15c96fa4fa',0x1455b9037:'8b8c82fca35b05',
        0x1455b903e:'4803ca',0x1455b9041:'ffe1'}
    require(all(rows[address]['bytes']==raw for address,raw in anchors.items()),'switch guard/index differs')
    switch=read(0x1455ba3fc,31*4)
    targets=[base+rva for rva in struct.unpack('<31I',switch)]
    require(digest(switch)==SWITCH_SHA and targets[6]==0x1455b9781
        and all(target in rows and inside(target) for target in targets),'switch source/targets differ')
    require(''.join(rows[address]['bytes'] for address in
        (0x1455b9fdc,0x1455b9fe0,0x1455b9fe5,0x1455b9fe9))==COPY,'progress copy differs')
    for role,(address,sha) in HELPERS.items():
        helper=image.containing(address)
        require(helper is not None and image.roots[helper][0]+base==address,'helper root differs')
        parts=native.decode_ranges(image,{image.roots[helper]})
        body=b''.join(bytes.fromhex(row['bytes']) for part in parts for row in part['instructions'])
        require(digest(body)==sha,'helper source instruction bytes differ')
    require(read(0x1455ab672,7).hex()=='488d0587c73504'
        and read(0x1455ab679,7).hex()=='c6871801000003'
        and read(0x1455ab680,3).hex()=='488907', 'case6 table initialization differs')
    require([row['address'] for row in context['task_tables']]==[hex(table) for table in TABLES],
        'task table declaration differs')
    require(all(struct.unpack('<Q',read(table+0x10,8))[0]==0x1455cec10 for table in TABLES)
        and read(0x1455cec10,16).hex()==COPY_LEAF,'task virtual copy slots differ')
    result=expected()
    validate(result)
    return result
