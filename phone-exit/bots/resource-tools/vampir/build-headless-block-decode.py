"""Native differential evidence for bounded literal/match block decoding."""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('block_stage', HERE/'build-headless-transport-stage.py')
stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)
sys.path.insert(0, str(HERE.parent.parent/'vampir-shared'))
from vampir_core.block_decode import decode_transport_block
x = stage.x


def extended(count):
    return bytes([255])*(count//255) + bytes([count%255])


def match_sequence(literals, offset, count):
    """Build an explicit fixture sequence, not a production compressor."""
    return (bytes([(min(len(literals),15)<<4)|min(count-4,15)])
            + (extended(len(literals)-15) if len(literals)>=15 else b'')
            + literals + struct.pack('<H',offset)
            + (extended(count-19) if count>=19 else b''))


class BlockEmulator(stage.TransportStageEmulator):
    def __init__(self):
        super().__init__()
        # Native small-offset copy tables: decoder indexes image base + RVA.
        self.table_address = 0x14898cd78
        page = self.table_address & ~4095
        self.uc.mem_map(page,4096)
        off = self.image.offset(page-self.image.pe.base)
        self.uc.mem_write(page,self.raw[off:off+4096])
        self.uc.mem_protect(page,4096,stage.ping.unicorn.UC_PROT_READ)

    def hook(self,uc,address,size,user):
        if address == stage.ping.MEMCPY:
            # The Ping harness permits 256 bytes; block staging needs up to 4096.
            # Both CRT functions copy the same non-overlapping fixture ranges.
            self.copy_sizes.append(uc.reg_read(x.UC_X86_REG_R8))
            stage.TransportStageEmulator.hook(self,uc,stage.MEMMOVE,size,user)
            return
        super().hook(uc,address,size,user)

    def decode(self, block, capacity=4096):
        if len(block)>2048 or not 0<=capacity<=4096:
            raise ValueError('Evidence allocation bound')
        self.copy_sizes=[]; self.io_entries=[]; self.decompress_calls=0
        source=self.scratch+0x8000; output=self.scratch+0x18000
        self.uc.mem_write(source,block+bytes(64))
        self.uc.mem_write(output,bytes(4160))
        self.call(stage.DECOMPRESS,source,output,len(block),capacity)
        result=self.uc.reg_read(x.UC_X86_REG_RAX)&0xffffffff
        if result&0x80000000: result-=0x100000000
        if result>capacity: raise ValueError('Native output outside capacity')
        return result, bytes(self.uc.mem_read(output,max(result,0)))


def main():
    emulator=BlockEmulator(); cases=[]; invalid=[]
    for size in [0,1,14,15,16,254,255,270,512,1024]:
        expected=bytes(i%251 for i in range(size))
        cases.append((stage.literal_block(expected),expected,'literals'))
    for offset in [1,2,3,4,5,7,8,15,16,31,255,512]:
        for count in [7,18,19,20,270,540]:
            prefix=bytes(i%251 for i in range(offset))
            expected=bytearray(prefix)
            for _ in range(count): expected.append(expected[-offset])
            expected.extend(b'tail!')
            block=match_sequence(prefix,offset,count)+stage.literal_block(b'tail!')
            cases.append((block,bytes(expected),'match'))
    prefix=b'abcdefgh'; expected=bytearray(prefix)
    block=match_sequence(prefix,8,40)
    for _ in range(40): expected.append(expected[-8])
    block+=match_sequence(b'xyz',3,300)+stage.literal_block(b'final-tail')
    expected.extend(b'xyz')
    for _ in range(300): expected.append(expected[-3])
    expected.extend(b'final-tail')
    cases.append((block,bytes(expected),'multiple-matches'))
    vectors=[]
    for block,expected,kind in cases:
        for capacity in sorted({max(1,len(expected)),4096}):
            result,output=emulator.decode(block,capacity)
            shared=decode_transport_block(block,max_output_size=capacity)
            if output!=expected or result!=len(expected) or shared!=expected:
                raise ValueError(f'Native/shared block mismatch: {kind}, {len(expected)}, {capacity}')
            vectors.append(dict(block_hex=block.hex(),capacity=capacity,result=result,
                                output_hex=output.hex(),kind=kind))
    for block in [b'',b'\xf0',b'\xf0\xff',b'\x50abc',b'\x10a\xff\xff'+b'\x50tail!']:
        result,_=emulator.decode(block)
        if result>=0: raise ValueError('Invalid fixture accepted by native decoder')
        try: decode_transport_block(block,max_output_size=4096)
        except ValueError: pass
        else: raise ValueError('Shared decoder accepted invalid fixture')
        invalid.append(dict(block_hex=block.hex(),capacity=4096,result=result))
    for block,expected,kind in cases:
        if len(expected)<2: continue
        capacity=len(expected)-1
        result,_=emulator.decode(block,capacity)
        if result>=0: raise ValueError('Native accepted insufficient output capacity')
        try: decode_transport_block(block,max_output_size=capacity)
        except ValueError: pass
        else: raise ValueError('Shared decoder exceeded output budget')
        invalid.append(dict(block_hex=block.hex(),capacity=capacity,result=result))
    # Static second-stage linkage, with decoded instruction boundary evidence.
    roots={emulator.image.roots[emulator.image.containing(address)]
           for address in [0x1445ed720,0x1445dede0]}
    fragments=stage.native.decode_ranges(emulator.image,roots)
    rows={i['address']:i for f in fragments for i in f['instructions']}
    target=rows[0x1445ed65a]['rip_references'][0]
    thunks=[]
    for address,slot in [(0x1415f6848,0x38),(target,0x40)]:
        off=emulator.image.offset(address-emulator.image.pe.base)
        code=emulator.raw[off:off+6]
        if code!=b'\x48\x8b\x01\xff\x60'+bytes([slot]):
            raise ValueError('Listener virtual thunk changed')
        thunks.append(dict(address=address,file_offset=off,bytes=code.hex(),virtual_slot=slot))
    table_off=emulator.image.offset(emulator.table_address-emulator.image.pe.base)
    table=emulator.raw[table_off:table_off+64]
    report=dict(schema_version=1,source=emulator.bindings['source'],sha256=emulator.bindings['sha256'],
                tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                fragments=emulator.stage_fragments,listener_fragments=fragments,listener_thunks=thunks,
                copy_table=dict(address=emulator.table_address,file_offset=table_off,bytes=table.hex(),
                                sha256=hashlib.sha256(table).hexdigest()),
                cases=vectors,invalid_cases=invalid,
                statistics=dict(native_valid_cases=len(vectors),native_invalid_cases=len(invalid)),
                network_ready=False,
                limitations=['Standalone native decoder replay; CRT memory functions bounded shims.',
                             'Listener linkage is static evidence; no full listener-loop replay.',
                             'No dictionary, whole transport socket or incoming integrity proof.',
                             'Zero offset rejected locally; native invalid-input byte-for-byte parity not promised.'])
    path=stage.native.ROOT/'code-clues/headless-block-decode.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n','utf-8')
    print(json.dumps(dict(output=str(path),**report['statistics'],listener_target=hex(target),network_ready=False)))


if __name__=='__main__':main()
