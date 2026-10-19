"""Execute native percent byte loop; explicit UTF-8 input and %u conversion shim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('percent_validation', HERE / 'replay-nid-result-validation.py')
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)
config = validation.bootstrap.settings.config
START, STOP = 0x141c13495, 0x141c13764


class Replay:
    def __init__(self, raw, image, fragments):
        ping = validation.bootstrap.settings.ping
        self.x = ping.x
        self.uc = ping.unicorn.Uc(ping.unicorn.UC_ARCH_X86, ping.unicorn.UC_MODE_64)
        self.base, self.stack = 0x20000000, 0x20010000
        self.uc.mem_map(self.base, 0x20000)
        self.allowed = {r['address'] for f in fragments for r in f['instructions'] if START <= r['address'] <= STOP}
        pages = {a & ~4095 for a in self.allowed | {0x141440ac0, 0x1487a2e19}}
        for page in pages:
            self.uc.mem_map(page, 4096)
            offset = image.offset(page - image.pe.base)
            self.uc.mem_write(page, raw[offset:offset + 4096])
        self.events = []
        self.uc.hook_add(ping.unicorn.UC_HOOK_CODE, self.hook)

    def hook(self, uc, address, size, user):
        if address == STOP:
            uc.emu_stop()
            return
        if address in self.allowed:
            return
        x = self.x
        a,b,c,d = [uc.reg_read(r) for r in (x.UC_X86_REG_RCX,x.UC_X86_REG_RDX,x.UC_X86_REG_R8,x.UC_X86_REG_R9)]
        if address == 0x141440ac0:
            if b != 8 or d != 1:
                raise ValueError('Unexpected percent unicode conversion arguments')
            unit = struct.unpack('<I', bytes(uc.mem_read(c, 4)))[0]
            payload = chr(unit).encode('utf-8', 'strict')
            uc.mem_write(a, payload)
            result = a + len(payload)
            self.events.append(dict(kind='unicode_to_utf8_shim', unit=unit, bytes=payload.hex()))
        elif address == 0x1487a2e19:
            if not 0 < c <= 8 or not all(self.base <= p < self.base + 0x20000 - c for p in (a,b)):
                raise ValueError('Percent copy shim exceeds bounds')
            uc.mem_write(a, bytes(uc.mem_read(b,c)))
            result = a
        else:
            raise ValueError('Unreviewed percent loop target ' + hex(address))
        rsp=uc.reg_read(x.UC_X86_REG_RSP)
        ret=struct.unpack('<Q',bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(x.UC_X86_REG_RAX,result)
        uc.reg_write(x.UC_X86_REG_RSP,rsp+8)
        uc.reg_write(x.UC_X86_REG_RIP,ret)

    def run(self, text):
        data=text.encode('utf-8')
        if not 0 <= len(data) <= 1024:
            raise ValueError('Percent fixture input outside reviewed bounds')
        input_pointer, output_pointer=self.base+0x2000,self.base+0x4000
        self.uc.mem_write(input_pointer,data+b'\0')
        self.uc.mem_write(output_pointer-8,b'\xaa'*4112)
        self.uc.mem_write(self.stack+0x28,struct.pack('<QII',output_pointer,0,4096))
        self.uc.mem_write(self.stack+0x38,struct.pack('<Q',self.base+0x6000))
        self.uc.mem_write(self.stack+0xd0,struct.pack('<I',len(data)))  # RBP-0x30
        for name,value in dict(rsp=self.stack,rbp=self.stack+0x100,rcx=len(data),r12=0,r15=input_pointer).items():
            self.uc.reg_write(getattr(self.x,'UC_X86_REG_'+name.upper()),value)
        self.uc.emu_start(START,0,count=65536)
        if self.uc.reg_read(self.x.UC_X86_REG_RIP)!=STOP:
            raise ValueError('Percent replay did not reach reviewed stop')
        count=struct.unpack('<I',bytes(self.uc.mem_read(self.stack+0x30,4)))[0]
        if not 1 <= count <= 4096:
            raise ValueError('Percent output count outside fixture buffer')
        output=bytes(self.uc.mem_read(output_pointer,count))
        visible=self.uc.reg_read(self.x.UC_X86_REG_RBX)
        if visible != output.index(0) or output[-1:]!=b'\0':
            raise ValueError('Percent native strlen boundary differs')
        if bytes(self.uc.mem_read(output_pointer-8,8))!=b'\xaa'*8 or bytes(self.uc.mem_read(output_pointer+4096,8))!=b'\xaa'*8:
            raise ValueError('Percent output guards changed')
        return dict(input=text, output_bytes=output[:-1].hex(), strlen_bytes=visible,
                    visible_bytes=output[:visible].hex(), guards_unchanged=True, calls=self.events)


def build():
    prior=json.loads((config.native.ROOT/'code-clues/headless-nid-result.json').read_text('utf-8'))
    raw=Path(prior['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prior['sha256']:
        raise ValueError('Percent source EXE changed')
    image=config.native.Image(raw)
    roots={image.roots[image.containing(a)] for a in (0x141c13390,0x1445255e0,0x144591880,0x1445123b0)}
    fragments=config.native.decode_ranges(image,roots)
    cases=['','a+b','%2B','%20','a%26b%3Dc','%2526','%','%2','%u','%u00','%u0041','%u20AC',
           '%GG','%G1','%1G','%U0041','before%00after','plain_ASCII-._~','a'*1024]
    cases += ['%'+format(n,'02X') for n in range(128)]
    results=[Replay(raw,image,fragments).run(text) for text in cases]
    return dict(schema_version=1,source=prior['source'],sha256=prior['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),fragments=fragments,
        start=START,stop=STOP,cases=results,network_ready=False,limitations=[
            'Actual percent byte loop, terminator append and strlen executed; converted UTF8 input/output arena supplied explicitly.',
            'Native UTF16-to-UTF8 and final UTF8-to-UTF16 conversion not executed; %u unit-to-UTF8 is an explicit shim.',
            'Caller URI/query getter/map functions recorded statically only, no full callback acceptance or duplicate semantics.',
            'No account, network, SDK settings persistence, callback or game session.'])


if __name__=='__main__':
    report=build()
    path=config.native.ROOT/'code-clues/sdk-percent-decode-replay.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),cases=len(report['cases'])),indent=2))
