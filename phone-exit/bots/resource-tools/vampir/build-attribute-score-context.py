"""Identify the local weight score's item-comparison consumer; gates are synthetic."""
import hashlib
import importlib.util
import itertools
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]/'.tools/vampir-analysis'))
import unicorn
from unicorn import x86_const as x

ROOT = Path('F:/PhoneExit Resources/Vampir')
STUBS = [0x145a80590,0x145db9d00,0x145db73c0,0x1455b8180,0x1455baad0,
         0x1455b5b10,0x145d371c0,0x145d342d0,0x145d2da30]


class ComparisonEmulator:
    def __init__(self, root=ROOT):
        spec = importlib.util.spec_from_file_location('score_context_native', HERE/'build-native-entry-code.py')
        n = importlib.util.module_from_spec(spec); spec.loader.exec_module(n)
        self.meta = json.loads((root/'code-clues/native-enums.json').read_text('utf-8'))
        self.raw = Path(self.meta['source']).read_bytes()
        if hashlib.sha256(self.raw).hexdigest()!=self.meta['sha256']:
            raise ValueError('Changed native client')
        self.image = n.Image(self.raw)
        addresses = [0x145db6fb0,0x1463b73f0,0x1463b7e40,0x145aa2460,0x145a80590,0x145db9d00]
        self.fragments = n.decode_ranges(self.image,{self.image.roots[self.image.containing(a)] for a in addresses})
        rows = {r['address']:r for f in self.fragments for r in f['instructions']}
        expected = [(0x145db6fc1,'call','0x145a80590'),
                    (0x145aa2970,'call','0x1487a2e49'),
                    (0x145aa29b4,'mov','byte ptr [rbx + 0x61], al'),
                    (0x145db7034,'movzx','r8d, byte ptr [rax + 0x61]'),
                    (0x145db7039,'call','0x1455b5b10'),
                    (0x145db705f,'call','0x145d2da30'),
                    (0x145db7069,'call','0x145d2da30'),
                    (0x145db706e,'cmp','eax, ebx'),(0x145db7075,'setg','al'),
                    (0x1463b7753,'cmp','byte ptr [rax + 0x50], 1'),
                    (0x1463b7775,'call','0x145db6fb0'),
                    (0x1463b777a,'mov','rbx, qword ptr [rdi + 0xc68]'),
                    (0x1463b77ac,'mov','dl, 4'),(0x1463b77ae,'test','sil, sil'),
                    (0x1463b77b3,'mov','dl, 1'),
                    (0x1463b7f1e,'call','0x145db6fb0')]
        self.anchors = []
        for a,m,o in expected:
            r = rows[a]
            if (r['mnemonic'],r['operands'])!=(m,o):
                raise ValueError('Changed context anchor '+hex(a))
            self.anchors.append(r)
        self.literals = []
        for a,text in [(0x145aa2969,'EquipmentType')]:
            r = rows[a]; va = r['rip_references'][0]; off = self.image.offset(va-self.image.pe.base)
            content = (text+'\0').encode('ascii')
            if self.raw[off:off+len(content)]!=content:
                raise ValueError('Changed item field name')
            self.literals.append(dict(address=va,file_offset=off,bytes=content.hex(),name=text))
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
        self.base = 0x20000000
        self.uc.mem_map(self.base,0x10000)
        pages = {a & ~4095 for a in STUBS+[0x145db6fb0,0x141482990,0x1463b77ac]}
        for page in pages:
            self.uc.mem_map(page,4096)
            off = self.image.offset(page-self.image.pe.base)
            self.uc.mem_write(page,self.raw[off:off+4096])
        for a in STUBS:
            self.uc.mem_write(a,b'\xc3')
        for page in pages:
            self.uc.mem_protect(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.uc.hook_add(unicorn.UC_HOOK_CODE,self.hook)

    def hook(self,uc,address,size,user):
        if address not in STUBS:
            return
        c = self.case; b = self.base
        self.calls.append(address)
        if address==0x145a80590:
            handle = uc.reg_read(x.UC_X86_REG_RCX)
            uc.mem_write(handle+8,struct.pack('<Q',b+0x1000 if c['info'] else 0))
            result = handle
        elif address==0x145db9d00:result=c['class_allowed']
        elif address==0x145db73c0:result=c['excluded']
        elif address==0x1455b8180:result=b+0x4000
        elif address==0x1455baad0:result=c['blocked']
        elif address==0x1455b5b10:
            if uc.reg_read(x.UC_X86_REG_R8)!=6:
                raise ValueError('EquipmentType argument changed')
            result=b+0x2000 if c['slot'] else 0
        elif address==0x145d371c0:result=b+0x5000
        elif address==0x145d342d0:result=b+0x3000 if c['peer'] else 0
        elif address==0x145d2da30:
            owner=uc.reg_read(x.UC_X86_REG_RCX)
            if owner not in [b+0x3000,b+0x6000]:raise ValueError('Unexpected score owner')
            result=c['peer_score'] if owner==b+0x3000 else c['candidate_score']
            self.score_owners.append(owner)
        uc.reg_write(x.UC_X86_REG_RAX,int(result)&0xffffffffffffffff)

    def execute(self,case):
        self.case=case;self.calls=[];self.score_owners=[];uc=self.uc;b=self.base
        uc.mem_write(b,bytes(0x10000))
        uc.mem_write(b+0x1061,b'\x06')
        uc.mem_write(b+0x2008,struct.pack('<Q',123456))
        uc.mem_write(b+0xf000,struct.pack('<Q',b+0xe000))
        uc.reg_write(x.UC_X86_REG_RCX,b+0x6000)
        uc.reg_write(x.UC_X86_REG_RSP,b+0xf000)
        uc.reg_write(x.UC_X86_REG_RBX,0x1234)
        uc.reg_write(x.UC_X86_REG_RDI,0x5678)
        uc.emu_start(0x145db6fb0,b+0xe000,count=512)
        if uc.reg_read(x.UC_X86_REG_RIP)!=b+0xe000:
            raise ValueError('Comparison did not return')
        if uc.reg_read(x.UC_X86_REG_RBX)!=0x1234 or uc.reg_read(x.UC_X86_REG_RDI)!=0x5678:
            raise ValueError('Nonvolatile registers changed')
        return bool(uc.reg_read(x.UC_X86_REG_AL))

    def ui_branch(self,result):
        uc=self.uc
        uc.reg_write(x.UC_X86_REG_RSI,int(result))
        uc.reg_write(x.UC_X86_REG_RDX,0)
        uc.emu_start(0x1463b77ac,0x1463b77b5,count=8)
        if uc.reg_read(x.UC_X86_REG_RIP)!=0x1463b77b5:
            raise ValueError('UI selector boundary changed')
        return uc.reg_read(x.UC_X86_REG_DL)


def main(root=ROOT):
    emulator=ComparisonEmulator(root)
    cases=[]
    for bits in itertools.product([False,True],repeat=6):
        gates=dict(zip(['info','class_allowed','excluded','blocked','slot','peer'],bits))
        for candidate,peer in [(-1,0),(0,0),(1,0),(-2147483648,2147483647),(2147483647,-2147483648)]:
            case=dict(gates,candidate_score=candidate,peer_score=peer)
            expected=bool(gates['info'] and gates['class_allowed'] and not gates['excluded'] and not gates['blocked']
                          and (not gates['slot'] or not gates['peer'] or candidate>peer))
            result=emulator.execute(case)
            if result!=expected:raise ValueError('Native comparison mismatch')
            ui=emulator.ui_branch(result)
            if ui!=(4 if result else 1):raise ValueError('UI branch mismatch')
            cases.append(dict(case,result=result,ui_argument=ui,score_calls=len(emulator.score_owners)))
    inherited_path=root/'code-clues/item-skill-binding.json'
    inherited=json.loads(inherited_path.read_text('utf-8'))
    if inherited['sha256']!=emulator.meta['sha256']:
        raise ValueError('Different item table binding EXE')
    for anchor in inherited['anchors']+inherited['data_anchors']:
        blob=bytes.fromhex(anchor['bytes']);off=anchor['file_offset']
        if emulator.raw[off:off+len(blob)]!=blob:raise ValueError('Changed inherited item binding')
    report=dict(source=emulator.meta['source'],sha256=emulator.meta['sha256'],fragments=emulator.fragments,
        anchors=emulator.anchors,data_anchors=emulator.literals,
        inherited_binding=dict(file='code-clues/item-skill-binding.json',sha256=hashlib.sha256(inherited_path.read_bytes()).hexdigest()),
        cases=cases,statistics=dict(comparisons=len(cases),ui_selectors=len(cases)),
        context='Item comparison: candidate score > peer score after gates; matching slot lookup keyed by Item.EquipmentType',
        item_comparison_verified=True,total_character_power_verified=False,
        ui_widget_name_verified=False,full_score_function_executed=False,
        limitations=['Whole comparator executed with synthetic dependency/score stubs; game state and score function not executed here.',
                    'Exclusion/block/class checks are Boolean inputs, not recovered complete game rules.',
                    'No peer returns true only after earlier gates succeed; equality is false.',
                    'UI code selects argument 4/1 for widget+0xc68; widget resource/name and enum meaning not bound here.',
                    'This identifies an item-comparison use, not every possible indirect use or total character power.'])
    path=root/'code-clues/attribute-score-context.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(anchors=len(report['anchors']),fragments=len(report['fragments']),**report['statistics'])))
    return report


if __name__=='__main__':main()
