"""Execute the current inline GMC2 URL builder and its explicit dependencies."""
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[1]/'vampir-shared'))
from vampir_core.sdk_config import assemble_gmc2_config_url_ascii

EXPORTS = {
    'run-777fc0535ec7': 'a0509eeaa329af68616c59bbb695a7440c1487aaa894f808615cebe0139bf2fa',
    'run-649b566d2b6e': 'a8c91092a8f3d87d80bf9e0bfa3c20b92e552c4639ef2f65ededd3bc5e57410b',
    'run-d064d86b997f': 'b6cbad96713d894b02208876c5fe027e161184f0c4dc66dcc1b30b000a22976f',
    'run-0cdca2f717ea': 'e5667cf351382f2ae5d7454010f6526cb24d0a11b49e86e87eb652c64babaf34',
}
INITIALIZERS = (0x1411b3260,0x1411b3290,0x1411b32c0)
GLOBALS = (0x14b5628d8,0x14b5628e8,0x14b5628f8)
START, STOP = 0x1444fa308,0x1444fa61d


def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay(root=None):
    harness = load('gmc_url_11316_harness',HERE/'native-request-harness-11316.py')
    h = harness.make_harness(EXPORTS,{0x1444fa180,0x1445320c0,0x14452ac30,0x1417619b0,*INITIALIZERS},
                             leaves={0x141453890:'e924223a07'},root=root)
    rbp,manager,settings,cls = [h.scratch+n for n in (0x10000,0x14000,0x15000,0x16000)]
    heap,events = [h.scratch+0x20000],[]

    def put(destination,text):
        if not (h.scratch <= destination <= h.scratch+0x40000-16 or destination in GLOBALS):
            raise ValueError('GMC2 string destination bound')
        data = (text+'\0').encode('utf-16le')
        if len(data)>512 or heap[0]+len(data)>=h.scratch+0x2e000:
            raise ValueError('GMC2 string allocation bound')
        pointer = heap[0] if text else 0
        if pointer:
            h.uc.mem_write(pointer,data)
            heap[0]+=(len(data)+15)&~15
        count = len(data)//2 if text else 0
        h.uc.mem_write(destination,struct.pack('<QII',pointer,count,count))

    def literal(address):
        off = h.image.offset(address-h.image.pe.base)
        data = h.raw[off:off+256]
        end = next((i for i in range(0,254,2) if data[i:i+2]==bytes(2)),None)
        if end is None:
            raise ValueError('GMC2 literal bound')
        return data[:end].decode('utf-16le')

    def fixture(machine):
        address = machine.reg_read(h.x.UC_X86_REG_RIP)
        a,b = [machine.reg_read(r) for r in (h.x.UC_X86_REG_RCX,h.x.UC_X86_REG_RDX)]
        result = 0
        if address==0x141426b30:
            value = literal(b)
            if a in GLOBALS:
                if value != ('A','B','C')[GLOBALS.index(a)]:
                    raise ValueError('GMC2 build initializer literal differs')
            elif a!=rbp or value!='5.2.11':
                raise ValueError('GMC2 SDK version fixture differs')
            put(a,value)
            result = a
            events.append(dict(action='literal_storage',destination=hex(a),value=value))
        elif address==0x141436ed0:
            if a!=rbp+0x20 or b!=2:
                raise ValueError('GMC2 build getter allocation bound')
            pointer = heap[0]
            heap[0]+=16
            if heap[0]>=h.scratch+0x2e000:
                raise ValueError('GMC2 build getter heap bound')
            machine.mem_write(a,struct.pack('<Q',pointer))
            machine.mem_write(a+12,struct.pack('<I',b))
            result = a
        elif address==0x1444b1fe0:
            result = cls
        elif address==0x141483080:
            if not h.scratch+0x20000 <= a < h.scratch+0x2e000:
                raise ValueError('GMC2 free fixture bound')
        elif address!=0x1487e914c:
            raise ValueError('Unreviewed GMC2 fixture')
        h.finish(result)

    fixtures = (0x141426b30,0x141436ed0,0x1444b1fe0,0x141483080,0x1487e914c)
    for address in fixtures:
        h.add_fixture(address,fixture)
    h.uc.mem_write(cls+0x110,struct.pack('<Q',settings))

    def run(base,group,code,market):
        heap[0] = h.scratch+0x20000
        events.clear()
        h.uc.mem_write(rbp-0x100,b'\xa5'*0xb20)
        for address in INITIALIZERS:
            h.call(address,budget=1024)
        put(manager+0x1e8,base)
        put(manager+0x1c8,group)
        put(settings+0x28,market)
        h.uc.mem_write(settings+0x48,bytes([code]))
        for register,value in ((h.x.UC_X86_REG_RSP,h.scratch+0x8000),(h.x.UC_X86_REG_RBP,rbp),
                               (h.x.UC_X86_REG_R15,manager),(h.x.UC_X86_REG_R14,0)):
            h.uc.reg_write(register,value)
        h.uc.emu_start(START,STOP,count=30000)
        if h.uc.reg_read(h.x.UC_X86_REG_RIP)!=STOP:
            raise ValueError('GMC2 URL instruction budget exhausted')
        begin,cursor,end = struct.unpack('<QQQ',bytes(h.uc.mem_read(rbp+0xf0,24)))
        if begin!=rbp+0x110 or end!=rbp+0x910 or not begin<=cursor<end or (cursor-begin)%2:
            raise ValueError('GMC2 inline builder bounds differ')
        actual = bytes(h.uc.mem_read(begin,cursor-begin)).decode('utf-16le')
        if bytes(h.uc.mem_read(end,16))!=b'\xa5'*16:
            raise ValueError('GMC2 inline builder end canary changed')
        expected = assemble_gmc2_config_url_ascii(base=base,group=group,sdk_version='5.2.11',build_code=code,market=market)
        if actual!=expected:
            raise ValueError('GMC2 native URL differs from portable helper')
        return dict(base=base,group=group,build_code=code,market=market,actual=actual,
                    events=events.copy(),end_canary_unchanged=True)

    cases = [run(base,'netmarbles-v5',code,market) for base,code,market in itertools.product(
        ('https://config.invalid','https://config.invalid/',''),(0,1,2,255),('nmp','epicgames'))]
    cases.extend([run('https://config.invalid','',0,''),run('https://config.invalid','a/b',2,'a b&c=1'),
                  run('https://apis.netmarble.com/gc2','netmarbles-v5',0,'nmp')])
    return dict(schema=1,source=str(h.source),source_sha256=h.sha,evidence=h.evidence,cases=cases,
        start=hex(START),stop=hex(STOP),copy_import=h.copy_import,fixtures=[hex(a) for a in sorted(h.fixtures)],
        dependencies={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ('replay-gmc2-url-11316.py','native-request-harness-11316.py','build-native-entry-code.py','extract-native-enums.py','build-object-zero-init-code.py')},
        portable_helper_sha256=hashlib.sha256((HERE.parents[1]/'vampir-shared/vampir_core/sdk_config.py').read_bytes()).hexdigest(),
        native_execution=True,network_ready=False,
        limits=['Actual current URL slice, three build initializers, build/version getters, ASCII append and verified copy tail execute.',
                'Manager/settings/CDO, FString storage/allocation, memcpy/free and exit registration are fixtures.',
                'All cases fit inline storage; growth target is not intercepted and is not covered.',
                'No complete Refresh, HTTP headers, active startup inputs, authentication or network.'])


if __name__=='__main__':
    report = replay()
    native = load('gmc_url_11316_root',HERE/'build-native-entry-code.py')
    audit = load('gmc_url_11316_snapshot',HERE/'audit-client-release.py')
    path = audit.save_snapshot(native.ROOT/'code-clues/gmc2-url-11316',report)
    print(json.dumps(dict(report=str(path),cases=len(report['cases']))))
