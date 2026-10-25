"""Compare explicit old/current whole instruction contracts and report boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path('F:/PhoneExit Resources/Vampir')
OLD = '98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e'
NEW = 'd00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
PAIRS = {
    'select_writer':(0x1456e9550,0x1456e8280),
    'select_request':(0x145db0e30,0x145dafa00),
    'select_reader':(0x1456f1390,0x1456f00c0),
    'reserve_reader':(0x1458506a0,0x14584f3d0),
    'reserve_nested':(0x145823280,0x145821fb0),
    'start_writer':(0x1456bbdc0,0x1456baaf0),
    'start_request':(0x145db4510,0x145db30e0),
    'start_reader':(0x1458507c0,0x14584f4f0),
    'finish_request':(0x145db3fe0,0x145db2bb0),
    'finish_gate':(0x14561cf70,0x14561bca0),
    'finish_reader':(0x1458503f0,0x14584f120),
    'finish_nested':(0x1458233c0,0x1458220f0),
    'ping_reader':(0x1456dc6e0,0x1456db410),
    'ping_handler':(0x14679da80,0x14679c450),
    'ping_receiver':(0x1467d09b0,0x1467cf320),
}


def main():
    spec = importlib.util.spec_from_file_location('world_relocation_native',HERE/'build-native-entry-code.py')
    n = importlib.util.module_from_spec(spec); spec.loader.exec_module(n)
    images = []
    for sha in (OLD,NEW):
        raw = (ROOT/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha: raise ValueError('World contract source differs')
        images.append(n.Image(raw))
    cs = n.capstone.Cs(n.capstone.CS_ARCH_X86,n.capstone.CS_MODE_64); cs.detail=True
    reports = []
    for name, pair in PAIRS.items():
        sets = []
        for im, at in zip(images,pair):
            part = im.containing(at)
            if part is None or im.pe.base+im.roots[part][0]!=at: raise ValueError('Contract requires unwind root')
            rows = [r for f in n.decode_ranges(im,{im.roots[part]}) for r in f['instructions']]
            shape, refs, calls = [], [], []
            locations = {r['address'] for r in rows}
            for row in rows:
                data = bytearray.fromhex(row['bytes']); ins = next(cs.disasm(bytes(data),row['address']))
                if row['call'] or row['branch']:
                    if ins.imm_size:
                        if row['direct_target'] in locations:
                            target = ('local',row['direct_target']-at)
                        else:
                            target = ('external',len(calls)); calls.append(dict(offset=row['address']-at,target=hex(row['direct_target'])))
                        data[ins.imm_offset:ins.imm_offset+ins.imm_size]=bytes(ins.imm_size)
                    else: target=('indirect',row['operands'])
                else: target=None
                for ref in row['rip_references']:
                    refs.append(dict(offset=row['address']-at,address=hex(ref),instruction=row['operands']))
                    data[ins.disp_offset:ins.disp_offset+ins.disp_size]=bytes(ins.disp_size)
                shape.append((row['address']-at,data.hex(),target))
            sets.append(dict(shape=shape,calls=calls,refs=refs))
        equal = sets[0]['shape']==sets[1]['shape']
        reports.append(dict(name=name,old=hex(pair[0]),current=hex(pair[1]),equal=equal,
            calls=list(zip(sets[0]['calls'],sets[1]['calls'])),data=list(zip(sets[0]['refs'],sets[1]['refs'])),
            instruction_count=[len(s['shape']) for s in sets]))
    report = dict(source_sha256=NEW,baseline_sha256=OLD,functions=reports,
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),network_used=False,
        limits=['Full instruction shape comparison masks only RIP relocations and relative external calls.',
                'External callees/data are explicit unresolved pairs, not proven equivalent by this report.',
                'No native execution, active engine state, whole nested decoder or live compatibility claim.'])
    payload = (json.dumps(report,indent=2)+'\n').encode();sha=hashlib.sha256(payload).hexdigest()
    folder=ROOT/'code-clues/world-relocation-11316'/sha;folder.mkdir(parents=True,exist_ok=True)
    (folder/'manifest.json').write_bytes(payload)
    print(json.dumps(dict(report=str(folder/'manifest.json'),sha256=sha,
        functions=[(r['name'],r['equal'],r['instruction_count']) for r in reports])))


if __name__=='__main__':main()
