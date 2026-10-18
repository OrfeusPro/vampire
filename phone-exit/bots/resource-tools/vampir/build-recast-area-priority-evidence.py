"""Record the native cost-array -> sorted ordinal -> nav priority chain."""
import hashlib,importlib.util,json,math,random
from pathlib import Path
HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main(root=Path('F:/PhoneExit Resources/Vampir')):
    spec=importlib.util.spec_from_file_location('area_priority_evidence',HERE/'recast-area-priority-emulator.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    emulator=module.AreaPriorityEmulator(root);rows={r['address']:r for f in emulator.priority_fragments for r in f['instructions']};anchors=[]
    for address,mnemonic,operands in [
        (0x145240b44,'movups','xmmword ptr [rax + 0x94], xmm0'),(0x145240b59,'movups','xmmword ptr [rax + 0xc4], xmm0'),
        (0x1452b4838,'mov','rax, qword ptr [rax + 0x400]'),(0x1452b484d,'mov','rcx, qword ptr [rax + 0x10]'),
        (0x1452b4864,'lea','r14, [rcx + 8]'),(0x1452b4880,'movsd','xmm0, qword ptr [rsi + r14 + 0x208]'),
        (0x1452b488f,'addsd','xmm0, qword ptr [rsi + r14 + 8]'),(0x1452b4896,'mov','dword ptr [rsp + 0x40], ebp'),
        (0x1452b48cf,'movups','xmmword ptr [rax + rcx*8], xmm0'),(0x1452b48d3,'cmp','ebp, 0x40'),
        (0x1452b490c,'call','0x142405a70'),(0x1452b4920,'movsxd','rax, dword ptr [rcx]'),
        (0x1452b4927,'mov','byte ptr [rsp + rax + 0x50], bl'),(0x1452b492b,'inc','ebx'),
        (0x1452b4943,'call','0x14523d610'),(0x14523d613,'movups','xmmword ptr [rcx + 0x94], xmm0'),
        (0x14523d634,'movups','xmmword ptr [rcx + 0xc4], xmm1'),(0x142405ac2,'call','0x1487a2ecd'),
        (0x142405ac7,'addss','xmm0, xmm0'),(0x142405ad8,'cvttss2si','rax, xmm0'),
        (0x142405c74,'comisd','xmm0, xmmword ptr [rax]'),(0x142405c78,'cmovb','rcx, rax')]:
        row=rows[address]
        if (row['mnemonic'],row['operands'])!=(mnemonic,operands):raise ValueError('Changed area priority anchor '+hex(address))
        anchors.append(row)
    if emulator.constructor_priorities()!=[0]*64:raise ValueError('Changed constructor priorities')
    cases=[]
    def run(name,cost,fixed):
        result=emulator.priorities(cost,fixed)
        if sorted(result['ranks'])!=list(range(64)):raise ValueError('Priorities are not ordinal ranks')
        for i in range(64):
            for j in range(64):
                if result['sums'][i]<result['sums'][j] and not result['ranks'][i]<result['ranks'][j]:raise ValueError('Cost ordering mismatch')
        cases.append(dict(name=name,**result))
    run('all_equal',[1.]*64,[0.]*64)
    run('increasing',list(map(float,range(64))),[0.]*64)
    run('decreasing',list(map(float,range(63,-1,-1))),[0.]*64)
    run('fixed_cost_reorders',[1.]*64,list(map(float,range(63,-1,-1))))
    run('ties_four_groups',[float(i%4) for i in range(64)],[0.]*64)
    run('fractional_and_negative',[i/8-4 for i in range(64)],[(-1.)**i/16 for i in range(64)])
    run('large_finite',[3.4e38 if i%2 else 1. for i in range(64)],[0.]*64)
    run('signed_zero',[math.copysign(0.,-1 if i%2 else 1) for i in range(64)],[0.]*64)
    rng=random.Random(20261018)
    for index in range(64):run('random_'+str(index),[rng.randrange(20)/4 for _ in range(64)],[rng.randrange(8)/8 for _ in range(64)])
    source=json.loads((root/'code-clues/native-enums.json').read_bytes());path=root/'code-clues/recast-area-priority-evidence.json'
    report=dict(source=source['source'],sha256=source['sha256'],emulator_sha256=sha((HERE/'recast-area-priority-emulator.py').read_bytes()),
        base_emulator_sha256=sha((HERE/'recast-portal-emulator.py').read_bytes()),anchors=anchors,fragments=emulator.priority_fragments,
        native_pages=list(emulator.pages.values()),math_import=emulator.math_import,
        shims=dict(logf_only_input64=emulator.shims[0],logf_calls=len(emulator.shims),memset='Native sort scratch zero fill only, destination/count/value checked.',
            skipped_cookie_call=0x142405c4c,preallocated_sum_rows=64,excluded_wrapper_calls=['TArray reserve/grow/free; caller/filter pointer chain is static evidence only.']),
        constructor_priorities=[0]*64,cases=cases,summary=dict(native_cases=len(cases),native_sort_calls=emulator.sort_calls,native_heap_fallback_calls=emulator.heap_calls,
            priority_count=64,sorted_sum_ordinal_verified=True,equal_costs_have_equal_ranks=False,active_cost_arrays_verified=False,routes_verified=0,navigation_ready=False),
        limitations=['The two arrays are read through the wrapper/filter pointer chain; active object/CDO values have not been recovered.',
            'Equal sums still receive distinct ranks; native sort is not stable by area ID. Do not infer exact active costs from rank comparisons.',
            'Native sum loop, complete sort/heap code and rank-copy blocks execute with local preallocated storage; wrapper allocation/object lookup is not executed.',
            'Imported logf is shimmed only for float32 input64; memset and security-cookie handling are declared separately.'])
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2),'utf-8')
    print(json.dumps(dict(**report['summary'],sha256=sha(path.read_bytes()),equal_cost_ranks_11_63_10=[cases[0]['ranks'][i] for i in [11,63,10]])));return report

if __name__=='__main__':main()
