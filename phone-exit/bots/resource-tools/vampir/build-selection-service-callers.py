"""Find direct singleton getter callers using the existing PE call scanner."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('service_call_scan',HERE/'build-entry-window-code.py')
scan=importlib.util.module_from_spec(spec);spec.loader.exec_module(scan)
native=scan.native
GETTER=0x1456048e0


def build():
    source=json.loads((native.ROOT/'code-clues/selection-service-replay.json').read_text('utf-8'))
    raw=Path(source['source']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=source['sha256']:raise ValueError('Selection caller source changed')
    image=native.Image(raw);candidates=[]
    for section in image.pe.sections:
        if section['name']=='.text':
            candidates.extend(scan.direct_call_candidates(raw,section['raw'],section['raw_size'],image.pe.address,{GETTER}))
    roots={image.roots[f] for a,_ in candidates if (f:=image.containing(a)) is not None}
    fragments=[];failures=[]
    for root in sorted(roots):
        try:fragments.extend(native.decode_ranges(image,{root}))
        except ValueError as error:failures.append(dict(root=root[0]+image.pe.base,error=str(error)))
    rows={r['address']:(f,i,r) for f in fragments for i,r in enumerate(f['instructions'])}
    callers=[];unresolved=[]
    for a,target in candidates:
        found=rows.get(a)
        if found is None or not scan.checked_call(found[2],target):
            unresolved.append(dict(address=a,target=target));continue
        f,i,r=found
        callers.append(dict(address=a,root=f['root_begin_rva']+image.pe.base,
            context=f['instructions'][max(0,i-4):i+24]))
    return dict(schema_version=1,source=source['source'],sha256=source['sha256'],
        tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),getter=GETTER,
        fragments=fragments,callers=callers,unresolved=unresolved,failures=failures,
        limitations=['Direct E8 candidates validated against decoded PE unwind roots only.',
            'Indirect/tail calls and inline singleton accesses are not covered.',
            'Neighboring virtual-call offsets do not prove receiver identity or runtime reachability.'])


if __name__=='__main__':
    report=build();path=native.ROOT/'code-clues/selection-service-callers.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        callers=len(report['callers']),unresolved=len(report['unresolved']),failures=len(report['failures']))))
