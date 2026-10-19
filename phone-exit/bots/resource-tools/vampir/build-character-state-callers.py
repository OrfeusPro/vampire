"""Reuse the validated E8 scanner to locate character-state getter consumers."""
import hashlib
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('state_call_scan',HERE/'build-selection-service-callers.py')
scan=importlib.util.module_from_spec(spec);spec.loader.exec_module(scan)
scan.GETTER=0x145c859f0


def build():
    report=scan.build()
    report['scanner_tool_sha256']=report['tool_sha256']
    report['tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['field_f0_candidates']=[dict(address=c['address'],root=c['root'],context=c['context'])
        for c in report['callers'] if any('+ 0xf0]' in r['operands'] for r in c['context'])]
    report['limitations'].append('Nearby +f0 operands are candidates only; register/receiver/dataflow identity is not inferred.')
    return report


if __name__=='__main__':
    report=build();path=scan.native.ROOT/'code-clues/character-state-callers.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        callers=len(report['callers']),field_f0_candidates=len(report['field_f0_candidates']),
        unresolved=len(report['unresolved']),failures=len(report['failures']))))
