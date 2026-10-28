"""Consume existing source-pinned BinDiff pairs; never export or accept a role by score."""
import copy
import re
from pathlib import Path


def inputs(index,root,sha):
    root=Path(root).resolve()
    paths=sorted((root/'binary-diff/comparisons').glob('*/manifest.json'))
    if len(paths)>4096:raise ValueError('BinDiff comparison inventory budget exceeded')
    found=[]
    for path in paths:
        value=index.read_json(path)
        if value.get('source_sha256')==sha:
            material={}
            for key in ('database','primary','secondary'):
                target=Path(value[key]).resolve()
                if not target.is_relative_to(root/'binary-diff'):
                    raise ValueError('BinDiff material outside the public library')
                material[str(target)]=index.digest(target)
                if key!='database':
                    exported=index.read_json(target)
                    blob=Path(exported['export']).resolve()
                    if not blob.is_relative_to(root/'binary-diff/exports'):
                        raise ValueError('BinExport outside the public library')
                    material[str(blob)]=index.digest(blob)
            found.append(dict(path=str(path),sha256=index.digest(path),artifacts=material))
    return found


def matches(index,root,sha,receipts):
    root=Path(root).resolve();tool=index.extension('binary-diff');found={}
    for item in receipts:
        path=Path(item['path']).resolve()
        if not path.is_relative_to(root/'binary-diff/comparisons') or index.digest(path)!=item['sha256']:
            raise ValueError('BinDiff comparison receipt changed')
        if any(index.digest(p)!=expected for p,expected in item.get('artifacts',{}).items()):
            raise ValueError('BinDiff material changed during candidate resolution')
        declared=index.read_json(path)
        if any(not isinstance(declared.get(key),str) or not re.fullmatch('[0-9a-f]{64}',declared[key])
               for key in ('baseline_sha256','source_sha256')):
            raise ValueError('BinDiff needs complete source hashes')
        for key in ('primary','secondary','database'):
            if not Path(declared[key]).resolve().is_relative_to(root/'binary-diff'):
                raise ValueError('BinDiff artifact outside the public library')
        for side,expected in (('primary',declared['baseline_sha256']),('secondary',sha)):
            export=index.read_json(Path(declared[side]))
            source=(root/'client-code-snapshots'/expected/'ProjectRED-Win64-Shipping.exe').resolve()
            if Path(export['source']).resolve()!=source or not Path(export['export']).resolve().is_relative_to(root/'binary-diff/exports'):
                raise ValueError('BinDiff export source is outside the exact snapshot')
        checked=tool.checked_comparison(path)
        if checked['source_sha256']!=sha:
            raise ValueError('BinDiff target source differs')
        for row in tool.candidates(Path(checked['database'])):
            key=(checked['baseline_sha256'],row['old_address'])
            values=found.setdefault(key,{})
            values.setdefault(row['new_address'],[]).append(dict(comparison=item,
                database=dict(path=checked['database'],sha256=checked['database_sha256']),
                state='candidate',semantic_verification=False))
    return found


def resolve(index,args,model,sha,discoveries,receipts):
    resolver=index.extension('update-bindings')
    first=resolver.resolve(index,args,model,sha,discoveries)
    if not receipts:return first
    suggestions=matches(index,args.root,sha,receipts)
    revised=copy.deepcopy(model);adopted={}
    for contract in revised['contracts']:
        state=first['contracts'][contract['id']]
        for recipe in contract['recipes']:
            key=recipe['key']
            if (recipe['method']!='closed_shape' or key in state.get('closed_shapes',{})
                    or state.get('search_candidates',{}).get(key)):
                continue
            choices=suggestions.get((recipe['baseline_sha256'],recipe['baseline_address']),{})
            if len(choices)!=1:continue
            candidate,evidence=next(iter(choices.items()))
            contract['bindings'].setdefault(sha,{})[key]=candidate
            adopted[(contract['id'],key)]=evidence
    if not adopted:return first
    # Scores and names never establish a binding. The original complete
    # instruction/callee/data verifier runs again, including caller pruning.
    result=resolver.resolve(index,args,revised,sha,discoveries)
    for (contract,key),evidence in adopted.items():
        proof=result['contracts'][contract]['verification'][key]
        proof['candidate_evidence']=evidence
    result['candidate_providers']=dict(bindiff=receipts,scope='candidates_only',semantic_verification=False)
    return result
