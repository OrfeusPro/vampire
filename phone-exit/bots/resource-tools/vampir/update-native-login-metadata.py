"""Portable metadata pipeline and its explicit Login SDK integration."""
import copy
import hashlib
import json
from pathlib import Path
from importlib.util import module_from_spec,spec_from_file_location

HERE=Path(__file__).resolve().parent
FAMILIES=('login-metadata','login-prepare-metadata')
ADAPTER='login-metadata-v1'
META={'schema','source','source_sha256','family','layout','exports','transfer_proof','release_id','verify_whole_exports'}


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    value=module_from_spec(spec);spec.loader.exec_module(value);return value


core=load('portable-native-family')
def semantic(c):
    if isinstance(c,dict):return {k:semantic(v) for k,v in c.items() if k not in META}
    if isinstance(c,list):return [semantic(v) for v in c]
    return c
def sdk_view(c):return {k:copy.deepcopy(v) for k,v in c.items() if k not in ('native_metadata','function_budget','family','layout','transfer_proof','release_id')}
def normalized_metadata(c):
    if c.get('verify_whole_exports',True) is not True:raise ValueError('Embedded metadata export scope differs')
    return dict(c,verify_whole_exports=True)


def sdk_at(args,sha):
    api=load('update-native-login-sdk');registry=load('native-release-registry').read(args.knowledge)
    found=core.historical(args.knowledge,'login-prepare-sdk',registry)+api.published_contexts(args.root,registry)
    found=[(p,c) for p,c,_ in found if c['source_sha256']==sha]
    if len(found)!=1:raise ValueError('Missing or ambiguous source-specific Login SDK')
    return found[0]


def sdk_receipt(args,sha):
    api=load('update-native-login-sdk');registry=load('native-release-registry').read(args.knowledge)
    api.published_contexts(args.root,registry)
    value=json.loads((args.root/'knowledge/generated-login-sdk/index.json').read_text('utf-8'))
    found=[r for r in value['contexts'] if core.checked(args.root,r['context'],'generated-native-contexts')['source_sha256']==sha]
    if len(found)!=1:raise ValueError('Target Login SDK needs a published semantic proof')
    return found[0]


def scoped_roots(family,c):
    rule=load('login-metadata-transfer-rules')
    if family==FAMILIES[0]:
        if 'function_budget' in c or 'native_sdk' in c or 'native_metadata' in c:raise ValueError('Standalone metadata optional native scope differs')
        return rule.roots(c)
    if family!=FAMILIES[1] or c.get('verify_whole_exports') is not True or 'function_budget' in c:
        raise ValueError('Login metadata integration scope/export budget differs')
    sdk=load('update-native-login-sdk');view=sdk_view(c);result=sdk.roots(view)
    metadata=normalized_metadata(c['native_metadata']);native=rule.roots(metadata)
    leaves={int(at,16) for at in c['native_sdk']['leaves']}
    if len(result)!=5 or len(native)!=6 or result&native or (result|native)&leaves or len(leaves)!=6:
        raise ValueError('Login metadata roots or leaves alias')
    source=c['source_sha256'];path=Path(c['source']).resolve()
    if metadata['source_sha256']!=source or Path(metadata['source']).resolve()!=path or metadata['helpers']!=c['helpers']:
        raise ValueError('Login metadata nested source/memcpy differs')
    if (c['fixtures']['sdk_aux_text']!=metadata['functions']['collector']
            or c['native_sdk']['metadata']['collector']!=metadata['functions']['collector']
            or c['native_sdk']['metadata']['consumer']!=metadata['functions']['selector']
            or c['native_sdk']['globals']['manager']!=metadata['globals']['optional_manager']):
        raise ValueError('Login metadata caller/selector/manager linkage differs')
    if [r['key'] for r in c['native_sdk']['metadata']['fields']]!=metadata['collector_order']:
        raise ValueError('Login metadata ordered collector projection differs')
    outer={name:int(at,16) for name,at in c['fixtures'].items() if name not in sdk.NATIVE_NAMES and name!='sdk_aux_text'}
    inner={name:int(at,16) for name,at in c['native_sdk']['fixtures'].items()}
    hooks={name:int(at,16) for name,at in metadata['fixtures'].items()}
    executable=result|native|leaves
    if (set(outer.values())|set(inner.values())|set(hooks.values())|{int(c['helpers']['memcpy'],16)})&executable:
        raise ValueError('Login metadata fixture shadows executed root/leaf')
    allowed_outer={('copy_string','copy_string'),('wide_string','wide_string'),('ascii_string','ascii_string'),('free','free'),('format_number','format')}
    allowed_inner={('main_store','optional_store'),('cache_resolve','optional_resolve')}
    for group,allowed in ((outer,allowed_outer),(inner,allowed_inner)):
        actual={(a,b) for a,at in group.items() for b,bt in hooks.items() if at==bt}
        if actual!=allowed:raise ValueError('Login metadata shared hook partition differs')
    if len(hooks)!=len(set(hooks.values())):raise ValueError('Login metadata fixture roles alias')
    return result|native


def seed(index,args,baseline_sha,sha):
    api=load('update-native-login-sdk');old_path,old=sdk_at(args,baseline_sha);target_path,target=sdk_at(args,sha)
    publication=sdk_receipt(args,sha)
    old_memo=getattr(args,'_login_metadata_memo',None)
    if old_memo is None or old_memo['store'] is not args.source_store:
        old_memo=dict(store=args.source_store,values={});args._login_metadata_memo=old_memo
    lineage={**core.lineage_inputs(args,old_path),**core.lineage_inputs(args,target_path)}
    key=(json.dumps(lineage,sort_keys=True),json.dumps(api.tools(),sort_keys=True),publication['check']['sha256'])
    if key not in old_memo['values']:
        if old.get('transfer_proof'):api.validate(index,args,old)
        api.validate(index,args,target)
        proof=core.checked(args.root,target['transfer_proof'],'native-login-sdk-proofs')
        base=core.checked(args.root,proof['base_login'],'generated-native-contexts')
        base_proof=core.checked(args.root,base['transfer_proof'],'native-login-prepare-proofs')
        archive=core.checked(args.root,base_proof['archive'],'generated-native-contexts')
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        before=args.source_store.image(native,baseline_sha);after=args.source_store.image(native,sha)
        api.export_coverage(args.root,old,native,bindings,before)
        current,relation=api.transfer(native,bindings,before,after,old,base,archive)
        if api.plain(current)!=api.plain(target):raise ValueError('Metadata SDK baseline differs from independent target proof')
        old_memo['values'][key]=(target,{int(a,16):int(b,16) for a,b in relation['mapping'].items()},
            dict(baseline_sdk=core.pointer(old_path),target_sdk=core.pointer(target_path),target_sdk_check=publication['check']))
    return copy.deepcopy(old_memo['values'][key])


class Adapter(core.Family):
    def __init__(self,family):
        if family not in FAMILIES:raise ValueError('Unreviewed Login metadata family')
        self.family=family;self.adapter=ADAPTER;self.proofs='native-login-metadata-proofs'
        self.scope='bounded_native_'+family.replace('-','_');self.index='generated-login-metadata/'+family
        integrated=family==FAMILIES[1]
        self.layout=dict(abi='win64',executed_roots=11 if integrated else 6,returning_leaves=6 if integrated else 0,
            userinfo_bytes=592,packet_bytes=320 if integrated else None,max_allocation=8192,metadata_text_units=4096,
            packet_text_units=1024 if integrated else None,real_sdk_backend=False)
        self.verifier=load('login-metadata-case-contracts').verifier(family)

    def roots(self,c):return scoped_roots(self.family,c)

    def tools(self):
        return {**load('update-native-login-sdk').tools(),**load('login-metadata-transfer-rules').tools(),
            **load('login-metadata-case-contracts').tools(),
            **{str(HERE/n):core.digest(HERE/n) for n in ('portable-native-family.py','update-native-login-metadata.py')}}

    def export_parts(self,c):
        result=[c]
        if self.family==FAMILIES[1]:
            result.extend((dict(c['native_sdk'],source_sha256=c['source_sha256'],source=c['source']),c['native_metadata']))
        return result

    def dependencies(self,index,args,sha):
        p,c=sdk_at(args,sha);row=sdk_receipt(args,sha)
        result=dict(sdk=core.pointer(p),sdk_check=row['check'])
        if self.family==FAMILIES[1]:
            adapter=Adapter(FAMILIES[0]);path,metadata=adapter.at(args,sha)
            if not metadata.get('transfer_proof'):raise ValueError('Target metadata needs a portable proof')
            registry=load('native-release-registry').read(args.knowledge);adapter.published_contexts(args.root,registry)
            data=json.loads((args.root/'knowledge'/adapter.index/'index.json').read_text('utf-8'))
            found=[r for r in data['contexts'] if r['context']==core.pointer(path)]
            if len(found)!=1:raise ValueError('Target metadata needs a published semantic proof')
            result.update(metadata=core.pointer(path),metadata_check=found[0]['check'])
        return result

    def input_materials(self,args,path,baseline,sha):
        result=core.lineage_inputs(args,path);p,_=sdk_at(args,baseline['source_sha256']);result.update(core.lineage_inputs(args,p))
        if self.family==FAMILIES[1]:
            p,_=Adapter(FAMILIES[0]).at(args,baseline['source_sha256']);result.update(core.lineage_inputs(args,p))
        return result

    def validate_report(self,r,c):
        load('login-metadata-case-contracts').validate_report(self.family,r)
        if self.family==FAMILIES[1] and r['metadata_fields']!=c['native_sdk']['metadata']['fields']:
            raise ValueError('Login metadata report literal/call-site provenance differs')

    def transfer(self,index,args,baseline,sha):
        self.roots(baseline);sdk,mapping,seed_proof=seed(index,args,baseline['source_sha256'],sha)
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha)
        rule=load('login-metadata-transfer-rules')
        if self.family==FAMILIES[0]:
            result,detail=rule.transfer(native,bindings,before,after,baseline,mapping)
        else:
            old_sdk_path,old_sdk=sdk_at(args,baseline['source_sha256'])
            if semantic(sdk_view(baseline))!=semantic(old_sdk):raise ValueError('Login metadata baseline SDK integration differs')
            standalone=Adapter(FAMILIES[0]);p,old=standalone.at(args,baseline['source_sha256'])
            if semantic(normalized_metadata(baseline['native_metadata']))!=semantic(old):
                raise ValueError('Login metadata baseline standalone integration differs')
            target_path,target=standalone.at(args,sha);standalone.validate(index,args,target)
            moved,detail=rule.transfer(native,bindings,before,after,old,mapping)
            if semantic(moved)!=semantic(target):raise ValueError('Login metadata integration differs from standalone target proof')
            result=copy.deepcopy(sdk);result['native_metadata']={k:copy.deepcopy(v) for k,v in target.items() if k not in ('family','layout','transfer_proof','release_id')}
            detail['baseline_metadata']=core.pointer(p);detail['target_metadata']=core.pointer(target_path)
        for key in ('exports','family','layout','transfer_proof','release_id'):result.pop(key,None)
        result.update(schema=1,family=self.family,source_sha256=sha,source=str(args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'),
            layout=self.layout,verify_whole_exports=True)
        self.roots(result)
        return result,dict(seed=seed_proof,details=detail,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())})


def select(family):return Adapter(family)
