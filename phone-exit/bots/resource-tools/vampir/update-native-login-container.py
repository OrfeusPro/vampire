"""Source-bound insert/name integration without changing the frozen helper proof."""
import copy
import json
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
FAMILY='login-container'
ADAPTER='container-v1'


def load(name):
    spec=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    value=module_from_spec(spec);spec.loader.exec_module(value);return value


core=load('portable-native-family')


def dependency(args,sha):
    api=load('update-native-login-registration').select('login-registration');path,c=api.at(args,sha)
    if not c.get('transfer_proof'): raise ValueError('Container needs a target registration proof')
    api.published_contexts(args.root,load('native-release-registry').read(args.knowledge))
    data=json.loads((args.root/'knowledge'/api.index/'index.json').read_text('utf-8'))
    rows=[row for row in data['contexts'] if row['context']==core.pointer(path)]
    if len(rows)!=1: raise ValueError('Container needs the exact published registration report')
    return api,path,c,rows[0]['check']


def validate_parent(index,args,selected):
    """Memoize only inside one frozen SourceStore, with full ordered lineage."""
    api,path,c,check=selected
    materials=core.lineage_inputs(args,path)
    materials.update(core.lineage_inputs(args,check['path']))
    key=json.dumps(dict(context=core.pointer(path),check=check,source=c['source_sha256'],tools=api.tools(),materials=materials),sort_keys=True,separators=(',',':'))
    store=args.source_store
    memo=getattr(store,'_login_container_parent_validations',None)
    if memo is None: memo={};store._login_container_parent_validations=memo
    stats=getattr(store,'_login_container_parent_metrics',None)
    if stats is None: stats=dict(validated=0,reused=0);store._login_container_parent_metrics=stats
    if key in memo:
        stats['reused']+=1;return
    # Frozen input recipes have an unordered mapping memo. Do not inherit or
    # mutate another family's directional memo while validating this parent.
    isolated=SimpleNamespace(root=args.root,knowledge=args.knowledge,source_store=store)
    api.validate(index,isolated,c)
    memo[key]=True;stats['validated']+=1


class Adapter(core.Family):
    family=FAMILY
    adapter=ADAPTER
    proofs='native-login-container-proofs'
    index='generated-login-container'
    scope='bounded_native_login_container_and_name'
    verifier='verify-login-container-context'
    layout=dict(abi='win64',executed_roots=5,packet_bytes=352,packet_allocation_bytes=344,owner_bytes=72,node_bytes=40,
        native_registration=True,native_insert=True,native_rehash=True,native_name=True,native_string_constructor=True,
        native_owner=False,native_packet_constructor=False,native_handler=False,native_dispatch=False,real_services=False,session_executed=False)

    def contexts(self,args):
        rows=super().contexts(args);proved={c['source_sha256'] for _,c,_ in rows if c.get('transfer_proof')}
        return [row for row in rows if row[1].get('transfer_proof') or row[1]['source_sha256'] not in proved]

    def baseline_context(self,args):
        rows=self.contexts(args)
        if not rows: raise ValueError('No reviewed container baseline')
        proved=[row for row in rows if row[1].get('transfer_proof')]
        return max(proved or rows,key=lambda row:(row[2],str(row[0])))[:2]

    def roots(self,c): return load('login-container-rules').roots(c)

    def tools(self):
        return {**load('update-native-login-registration').select().tools(),**load('login-container-rules').tools(),
            **load('login-container-case-contracts').tools(),**{str(HERE/name):core.digest(HERE/name) for name in ('portable-native-family.py','update-native-login-container.py')}}

    def dependencies(self,index,args,sha):
        _,path,_,check=dependency(args,sha)
        return dict(registration=core.pointer(path),registration_check=check)

    def export_parts(self,c): return [c]
    def export_coverage(self,root,c,native,bindings,image): return load('login-container-rules').export_coverage(root,c,native,bindings,image)
    def validate_report(self,r,c): load('login-container-case-contracts').validate_report(r,c)

    def transfer(self,index,args,baseline,sha):
        self.roots(baseline);selected=dependency(args,sha);validate_parent(index,args,selected)
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha);mapping={}
        current,detail=load('login-container-rules').transfer(args.root,native,bindings,before,after,baseline,mapping,selected[2],registration_pointer=core.pointer(selected[1]))
        current.update(source=str(args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'),layout=copy.deepcopy(self.layout))
        self.roots(current)
        return current,dict(details=detail,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())})


def select(family=FAMILY):
    if family!=FAMILY: raise ValueError('Unreviewed container family')
    return Adapter()
