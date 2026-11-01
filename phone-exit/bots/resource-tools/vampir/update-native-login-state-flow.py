"""Native dispatch-to-post-state/continuation integration with independent parent proofs."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from importlib.util import module_from_spec,spec_from_file_location

HERE=Path(__file__).resolve().parent
FAMILY='login-state-flow'
ADAPTER='state-flow-v1'


def load(name):
    s=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));v=module_from_spec(s);s.loader.exec_module(v);return v


core=load('portable-native-family')
CHILDREN={'dispatch':('update-native-login-dispatch','login-dispatch'),
          'post_state':('update-native-response','login-post-state'),
          'continuation':('update-native-login-handler','login-continuation')}


def dependency(args,role,sha):
    if role not in CHILDREN:raise ValueError('Unreviewed state-flow dependency')
    name,family=CHILDREN[role];api=load(name).select(family)
    published=api.published_contexts(args.root,load('native-release-registry').read(args.knowledge))
    found=[(path,c) for path,c,_ in published if c['source_sha256']==sha]
    if len(found)!=1:raise ValueError('State-flow needs one proved target publication: '+role)
    path,c=found[0]
    if not c.get('transfer_proof'):raise ValueError('State-flow needs independent target proof')
    value=json.loads((args.root/'knowledge'/api.index/'index.json').read_text('utf-8'))
    rows=[r for r in value['contexts'] if r['context']==core.pointer(path)]
    if len(rows)!=1:raise ValueError('State-flow dependency needs exact published semantic report')
    return api,path,c,rows[0]['check']


def validate_parents(index,args,selected):
    materials={};declarations={}
    for role,(api,path,c,check) in selected.items():
        materials.update(core.lineage_inputs(args,path));materials.update(core.lineage_inputs(args,check['path']))
        declarations[role]=dict(context=core.pointer(path),check=check,source=c['source_sha256'],tools=api.tools())
    key=json.dumps(dict(parents=declarations,materials=materials),sort_keys=True,separators=(',',':'))
    store=args.source_store;memo=getattr(store,'_login_state_flow_parent_validations',None)
    if memo is None:memo={};store._login_state_flow_parent_validations=memo
    stats=getattr(store,'_login_state_flow_parent_metrics',None)
    if stats is None:stats=dict(validated=0,reused=0);store._login_state_flow_parent_metrics=stats
    if key in memo:stats['reused']+=1;return
    for api,path,c,check in selected.values():
        isolated=SimpleNamespace(root=args.root,knowledge=args.knowledge,source_store=store)
        api.validate(index,isolated,c)
    memo[key]=True;stats['validated']+=1


class Adapter(core.Family):
    family=FAMILY
    adapter=ADAPTER
    proofs='native-login-state-flow-proofs'
    index='generated-login-state-flow'
    scope='bounded_native_login_state_flow'
    verifier='verify-login-state-flow-context'
    layout=dict(abi='win64',executed_roots=33,leaves=14,packet_bytes=352,packet_allocation_bytes=344,owner_bytes=80,node_bytes=40,
        framing_minimum=5,continuation_bytes=1024,post_state_service_bytes=768,post_state_actor_bytes=832,post_state_class_bytes=64,native_dispatch=True,native_lookup=False,native_container=True,native_reader=True,native_handler=True,
        native_gate=True,native_input_utf8=True,native_diagnostic_utf8=False,native_packet_constructor=True,native_tls_setter=True,
        native_cleanup=True,native_owner=False,os_tls_provider=False,native_post_state=True,native_continuation=True,real_services=False,session_executed=False)

    def contexts(self,args):
        rows=super().contexts(args);proved={c['source_sha256'] for _,c,_ in rows if c.get('transfer_proof')}
        return [r for r in rows if r[1].get('transfer_proof') or r[1]['source_sha256'] not in proved]

    def baseline_context(self,args):
        rows=self.contexts(args);proved=[r for r in rows if r[1].get('transfer_proof')]
        if not rows:raise ValueError('No reviewed state-flow baseline')
        return max(proved or rows,key=lambda r:(r[2],str(r[0])))[:2]

    def roots(self,c):return load('login-state-flow-rules').roots(c)
    def export_parts(self,c):return [c]
    def export_coverage(self,root,c,native,bindings,image):return load('login-state-flow-rules').export_coverage(root,c,native,bindings,image)
    def validate_report(self,r,c):load('login-state-flow-case-contracts').validate_report(r,c)

    def tools(self):
        return {**{path:sha for name,family in CHILDREN.values() for path,sha in load(name).select(family).tools().items()},
            **load('login-state-flow-rules').tools(),**load('login-state-flow-case-contracts').tools(),
            **{str(HERE/n):core.digest(HERE/n) for n in ('portable-native-family.py','update-native-login-state-flow.py')}}

    def dependencies(self,index,args,sha):
        result={}
        for role in CHILDREN:
            _,path,_,check=dependency(args,role,sha);result[role]=core.pointer(path);result[role+'_check']=check
        return result

    def transfer(self,index,args,baseline,sha):
        self.roots(baseline);selected={role:dependency(args,role,sha) for role in CHILDREN};validate_parents(index,args,selected)
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha);mapping={}
        c,detail=load('login-state-flow-rules').transfer(args.root,native,bindings,before,after,baseline,mapping,
            selected['dispatch'][2],selected['post_state'][2],selected['continuation'][2],dispatch_pointer=core.pointer(selected['dispatch'][1]),post_state_pointer=core.pointer(selected['post_state'][1]),continuation_pointer=core.pointer(selected['continuation'][1]))
        c.update(layout=copy.deepcopy(self.layout),source=str(args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'))
        self.roots(c);return c,dict(details=detail,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())})


def select(family=FAMILY):
    if family!=FAMILY:raise ValueError('Unreviewed state-flow family')
    return Adapter()
