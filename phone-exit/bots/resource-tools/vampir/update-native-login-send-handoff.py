"""Native Login preparation and bounded sender handoff, with independent schema evidence."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
from importlib.util import module_from_spec,spec_from_file_location

HERE=Path(__file__).resolve().parent
FAMILY='login-send-handoff'
ADAPTER='send-handoff-v1'


def load(name):
    s=spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'));v=module_from_spec(s);s.loader.exec_module(v);return v


core=load('portable-native-family')
CHILDREN={'prepare':('update-native-login-metadata','login-prepare-metadata'),
          'wire':('update-native-archive-wire',None)}


def dependency(args,role,sha):
    if role not in CHILDREN:raise ValueError('Unreviewed handoff dependency')
    name,family=CHILDREN[role];module=load(name);api=module.select(family) if family else module
    published=api.published_contexts(args.root,load('native-release-registry').read(args.knowledge))
    found=[(path,c) for path,c,_ in published if c['source_sha256']==sha]
    if len(found)!=1:raise ValueError('Handoff needs one proved target publication: '+role)
    path,c=found[0]
    if not c.get('transfer_proof'):raise ValueError('Handoff needs independent target proof')
    value=json.loads((args.root/'knowledge'/(api.index if family else api.INDEX)/'index.json').read_text('utf-8'))
    rows=[r for r in value['contexts'] if r['context']==core.pointer(path)]
    if len(rows)!=1:raise ValueError('Handoff dependency needs exact published semantic report')
    return api,path,c,rows[0]['check']


def validate_parents(index,args,selected):
    materials={};declarations={}
    for role,(api,path,c,check) in selected.items():
        materials.update(core.lineage_inputs(args,path));materials.update(core.lineage_inputs(args,check['path']))
        declarations[role]=dict(context=core.pointer(path),check=check,source=c['source_sha256'],tools=api.tools())
    key=json.dumps(dict(parents=declarations,materials=materials),sort_keys=True,separators=(',',':'))
    store=args.source_store;memo=getattr(store,'_login_send_handoff_parent_validations',None)
    if memo is None:memo={};store._login_send_handoff_parent_validations=memo
    stats=getattr(store,'_login_send_handoff_parent_metrics',None)
    if stats is None:stats=dict(validated=0,reused=0);store._login_send_handoff_parent_metrics=stats
    if key in memo:stats['reused']+=1;return
    for api,path,c,check in selected.values():
        isolated=SimpleNamespace(root=args.root,knowledge=args.knowledge,source_store=store)
        api.validate(index,isolated,c)
    memo[key]=True;stats['validated']+=1


class Adapter(core.Family):
    family=FAMILY
    adapter=ADAPTER
    proofs='native-login-send-handoff-proofs'
    index='generated-login-send-handoff'
    scope='bounded_native_login_send_handoff'
    verifier='verify-login-send-handoff-context'
    layout=dict(abi='win64',executed_roots=12,leaves=7,packet_bytes=320,session_bytes=160,native_prepare=True,
        native_sdk=True,native_metadata=True,native_sender=True,native_service_getter=True,
        synthetic_service_vtable=True,native_wire=False,native_pending_insert=False,native_delegate=False,
        native_service_backend=False,real_services=False,session_executed=False)

    def contexts(self,args):
        rows=super().contexts(args);proved={c['source_sha256'] for _,c,_ in rows if c.get('transfer_proof')}
        return [r for r in rows if r[1].get('transfer_proof') or r[1]['source_sha256'] not in proved]

    def baseline_context(self,args):
        rows=self.contexts(args);proved=[r for r in rows if r[1].get('transfer_proof')]
        if not rows:raise ValueError('No reviewed handoff baseline')
        return max(proved or rows,key=lambda r:(r[2],str(r[0])))[:2]

    def roots(self,c):return load('login-send-handoff-rules').roots(c)
    def export_parts(self,c):return [c]
    def export_coverage(self,root,c,native,bindings,image):return load('login-send-handoff-rules').export_coverage(root,c,native,bindings,image)
    def validate_report(self,r,c):
        root=Path(c['source']).parents[2];proof=core.checked(root,c['transfer_proof'],self.proofs)
        parent=core.checked(root,proof['dependencies']['prepare_check'],'native-adapter-checks')
        load('login-send-handoff-case-contracts').validate_report(r,c,parent)

    def tools(self):
        return {**{path:sha for name,family in CHILDREN.values() for path,sha in (load(name).select(family) if family else load(name)).tools().items()},
            **load('login-send-handoff-rules').tools(),**load('login-send-handoff-case-contracts').tools(),
            **{str(HERE/n):core.digest(HERE/n) for n in ('portable-native-family.py','update-native-login-send-handoff.py')}}

    def dependencies(self,index,args,sha):
        result={}
        for role in CHILDREN:
            _,path,_,check=dependency(args,role,sha);result[role]=core.pointer(path);result[role+'_check']=check
        return result

    def transfer(self,index,args,baseline,sha):
        self.roots(baseline);selected={role:dependency(args,role,sha) for role in CHILDREN};validate_parents(index,args,selected)
        native,bindings=load('build-native-entry-code'),load('update-bindings')
        before=args.source_store.image(native,baseline['source_sha256']);after=args.source_store.image(native,sha);mapping={}
        c,detail=load('login-send-handoff-rules').transfer(args.root,native,bindings,before,after,baseline,mapping,
            selected['prepare'][2],selected['wire'][2],prepare_pointer=core.pointer(selected['prepare'][1]),wire_pointer=core.pointer(selected['wire'][1]))
        c.update(layout=copy.deepcopy(self.layout),source=str(args.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'))
        self.roots(c);return c,dict(details=detail,mapping={hex(a):hex(b) for a,b in sorted(mapping.items())})


def select(family=FAMILY):
    if family!=FAMILY:raise ValueError('Unreviewed handoff family')
    return Adapter()
