"""Whole-function relocation and transitive dependency admission, no game IO."""
import copy
import hashlib
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from test_vampir_update_bindings import BindingTests
from test_vampir_update_contracts import load

class ClosedShapeTests(unittest.TestCase):
    setUp=BindingTests.setUp
    image=BindingTests.image
    model=BindingTests.model
    def closed_model(self,old):
        model=self.model(old)
        for recipe in model['contracts'][0]['recipes']:
            recipe['method']='closed_shape';recipe['search_window']=0x100
        return model

    def test_whole_function_search_survives_relocated_call_inside_prefix(self):
        old=self.image(0x1000);new=self.image(0x1020)
        model=self.closed_model(old)
        # The prefix has no role in the new method: the CALL bytes now differ.
        result=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),model,new,[])['contracts']['fixture']
        self.assertEqual(result['queue'],[])
        self.assertEqual(result['verification']['main']['state'],'moved_verified')
        self.assertEqual(result['verification']['helper']['state'],'unchanged')
        self.assertFalse(result['verification']['main']['runtime_activated'])

    def test_ambiguous_whole_functions_are_never_selected_by_proximity(self):
        old=self.image(0x1000);new=self.image(0x1020,ambiguous=True)
        # Regenerate duplicate call displacement, preserving its actual callee.
        p=self.root/'client-code-snapshots'/new/'ProjectRED-Win64-Shipping.exe'
        raw=bytearray(p.read_bytes());struct.pack_into('<i',raw,0x271,0x1040-0x1070-5)
        new=self.save(raw)
        got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),self.closed_model(old),new,[])['contracts']['fixture']
        self.assertEqual(len(got['search_candidates']['main']),2)
        self.assertNotIn('main',got['closed_shapes'])
        self.assertEqual(got['verification']['main']['state'],'requires_review')

    def save(self,raw):
        raw=bytes(raw);sha=hashlib.sha256(raw).hexdigest()
        p=self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);return sha

    def chain(self,changed=False):
        from test_vampir_update_targets import UpdateTargetsTests
        raw=bytearray(UpdateTargetsTests().image());raw[0x200:0x300]=b'\xcc'*256
        # a -> b -> c, all fixed-size unique instruction shapes.
        for address,prefix,target in ((0x1000,0x51,0x1040),(0x1040,0x52,0x1080)):
            off=0x200+address-0x1000
            raw[off:off+16]=bytes([prefix])+b'\x90'*15
            raw[off+16:off+22]=b'\xe8'+struct.pack('<i',target-address-21)+b'\xc3'
            raw[off+22:off+32]=b'\x90'*10
        raw[0x280:0x290]=b'\xb8'+struct.pack('<I',8 if changed else 7)+b'\xc3'+b'\x90'*10
        struct.pack_into('<II',raw,0x98+112+3*8,0x2050,36)
        for n,(a,b) in enumerate(((0x1000,0x1020),(0x1040,0x1060),(0x1080,0x1090))):
            struct.pack_into('<III',raw,0x350+n*12,a,b,0x2090)
        raw[0x390:0x394]=b'\x01\0\0\0'
        return self.save(raw)

    def chain_model(self,old,order):
        recipes={key:dict(key=key,method='prefix',baseline_sha256=old,
            baseline_address=hex(0x140001000+offset),prefix_bytes=16,
            calls={'16':callee} if callee else {}) for key,offset,callee in
            (('a',0,'b'),('b',0x40,'c'),('c',0x80,None))}
        return dict(contracts=[dict(id='chain',bindings={old:{k:r['baseline_address'] for k,r in recipes.items()}},recipes=[recipes[k] for k in order])])

    def test_transitive_callee_failure_prunes_all_ancestors_in_every_order(self):
        old=self.chain();new=self.chain(changed=True)
        for order in (('a','b','c'),('c','b','a'),('b','a','c')):
            with self.subTest(order=order):
                got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),self.chain_model(old,order),new,[])['contracts']['chain']
                self.assertEqual(got['closed_shapes'],{})
                self.assertTrue(got['queue'])

    def test_whole_shape_changed_callee_prunes_outer_candidate(self):
        old=self.chain();new=self.chain(changed=True)
        model=self.chain_model(old,('a','b','c'))
        for r in model['contracts'][0]['recipes']:r.update(method='closed_shape',search_window=0x100)
        got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),model,new,[])['contracts']['chain']
        self.assertEqual(got['closed_shapes'],{})
        self.assertEqual(got['search_candidates'],{'a':[],'b':[],'c':[]})

    def test_search_budget_and_undeclared_callee_are_fail_closed(self):
        old=self.image(0x1000);new=self.image(0x1020)
        for window in (None,True,-1,0x100001):
            m=self.closed_model(old);m['contracts'][0]['recipes'][0]['search_window']=window
            got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),m,new,[])['contracts']['fixture']
            self.assertNotIn('main',got['closed_shapes'])
        m=self.closed_model(old);m['contracts'][0]['recipes'][0]['calls']={}
        got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),m,new,[])['contracts']['fixture']
        self.assertNotIn('main',got['closed_shapes'])

    def test_rip_data_is_verified_and_not_merely_relocation_normalized(self):
        old=self.image(0x1000)
        def variant(begin,text):
            p=self.root/'client-code-snapshots'/old/'ProjectRED-Win64-Shipping.exe'
            raw=bytearray(p.read_bytes());raw[0x200:0x300]=b'\xcc'*256
            off=0x200+begin-0x1000
            raw[off:off+16]=b'\x48\x8d\x05'+struct.pack('<i',0x2000-begin-7)+b'\xc3'+b'\x90'*8
            raw[0x300:0x30a]=text
            struct.pack_into('<II',raw,0x98+112+3*8,0x2050,12)
            struct.pack_into('<III',raw,0x350,begin,begin+16,0x2090)
            return self.save(raw)
        before=variant(0x1000,b'I_fixture\0');after=variant(0x1020,b'I_fixture\0')
        r=dict(key='main',method='closed_shape',baseline_sha256=before,baseline_address='0x140001000',search_window=0x100,
            data={'0':dict(size=10,sha256=hashlib.sha256(b'I_fixture\0').hexdigest())})
        m=dict(contracts=[dict(id='data',bindings={before:dict(main='0x140001000')},recipes=[r])])
        got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),m,after,[])['contracts']['data']
        self.assertEqual(set(got['closed_shapes']),{'main'})
        changed=variant(0x1020,b'X_fixture\0')
        got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),m,changed,[])['contracts']['data']
        self.assertEqual(got['closed_shapes'],{})

    def test_mutually_closed_cycle_is_verified_without_order_assumption(self):
        old=self.chain();p=self.root/'client-code-snapshots'/old/'ProjectRED-Win64-Shipping.exe'
        raw=bytearray(p.read_bytes())
        # Replace c with a direct call back to a; update its explicit boundary.
        raw[0x280:0x290]=b'\xe8'+struct.pack('<i',0x1000-0x1080-5)+b'\xc3'+b'\x90'*10
        before=self.save(raw)
        raw[0x301]=ord('Z');after=self.save(raw)
        model=self.chain_model(before,('a','b','c'))
        for r in model['contracts'][0]['recipes']:
            r.update(method='closed_shape',search_window=0x100)
            if r['key']=='c':r['calls']={'0':'a'}
        got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),model,after,[])['contracts']['chain']
        self.assertEqual(got['queue'],[])
        self.assertEqual(set(got['closed_shapes']),{'a','b','c'})

    def test_indirect_calls_and_external_tail_branches_are_not_normalized(self):
        old=self.image(0x1000)
        p=self.root/'client-code-snapshots'/old/'ProjectRED-Win64-Shipping.exe'
        for code in (b'\xff\xd0\xc3',b'\xe9'+struct.pack('<i',0x1040-0x1000-5)):
            raw=bytearray(p.read_bytes());raw[0x200:0x220]=code+b'\x90'*(32-len(code))
            before=self.save(raw);raw[0x301]=ord('Z');after=self.save(raw)
            model=dict(contracts=[dict(id='branch',bindings={before:dict(main='0x140001000')},recipes=[dict(
                key='main',method='closed_shape',baseline_sha256=before,baseline_address='0x140001000',search_window=0x100)])])
            got=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),model,after,[])['contracts']['branch']
            self.assertEqual(got['closed_shapes'],{})
            self.assertTrue(got['queue'])

class ClosedShapeSchemaTests(unittest.TestCase):
    def test_schema_rejects_missing_or_unbounded_search_scope(self):
        index=load('knowledge-index');tool=load('update-contracts')
        root=Path(__file__).parent/'resource-tools/vampir/knowledge'
        original=index.read_json;data=original(root/'update-contracts.json')
        for window in (None,True,-1,0x100001,0):
            value=copy.deepcopy(data);value['contracts'][0]['recipes'][0]=dict(key='constructor',method='closed_shape',
                baseline_sha256='a'*64,baseline_address='0x140001000',search_window=window)
            value['contracts'][0]['bindings']['a'*64]={'constructor':'0x140001000'}
            api=index.api();api.read_json=lambda p,value=value:value if p.name=='update-contracts.json' else original(p)
            if window==0 and type(window) is int:tool.load(api,root)
            else:
                with self.assertRaises(ValueError):tool.load(api,root)

def load_tests(loader,tests,pattern):
    return unittest.TestSuite(loader.loadTestsFromTestCase(case) for case in (ClosedShapeTests,ClosedShapeSchemaTests))

if __name__=='__main__':unittest.main()
