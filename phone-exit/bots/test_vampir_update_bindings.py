import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest

from test_vampir_update_contracts import load
import test_vampir_update_targets as fixture


class BindingTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.index=load('knowledge-index');self.tool=load('update-bindings')

    def image(self, begin, *, callee_value=7, ambiguous=False):
        raw=bytearray(fixture.UpdateTargetsTests().image())
        raw[0x200:0x300]=b'\xcc'*256
        main=begin
        raw[0x200+begin-0x1000:0x200+begin-0x1000+16]=b'\x90'*16
        off=0x200+begin-0x1000+16
        raw[off:off+6]=b'\xe8'+struct.pack('<i',0x1040-(begin+16)-5)+b'\xc3'
        raw[off+6:off+16]=b'\x90'*10
        raw[0x240:0x250]=b'\xb8'+struct.pack('<I',callee_value)+b'\xc3'+b'\x90'*10
        entries=[(begin,begin+32),(0x1040,0x1050)]
        if ambiguous:
            raw[0x260:0x280]=raw[0x200+begin-0x1000:0x220+begin-0x1000]
            entries.append((0x1060,0x1080))
        struct.pack_into('<II',raw,0x98+112+3*8,0x2050,len(entries)*12)
        for n,(a,b) in enumerate(sorted(entries)):struct.pack_into('<III',raw,0x350+n*12,a,b,0x2090)
        raw[0x390:0x394]=b'\x01\0\0\0'
        data=bytes(raw);sha=hashlib.sha256(data).hexdigest()
        path=self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        path.parent.mkdir(parents=True);path.write_bytes(data)
        return sha

    def model(self, old):
        return dict(contracts=[dict(id='fixture',bindings={old:dict(main='0x140001000',helper='0x140001040')},
            recipes=[dict(key='main',method='prefix',baseline_sha256=old,baseline_address='0x140001000',prefix_bytes=16,calls={'16':'helper'}),
                dict(key='helper',method='prefix',baseline_sha256=old,baseline_address='0x140001040',prefix_bytes=16)])])

    def test_moved_function_requires_closed_callee_match(self):
        old=self.image(0x1000);new=self.image(0x1020)
        result=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),self.model(old),new,[])
        c=result['contracts']['fixture']
        self.assertEqual(c['bindings']['main'],'0x140001020')
        self.assertEqual(c['queue'],[])
        self.assertEqual(set(c['closed_shapes']),{'main','helper'})

    def test_changed_callee_rejects_unchanged_outer_shape(self):
        old=self.image(0x1000);new=self.image(0x1020,callee_value=8)
        result=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),self.model(old),new,[])
        self.assertTrue(result['contracts']['fixture']['queue'])
        self.assertNotIn('main',result['contracts']['fixture']['closed_shapes'])

    def test_ambiguous_prefix_is_not_exported_as_confirmed(self):
        old=self.image(0x1000);new=self.image(0x1020,ambiguous=True)
        result=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),self.model(old),new,[])
        c=result['contracts']['fixture']
        self.assertNotIn('main',c['bindings']);self.assertTrue(c['queue'])

    def test_explicit_direct_call_and_constructor_table_slot(self):
        sha=self.image(0x1000)
        p=self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        raw=bytearray(p.read_bytes())
        raw[0x200:0x207]=b'\x48\x8d\x05'+struct.pack('<i',0x2000-0x1000-7)
        struct.pack_into('<Q',raw,0x300,0x140001040)
        new=hashlib.sha256(raw).hexdigest()
        target=self.root/'client-code-snapshots'/new/p.name;target.parent.mkdir(parents=True);target.write_bytes(raw)
        model=dict(contracts=[dict(id='fixture',bindings={new:dict(main='0x140001000')},recipes=[
            dict(key='main',method='reviewed'),dict(key='call-target',method='direct_call',**{'from':'main'},offset=16),
            dict(key='slot-target',method='vtable',**{'from':'main'},rip_offset=0,slot=0)])])
        result=self.tool.resolve(self.index.api(),SimpleNamespace(root=self.root),model,new,[])['contracts']['fixture']
        self.assertEqual(result['bindings']['call-target'],'0x140001040')
        self.assertEqual(result['bindings']['slot-target'],'0x140001040')
        self.assertEqual(result['queue'],[])


if __name__ == '__main__':unittest.main()
