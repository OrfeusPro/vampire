"""Pure metadata and exact whole-export guards; no native replay."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent/'resource-tools/vampir'
s=importlib.util.spec_from_file_location('container_rules',HERE/'login-container-rules.py')
rules=importlib.util.module_from_spec(s);s.loader.exec_module(rules)


def seed(): return json.loads((HERE/'knowledge/native-contexts/login-container-11322.json').read_text('utf-8'))


class ContainerRuleTests(unittest.TestCase):
    def test_reference_declares_five_whole_roots_and_separate_extents(self):
        c=seed();self.assertEqual(len(rules.roots(c)),5)
        self.assertEqual((c['packet_bytes'],c['packet_allocation_bytes'],c['owner_bytes'],c['node_bytes']),(352,344,72,40))
        self.assertNotIn('transfer_proof',c)
        self.assertEqual(c['format'],rules.REFERENCE)
        self.assertEqual(rules.SHAPES['rehash'],(113,429))

    def test_layout_booleans_and_old_owner64_are_rejected(self):
        for field,value in [('owner_bytes',64),('packet_allocation_bytes',352),('node_bytes',True),('verify_whole_exports',1)]:
            c=seed();c[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):rules.roots(c)

    def test_unknown_fields_aliases_and_extra_globals_are_rejected(self):
        for mutation in ('root','leaf','fixture','field','global'):
            c=seed()
            if mutation=='root':c['functions']['rehash']=c['functions']['insert']
            if mutation=='leaf':c['fixtures']['node_allocate']=c['bindings']['id_getter']
            if mutation=='fixture':c['fixtures']['node_allocate']=c['functions']['insert']
            if mutation=='field':c['native_dispatch']=True
            if mutation=='global':c['globals']['unreviewed']='0x140000000'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):rules.roots(c)

    def test_pointer_and_native_id_contracts_are_closed(self):
        for change in ('pointer','id','binding'):
            c=seed()
            if change=='pointer':c['registration_context']['sha256']='short'
            if change=='id':c['leaves']={c['bindings']['id_getter']:'b805000000c3'}
            if change=='binding':c['bindings']['handler']='not-address'
            with self.subTest(change=change),self.assertRaises(ValueError):rules.roots(c)

    def test_short_first_unwind_slice_cannot_replace_complete_rehash(self):
        b=SimpleNamespace(rows=lambda *_:[dict(address=0x140001000,bytes='90'*50)])
        with self.assertRaisesRegex(ValueError,'whole instruction/chained'):rules.whole(None,b,None,0x140001000,'rehash')

    def test_only_direct_call_with_the_declared_offset_is_selected(self):
        rr=[dict(address=100,call=False,direct_target=None),dict(address=119,call=True,direct_target=200)]
        self.assertEqual(rules.direct(rr,19),200)
        for offset in (0,18,20):
            with self.assertRaises(ValueError):rules.direct(rr,offset)

    def _export(self,change=None):
        c=seed();rr={k:[dict(address=int(at,16),bytes='c3')] for k,at in c['functions'].items()}
        functions=[dict(address=c['functions'][k],instructions=[dict(address=hex(r['address']),bytes=r['bytes']) for r in rows],
            decompilation_completed=True,block_coverage_complete=True,direct_flow_coverage_complete=True) for k,rows in rr.items()]
        if change:change(functions)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);p=root/'ghidra/request-exports'/c['source_sha256']/'run-test/details.json';p.parent.mkdir(parents=True)
            raw=json.dumps(dict(new_source_sha256=c['source_sha256'],functions=functions)).encode();p.write_bytes(raw)
            c['exports']={'run-test':hashlib.sha256(raw).hexdigest()}
            module=SimpleNamespace(normalize_function=lambda *_:None)
            with patch.object(rules,'validate_static',return_value=rr),patch.object(rules,'load',return_value=module):
                rules.export_coverage(root,c,None,None,None)

    def test_exact_complete_exports_are_accepted(self):self._export()

    def test_partial_duplicate_missing_or_changed_instruction_exports_fail(self):
        changes=[lambda fs:fs[0].update(block_coverage_complete=False),lambda fs:fs.pop(),
            lambda fs:fs[0]['instructions'].append(dict(fs[0]['instructions'][0])),
            lambda fs:fs[0]['instructions'][0].update(bytes='90')]
        for mutate in changes:
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self._export(mutate)


if __name__=='__main__':unittest.main()
