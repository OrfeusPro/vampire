"""Ready BinDiff matches must pass the same complete closure checks."""
import json
from contextlib import closing
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest

import test_vampir_update_bindings as fixture


class ReadyDiffTests(unittest.TestCase):
    setUp=fixture.BindingTests.setUp
    image=fixture.BindingTests.image
    model=fixture.BindingTests.model

    def pair(self,old,new,targets=('0x140001020',)):
        root=self.root.resolve();folder=root/'binary-diff/comparisons/pair';folder.mkdir(parents=True)
        db=folder/'pair.BinDiff'
        with closing(sqlite3.connect(db)) as conn:
            conn.execute('CREATE TABLE function(address1 INTEGER,address2 INTEGER,similarity REAL,confidence REAL)')
            for at in targets:conn.execute('INSERT INTO function VALUES(?,?,1,1)',(0x140001000,int(at,16)))
            conn.commit()
        refs={}
        for side,sha in (('primary',old),('secondary',new)):
            out=root/'binary-diff/exports'/sha;out.mkdir(parents=True)
            data=out/'client.BinExport';data.write_bytes(b'opaque export')
            receipt=out/'manifest.json'
            receipt.write_text(json.dumps(dict(source=str(root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'),
                source_sha256=sha,export=str(data),export_sha256=self.index.digest(data))))
            refs[side]=str(receipt);refs[side+'_sha256']=self.index.digest(receipt)
        path=folder/'manifest.json';path.write_text(json.dumps(dict(**refs,baseline_sha256=old,
            source_sha256=new,database=str(db),database_sha256=self.index.digest(db))))
        return dict(path=str(path),sha256=self.index.digest(path))

    def closed_model(self,old):
        model=self.model(old)
        for r in model['contracts'][0]['recipes']:r.update(method='closed_shape',search_window=0)
        return model

    def run_diff(self,model,new,receipts):
        tool=self.index.extension('binary-diff-candidates')
        return tool.resolve(self.index.api(),SimpleNamespace(root=self.root),model,new,[],receipts)['contracts']['fixture']

    def test_ready_pair_can_locate_a_moved_root_outside_window(self):
        old=self.image(0x1000);new=self.image(0x1020)
        pair=self.pair(old,new)
        result=self.run_diff(self.closed_model(old),new,[pair])
        self.assertEqual(set(result['closed_shapes']),{'main','helper'})
        self.assertEqual(result['verification']['main']['state'],'moved_verified')
        self.assertIn('candidate_evidence',result['verification']['main'])

    def test_perfect_score_does_not_accept_changed_callee(self):
        old=self.image(0x1000);new=self.image(0x1020,callee_value=8)
        result=self.run_diff(self.closed_model(old),new,[self.pair(old,new)])
        self.assertNotIn('main',result['closed_shapes']);self.assertTrue(result['queue'])

    def test_ambiguous_pair_and_changed_database_do_not_promote(self):
        old=self.image(0x1000);new=self.image(0x1020,ambiguous=True)
        pair=self.pair(old,new,('0x140001020','0x140001060'))
        result=self.run_diff(self.closed_model(old),new,[pair])
        self.assertNotIn('main',result['closed_shapes'])
        db=Path(json.loads(Path(pair['path']).read_text())['database'])
        with db.open('ab') as stream:stream.write(b'changed')
        with self.assertRaisesRegex(ValueError,'Comparison changed'):
            self.run_diff(self.closed_model(old),new,[pair])

    def test_missing_pairs_use_existing_resolver_without_extra_tools(self):
        old=self.image(0x1000);new=self.image(0x1020)
        self.assertTrue(self.run_diff(self.closed_model(old),new,[])['queue'])

    def test_database_bytes_participate_in_the_provider_cache_key(self):
        old=self.image(0x1000);new=self.image(0x1020);pair=self.pair(old,new)
        tool=self.index.extension('binary-diff-candidates')
        before=tool.inputs(self.index.api(),self.root,new)
        db=Path(json.loads(Path(pair['path']).read_text())['database'])
        with db.open('ab') as stream:stream.write(b'changed')
        self.assertNotEqual(before,tool.inputs(self.index.api(),self.root,new))


if __name__=='__main__':unittest.main()
