import copy
from pathlib import Path
import unittest

from test_vampir_update_contracts import load, HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')
SHA='d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960'
ARTIFACTS={'run-571e3ba7330a':'4280b5fc70e7708ecf95248adba6aeedcb7cd0755ac2da034ce0fc162a1770a5',
    'run-7c5a462e9d0c':'c94200451d70a9eb459767aa9076b5f98a90325605c135686db082f31a290619'}


def context(name):
    index=load('knowledge-index')
    model=load('update-contracts').load(index.api(),HERE/'knowledge')
    c=next(c for c in model['contracts'] if c['id']==name)
    exports=[]
    for key,at in c['bindings'][SHA].items():
        run='run-571e3ba7330a' if at=='0x1467ce6a0' else 'run-7c5a462e9d0c'
        exports.append(dict(address=at,state='ready',artifacts=[dict(
            path=str(ROOT/'ghidra/request-exports'/SHA/run/'details.json'),sha256=ARTIFACTS[run])]))
    return dict(schema=1,source_sha256=SHA,source=str(ROOT/'client-code-snapshots'/SHA/'ProjectRED-Win64-Shipping.exe'),
        contract=c,bindings=dict(bindings=c['bindings'][SHA]),exports=exports,dependencies={})


class VersionLoginContextTests(unittest.TestCase):
    def test_current_constructors_ids_names_and_both_tag_consumers(self):
        tool=load('verify-version-login-context')
        reports={name:tool.verify(context(name),ROOT) for name in ('game-version','game-login')}
        self.assertEqual(reports['game-version']['binding']['packet_id'],1)
        self.assertEqual(reports['game-login']['binding']['packet_id'],3)
        self.assertEqual(reports['game-version']['links']['version_slot'],0x48)
        self.assertEqual(reports['game-version']['links']['wrapper_table'],'0x149dc9320')
        self.assertEqual(reports['game-login']['links']['login_tag_field'],0x110)
        self.assertEqual(reports['game-version']['binding']['tag'],reports['game-login']['binding']['tag'])
        for r in reports.values():
            self.assertEqual(len(r['cases']),4)
            self.assertFalse(r['network_used']);self.assertFalse(r['profile_activated'])
            self.assertTrue(all(c['guards'] for c in r['cases']))

    def test_wrong_type_and_field_are_not_accepted(self):
        tool=load('verify-version-login-context')
        for key,value in (('packet_id',2),('tag_field',0x100),('destination_offset',0x70)):
            c=context('game-login');c['contract']['tag_check'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):tool.verify(c,ROOT)

    def test_corrupt_export_is_rejected(self):
        c=context('game-version')
        for e in c['exports']:
            for a in e['artifacts']:a['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'export SHA changed'):
            load('verify-version-login-context').verify(c,ROOT)

    def test_unknown_data_dependency_is_not_silently_accepted(self):
        c=context('game-version')
        c['contract']['data_dependencies'][SHA]['unknown-table']=dict(kind='vtable',address='0x140000000')
        with self.assertRaisesRegex(ValueError,'Unreviewed data'):
            load('verify-version-login-context').verify(c,ROOT)


if __name__=='__main__':unittest.main()
