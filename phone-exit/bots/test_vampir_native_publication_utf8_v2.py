"""Legacy UTF-8 provenance uses source/bindings/admission, without rewritten reports."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

import test_vampir_native_publication_v2 as fixtures
from test_vampir_update_contracts import load

BRIDGE = load('native-publication-utf8-v2')
COMMON = fixtures.COMMON


def fixture(directory, *, wrong_binding=False, wrong_context=False):
    f=fixtures.Fixture(directory)
    (f.knowledge/'native-drivers-v2/version-result.json').unlink()
    seed=BRIDGE.HERE/'knowledge/native-drivers-v2/utf8.json'
    (f.knowledge/'native-drivers-v2/utf8.json').write_bytes(seed.read_bytes())
    f.spec=dict(id='native-auto-utf8',family='utf8',adapter='utf8-v1');f.scope='bounded_native_utf8'
    f.context_value=dict(f.context_value,family='utf8',native_admission=f.context_value['transfer_proof'],
        bindings=dict(length='0x140001000',convert='0x140002000'))
    del f.context_value['transfer_proof']
    f.context=COMMON.receipt(f.root,'generated-native-contexts',f.context_value)
    f.report_value=dict(f.report_value,scope=f.scope,bindings=dict(f.context_value['bindings']),
        cases=[dict(guards=True) for _ in range(142)],scalar_cases=[dict(guards=True) for _ in range(80)])
    del f.report_value['context_sha256']
    if wrong_binding:f.report_value['bindings']['length']='0x140001001'
    if wrong_context:f.report_value['context_sha256']='f'*64
    f.report=COMMON.receipt(f.root,'native-adapter-checks',f.report_value)
    f.declaration.update(id=f.spec['id'],adapter='utf8-v1',scope=f.scope,context=f.context,
        dependencies={str(BRIDGE.HERE/name):fixtures.digest(BRIDGE.HERE/name) for name in COMMON.TOOLS})
    for path in list(f.declaration['artifacts']):
        if 'generated-native-contexts' in path:del f.declaration['artifacts'][path]
    f.declaration['artifacts'][f.context['path']]=f.context['sha256']
    f.outcome.update(id=f.spec['id'],scope=f.scope,report=f.report['path'],sha256=f.report['sha256'])
    f.path=f.root/'knowledge/generated-native/index.json'
    original_extension=f.index.extension
    f.index.extension=lambda name:fixtures.CACHE if name=='native-publication-v2' else original_extension(name)
    def publish(index,args,sha,declaration,outcome):
        f.publish_count+=1;f.write_index()
        f.registry.generated_contexts(f.root,f.registry.read(f.knowledge))
    f.tool=SimpleNamespace(TOOLS=COMMON.TOOLS,publish=publish)
    return f


class LegacyUtf8Publication(unittest.TestCase):
    def test_legacy_report_without_context_sha_earns_new_receipt_without_rewriting_report(self):
        with tempfile.TemporaryDirectory() as directory:
            f=fixture(directory);raw=Path(f.report['path']).read_bytes()
            session=BRIDGE.begin(f.index,f.args,f.sha)
            self.assertEqual(f.call(session),'validated');first=session.finish()
            f.new_args();session=BRIDGE.begin(f.index,f.args,f.sha)
            self.assertEqual(f.call(session),'reused');second=session.finish()
            self.assertEqual(first['validated'],1);self.assertEqual(second['validated'],0)
            self.assertEqual(f.publish_count,1);self.assertEqual(Path(f.report['path']).read_bytes(),raw)

    def test_legacy_bindings_and_explicit_foreign_context_sha_are_rejected(self):
        for mutation in ('binding','context'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                f=fixture(directory,wrong_binding=mutation=='binding',wrong_context=mutation=='context')
                with self.assertRaisesRegex(ValueError,'bindings/source/admission'):
                    f.call(BRIDGE.begin(f.index,f.args,f.sha))
                self.assertEqual(f.publish_count,0)

    def test_bridge_cannot_admit_another_native_family(self):
        with tempfile.TemporaryDirectory() as directory:
            f=fixture(directory);session=BRIDGE.begin(f.index,f.args,f.sha)
            f.spec=dict(id='native-auto-version-result',family='version-result',adapter='version-result-v1')
            with self.assertRaisesRegex(ValueError,'exact descriptor'):f.call(session)


if __name__=='__main__':unittest.main()
