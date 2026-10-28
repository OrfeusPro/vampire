"""Bundle admission and publication boundaries, without game/network processes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'vampir-shared'))
from vampir_core import release_bundle as admission


def load(name):
    path = HERE / 'resource-tools/vampir' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.workspace, self.root, self.install = [base / n for n in ('workspace', 'library', 'install')]
        self.tools = self.workspace / 'phone-exit/bots/resource-tools/vampir'
        self.shared = self.workspace / 'phone-exit/bots/vampir-shared/vampir_core/release_bundle.py'
        names = ['update-bundle.py', 'update-profile.py', 'update-contracts.py', 'research-workflow.py']
        self.rules = {}
        for name in names:
            path = self.tools / name
            self.write(path, b'# frozen tool\n')
            self.rules[str(path)] = admission.digest(path)
        self.write(self.shared, b'# frozen admission\n')
        self.rules[str(self.shared)] = admission.digest(self.shared)
        source = self.install / 'ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe'
        self.write(source, b'installed target\n')
        self.sha = admission.digest(source)
        self.contract = dict(id='position', coverage='source_checks', depends_on=[], checks=['position-native'])
        self.specs = dict(schema=1, capabilities={'map': {'requires': ['position']}}, contracts=[self.contract])
        self.check = dict(id='position-native', source_scope='client', offline_reviewed=True,
            source_sha256=[self.sha], test_pattern='test_vampir_example.py', dependencies=[],
            artifact_dependencies=['fixture.bin'])
        self.test = self.workspace / 'phone-exit/bots/test_vampir_example.py'
        self.write(self.test, b'# reviewed offline suite\n')
        fixture = self.root / 'fixture.bin'
        self.write(fixture, b'bounded fixture\n')
        self.write_json(self.tools / 'knowledge/update-contracts.json', self.specs)
        self.write_json(self.tools / 'knowledge/research-checks.json', {'checks': [self.check]})
        for name in ('update-contracts.json', 'research-checks.json'):
            path = self.tools / 'knowledge' / name
            self.rules[str(path)] = admission.digest(path)
        self.context = self.snapshot('update-contexts', dict(source_sha256=self.sha, contract={'id': 'position'}))
        self.proof = self.snapshot('check-results', dict(state='passed', definition=dict(
            check=self.check, source_sha256=self.sha, inputs={str(self.test): admission.digest(self.test)},
            artifacts={str(fixture): admission.digest(fixture)}, python_version=platform.python_version(),
            executable=sys.executable, runner_sha256=admission.digest(self.tools / 'research-workflow.py'),
            runtime_metadata={})))
        self.receipt = dict(id='position-native', state='passed', report=str(self.proof), sha256=self.proof.parent.name)
        self.bundle = dict(schema=1, capability='map', source_sha256=self.sha, source=str(source),
            install=str(self.install), state='prepared_offline', live_verified=False, runtime_activated=False,
            rules=self.rules, artifacts={str(self.context): self.context.parent.name, str(self.proof): self.proof.parent.name},
            contracts={'position': dict(state='passed', context=dict(path=str(self.context), sha256=self.context.parent.name),
                checks=[self.receipt])})

    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def write_json(self, path, value):
        self.write(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())

    def snapshot(self, category, value):
        raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        sha = hashlib.sha256(raw).hexdigest()
        path = self.root / 'knowledge' / category / sha / 'manifest.json'
        self.write(path, raw)
        return path

    def selected(self):
        return 'prepared:' + self.snapshot('prepared-bundles', self.bundle).parent.name

    def validate(self, selected=None):
        return admission.validate(root=self.root, workspace=self.workspace,
            selected=selected or self.selected(), capability='map')

    def test_complete_target_bundle_is_accepted_without_analysis(self):
        value = self.validate()
        self.assertEqual(value['source_sha256'], self.sha)
        self.assertFalse(value['live_verified'])

    def test_second_patch_rejects_old_pending_bundle(self):
        selected = self.selected()
        Path(self.bundle['source']).write_bytes(b'next installed target\n')
        with self.assertRaisesRegex(ValueError, 'artifact changed'):
            self.validate(selected)

    def test_changed_rules_and_check_inputs_are_rejected(self):
        selected = self.selected()
        self.test.write_bytes(b'# modified suite\n')
        with self.assertRaisesRegex(ValueError, 'artifact changed'):
            self.validate(selected)

    def test_function_only_proof_cannot_close_semantic_contract(self):
        proof = self.snapshot('check-results', dict(scope='function_only', state='passed', source_sha256=self.sha))
        self.bundle['contracts']['position']['checks'] = [dict(self.receipt, report=str(proof), sha256=proof.parent.name)]
        with self.assertRaises((ValueError, KeyError)):
            self.validate()

    def test_pointer_is_pinned_once_for_a_session(self):
        selected = self.selected()
        pointer = self.root / 'knowledge/next-profiles/map.json'
        self.write_json(pointer, dict(schema=1, capability='map', bundle_sha256=selected.partition(':')[2]))
        pinned = admission.select(self.root, capability='map')
        self.write_json(pointer, dict(schema=1, capability='map', bundle_sha256='a' * 64))
        self.assertEqual(self.validate(pinned)['selected_profile'], pinned)
        with self.assertRaises(OSError):
            self.validate('prepared-next')

    def test_missing_required_check_does_not_admit(self):
        self.bundle['contracts']['position']['checks'] = []
        with self.assertRaisesRegex(ValueError, 'semantic coverage'):
            self.validate()

    def test_unreviewed_target_sha_does_not_admit(self):
        self.check['source_sha256'] = []
        self.write_json(self.tools / 'knowledge/research-checks.json', {'checks': [self.check]})
        path = self.tools / 'knowledge/research-checks.json'
        self.rules[str(path)] = admission.digest(path)
        with self.assertRaisesRegex(ValueError, 'no reviewed target'):
            self.validate()

    def world_bundle(self):
        from vampir_core import runtime_admission
        self.specs['capabilities']={'world-session':{'requires':['position']}}
        self.contract['context_checks']=['version-login-tag']
        self.write_json(self.tools/'knowledge/update-contracts.json',self.specs)
        self.rules[str(self.tools/'knowledge/update-contracts.json')]=admission.digest(self.tools/'knowledge/update-contracts.json')
        for name in runtime_admission.CONSUMERS:
            path=self.workspace/name
            if not path.exists():self.write(path,b'# frozen runtime consumer\n')
            self.rules[str(path)]=admission.digest(path)
        adapter=runtime_admission.descriptor(self.workspace)
        sdk=dict(runtime_scope='sdk-launcher-auth',supported_auth_flows=['launcher'],source_sha256=self.sha,
            source=self.bundle['source'],public_gmc2={'profile':{},'request':{}},nid={'profile':{}},
            direct_sdk_operations_verified=False,network_ready=False,game_protocol_verified=False)
        sdk_path=self.snapshot('prepared-profiles',dict(state='prepared_offline',source_sha256=self.sha,profile=sdk))
        config_dir=self.root/'resource-config-snapshots'
        archive=self.install/'ProjectRED/Content/Paks/test.pak'
        self.write(archive,b'archive fixture')
        values={'CdnConfig':'True','CdnConfigUrl':'cdn.example.test/path','CdnConfigUrlQA':'qa.example.test/path',
            'ConfigPrefix':'real','AppVersion':'1.13.24'}
        raw=('\n'.join(k+'='+v for k,v in values.items())+'\n').encode()
        config=dict(exe_sha256=self.sha,source_exe=self.bundle['source'],source_archive={'path':str(archive)},
            archive_sha256=admission.digest(archive),configs=[dict(snapshot_file='DefaultGame.ini',payload_sha256=hashlib.sha256(raw).hexdigest(),
                values=[dict(section='NetworkSetting',line=n,key=k,value=v) for n,(k,v) in enumerate(values.items(),1)])])
        data=(json.dumps(config,sort_keys=True,indent=2)+'\n').encode();sha=hashlib.sha256(data).hexdigest()
        cp=config_dir/sha/'manifest.json';self.write(cp,data);self.write(cp.parent/'DefaultGame.ini',raw)
        from vampir_core.sdk_config import prepare_cdn_config_url_ascii
        url=prepare_cdn_config_url_ascii(normal=values['CdnConfigUrl'],qa=values['CdnConfigUrlQA'],
            prefix='real',app_version='1.13.24',platform_code=2)
        tag='A'*32
        proof=self.snapshot('update-context-checks',dict(source_sha256=self.sha,context_sha256=self.context.parent.name,
            network_used=False,cases=[{'guards':True}],binding={'tag':tag}))
        checks=self.bundle['contracts']['position']['checks']
        checks.append(dict(id='version-login-tag',state='passed',report=str(proof),sha256=proof.parent.name))
        self.bundle.update(capability='world-session',runtime_adapter=adapter,sdk_profile=sdk,
            sdk_profile_receipt=dict(path=str(sdk_path),sha256=sdk_path.parent.name),game_profile=dict(
                config_snapshot_sha256=sha,app_version='1.13.24',config_prefix='real',cdn_url='https://'+url,compiled_tag=tag))
        return self.bundle

    def test_world_bundle_requires_same_sdk_config_tag_and_runtime_consumers(self):
        bundle=self.world_bundle()
        selected=self.selected()
        value=admission.validate(root=self.root,workspace=self.workspace,selected=selected)
        self.assertEqual(value['source_sha256'],self.sha)
        bundle['game_profile']['compiled_tag']='B'*32
        with self.assertRaisesRegex(ValueError,'tag does not match'):
            admission.validate(root=self.root,workspace=self.workspace,selected=self.selected())

    def test_world_bundle_rejects_forged_sdk_payload_and_changed_consumer(self):
        self.world_bundle()
        original=self.bundle['sdk_profile']['nid']
        self.bundle['sdk_profile']['nid']={'profile':{'game_code':'other'}}
        with self.assertRaisesRegex(ValueError,'SDK profile'):
            admission.validate(root=self.root,workspace=self.workspace,selected=self.selected())
        self.bundle['sdk_profile']['nid']=original
        selected=self.selected()
        (self.workspace/'phone-exit/bots/vampir-headless/run-live-sessions.py').write_bytes(b'# changed')
        with self.assertRaisesRegex(ValueError,'artifact changed'):
            admission.validate(root=self.root,workspace=self.workspace,selected=selected)

    def test_prepare_publishes_only_a_complete_capability(self):
        builder, workflow = load('update-bundle'), load('research-workflow')
        args = SimpleNamespace(root=self.root, install=self.install)
        index = SimpleNamespace(digest=admission.digest, read_json=lambda p: json.loads(Path(p).read_bytes()),
            extension=lambda name: workflow)
        outcome = dict(state='passed', context=str(self.context), checks=[self.receipt])
        audit = dict(exe={'path': self.bundle['source'], 'sha256': self.sha}, files=[])
        with patch.object(builder, 'HERE', self.tools), patch.object(builder.release_bundle, '__file__', str(self.shared)):
            result = builder.prepare(index, args, self.specs, {'position': outcome},
                {'map': {'state': 'prepared_offline'}}, [], {}, audit)
            self.assertFalse((self.root/'knowledge/next-profiles/map.json').exists())
            builder.publish(index,args,result)
        self.assertEqual(result['queue'], [])
        self.assertEqual(len(result['bundles']), 1)
        self.assertEqual(self.validate('prepared-next')['source_sha256'], self.sha)
        empty = builder.prepare(index, args, self.specs, {}, {'map': {'state': 'incomplete'}}, [], {}, audit)
        self.assertEqual(empty['bundles'], [])

    def test_failed_tooling_blocks_pointer_publication(self):
        builder,workflow=load('update-bundle'),load('research-workflow')
        index=SimpleNamespace(extension=lambda name:workflow)
        result=dict(bundles=[{'capability':'map'}],next_profiles={},queue=[])
        actual=builder.publish(index,SimpleNamespace(root=self.root),result,
            tooling_checks=[{'id':'automatic-update-tooling','state':'failed'}])
        self.assertFalse(actual['next_profiles']);self.assertTrue(actual['queue'])


if __name__ == '__main__':
    unittest.main()
