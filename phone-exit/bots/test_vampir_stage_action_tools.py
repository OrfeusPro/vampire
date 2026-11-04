"""SHA инструментов отдельных действий на изолированном дереве файлов."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_vampir_update_contracts import load


ACTION = load('stage-action-tools-v1')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class StageActionToolsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name).resolve()
        self.here = self.workspace/'phone-exit/bots/resource-tools/vampir'
        self.knowledge = self.here/'knowledge'
        self.knowledge.mkdir(parents=True)
        for path in {p for role in ACTION.ROLES for p in ACTION.files(self.here,role)}:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text("raise RuntimeError('Fingerprinting must not execute this file')\n",encoding='utf-8')
        self.native_registry = self.knowledge/'native-release-registry.json'
        self.native_registry.write_bytes(b'{"fixture":"native metadata"}\n')
        self.rule = dict(schema=1,recipe=ACTION.RECIPE,roles={
            role:{p.relative_to(self.workspace).as_posix():digest(p) for p in ACTION.files(self.here,role)}
            for role in ACTION.ROLES})
        self.path = self.knowledge/'stage-action-tools.json'
        self.save_rule(self.rule)
        self.index = SimpleNamespace(HERE=self.here,digest=digest)
        self.groups = dict(context=dict(unrelated='context fixture'),profile=dict(unrelated='profile fixture'))
        self.native_runtime = dict(capstone=dict(version='fixture',record_sha256='a'*64))
        self.portable_runtime = dict(python='fixture Python',implementation='fixture',files={'runtime.py':'b'*64})
        mocked = patch.object(ACTION,'runtime',side_effect=lambda index:copy.deepcopy(self.portable_runtime))
        mocked.start()
        self.addCleanup(mocked.stop)

    def save_rule(self, rule, path=None):
        (path or self.path).write_text(json.dumps(rule,sort_keys=True)+'\n',encoding='utf-8')

    def inputs(self, knowledge=None):
        before = copy.deepcopy((self.groups,self.native_runtime))
        result = ACTION.inputs(self.index,knowledge or self.knowledge,self.groups,self.native_runtime)
        self.assertEqual((self.groups,self.native_runtime),before)
        return result

    def test_missing_selector_leaves_no_action_overrides(self):
        self.path.unlink()
        self.assertEqual(self.inputs(),{})

    def test_reviewed_roles_hash_exact_files_and_default_native_metadata(self):
        result = self.inputs()
        self.assertEqual(set(result),set(ACTION.ROLES))
        for role,value in result.items():
            self.assertEqual(value['mode'],'reviewed')
            self.assertNotIn('legacy_tools',value)
            self.assertEqual(value['files'],{
                str(p.resolve()):digest(p) for p in ACTION.files(self.here,role)})
            self.assertEqual(value['portable_runtime'],self.portable_runtime)
            if role.startswith('context-'):
                self.assertEqual(value['native_registry'],{str(self.native_registry):digest(self.native_registry)})
            else:
                self.assertNotIn('native_registry',value)

    def test_unknown_or_omitted_roles_are_rejected(self):
        for changed in ('missing','extra'):
            rule = copy.deepcopy(self.rule)
            if changed=='missing':
                rule['roles'].pop('context-tag')
            else:
                rule['roles']['unreviewed-command'] = {}
            self.save_rule(rule)
            with self.subTest(changed=changed),self.assertRaisesRegex(ValueError,'recipe'):
                self.inputs()

    def test_incomplete_extra_or_invalid_hash_declarations_are_rejected(self):
        for changed in ('missing','extra','hash','absolute'):
            rule = copy.deepcopy(self.rule)
            declared = rule['roles']['profile-builder']
            key = next(iter(declared))
            if changed=='missing':
                declared.pop(key)
            elif changed=='extra':
                declared['phone-exit/bots/unreviewed.py'] = 'a'*64
            elif changed=='hash':
                declared[key] = 'short'
            else:
                declared[str((self.workspace/key).resolve())] = declared.pop(key)
            self.save_rule(rule)
            with self.subTest(changed=changed),self.assertRaisesRegex(ValueError,'Incomplete'):
                self.inputs()

    def test_unknown_recipe_schema_and_oversized_registry_are_rejected(self):
        for field,value in (('schema',True),('schema',2),('recipe','unreviewed')):
            rule = dict(self.rule,**{field:value})
            self.save_rule(rule)
            with self.subTest(field=field,value=value),self.assertRaisesRegex(ValueError,'recipe'):
                self.inputs()
        self.path.write_bytes(b' '*16385)
        with self.assertRaisesRegex(ValueError,'budget'):
            self.inputs()

    def test_own_verifier_change_invalidates_only_its_action_role(self):
        before = self.inputs()
        (self.here/'verify-version-login-context.py').write_text('# changed tag verifier',encoding='utf-8')
        after = self.inputs()
        self.assertNotEqual(before['context-tag'],after['context-tag'])
        self.assertEqual(after['context-tag']['mode'],'conservative')
        self.assertEqual(after['context-tag']['legacy_tools'],self.groups['context'])
        self.assertEqual(before['context-writer'],after['context-writer'])
        self.assertEqual(before['profile-builder'],after['profile-builder'])

    def test_shared_portable_helper_change_affects_profile_builder_only(self):
        before = self.inputs()
        shared = self.here.parents[1]/'vampir-shared/vampir_core/gmc2_request.py'
        shared.write_text('# changed HTTP argument plan',encoding='utf-8')
        after = self.inputs()
        self.assertNotEqual(before['profile-builder'],after['profile-builder'])
        self.assertEqual(after['profile-builder']['legacy_tools'],self.groups['profile'])
        for role in ('context-tag','context-writer'):
            self.assertEqual(before[role],after[role])

    def test_common_workflow_change_uses_conservative_keys_for_all_actions(self):
        before = self.inputs()
        (self.here/'research-workflow.py').write_text('# changed generic workflow',encoding='utf-8')
        after = self.inputs()
        for role in ACTION.ROLES:
            self.assertNotEqual(before[role],after[role])
            self.assertEqual(after[role]['mode'],'conservative')

    def test_default_native_registry_change_affects_both_context_actions_only(self):
        before = self.inputs()
        self.native_registry.write_bytes(b'{"fixture":"another native baseline"}\n')
        after = self.inputs()
        for role in ('context-tag','context-writer'):
            self.assertNotEqual(before[role],after[role])
            self.assertEqual(after[role]['mode'],'reviewed')
        self.assertEqual(before['profile-builder'],after['profile-builder'])

    def test_portable_runtime_changes_invalidate_all_actions(self):
        before = self.inputs()
        self.portable_runtime['files']['runtime.py'] = 'c'*64
        after = self.inputs()
        self.assertTrue(all(before[role]!=after[role] for role in ACTION.ROLES))

    def test_native_runtime_changes_affect_context_actions_and_are_copied(self):
        before = self.inputs()
        self.native_runtime['capstone']['record_sha256'] = 'd'*64
        after = self.inputs()
        for role in ('context-tag','context-writer'):
            self.assertNotEqual(before[role],after[role])
        self.assertEqual(before['profile-builder'],after['profile-builder'])
        after['context-tag']['native_runtime']['capstone']['version'] = 'mutated result'
        self.assertEqual(self.native_runtime['capstone']['version'],'fixture')

    def test_rule_bytes_are_guarded_for_every_action(self):
        before = self.inputs()
        self.path.write_text(self.path.read_text()+'\n',encoding='utf-8')
        after = self.inputs()
        self.assertTrue(all(before[role]!=after[role] for role in ACTION.ROLES))
        guard = after['profile-builder']['recipe_guard']
        self.assertEqual(guard[str(self.path)],digest(self.path))
        self.assertEqual(guard[str(Path(ACTION.__file__).resolve())],digest(ACTION.__file__))

    def test_custom_knowledge_keeps_legacy_and_explicit_inputs_for_each_role(self):
        knowledge = self.workspace/'custom-knowledge'
        knowledge.mkdir()
        self.save_rule(self.rule,knowledge/'stage-action-tools.json')
        result = self.inputs(knowledge)
        for role,value in result.items():
            self.assertEqual(value['mode'],'conservative')
            group = 'profile' if role=='profile-builder' else 'context'
            self.assertEqual(value['legacy_tools'],self.groups[group])
            self.assertEqual(set(value['files']),{str(p.resolve()) for p in ACTION.files(self.here,role)})
        result['profile-builder']['legacy_tools']['unrelated'] = 'changed returned dict'
        self.assertEqual(self.groups['profile']['unrelated'],'profile fixture')

    def test_missing_declared_file_is_a_conservative_input_and_reappearance_is_seen(self):
        path = self.here/'verify-packet-writer-context.py'
        raw = path.read_bytes()
        path.unlink()
        missing = self.inputs()
        self.assertEqual(missing['context-writer']['mode'],'conservative')
        self.assertIsNone(missing['context-writer']['files'][str(path)])
        path.write_bytes(raw)
        present = self.inputs()
        self.assertEqual(present['context-writer']['mode'],'reviewed')
        self.assertNotEqual(missing['context-writer'],present['context-writer'])


class StageActionRuntimeTests(unittest.TestCase):
    def test_runtime_pins_python_and_portable_implementation_files(self):
        value = ACTION.runtime(SimpleNamespace(digest=digest))
        self.assertEqual(value['python'],sys.version)
        self.assertEqual(value['implementation'],sys.implementation.name)
        required = (Path(sys.executable),Path(ACTION.dataclasses.__file__),
            Path(ACTION.urllib.parse.__file__),Path(ACTION.ctypes.__file__),
            Path(ACTION.locale.__file__),Path(ACTION.encodings.utf_8_sig.__file__))
        for path in required:
            self.assertEqual(value['files'][str(path.resolve())],digest(path))


if __name__=='__main__':
    unittest.main()
