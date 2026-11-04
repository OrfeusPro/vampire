"""Выборочные ключи static materialize на изолированном дереве файлов."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from test_vampir_update_contracts import load


SCOPE = load('native-materialize-inputs-v2')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class NativeMaterializeInputsV2Tests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Path(directory.name).resolve()
        self.here = self.workspace/'phone-exit/bots/resource-tools/vampir'
        self.knowledge = self.here/'knowledge'
        self.knowledge.mkdir(parents=True)
        self.bots = self.here.parents[1]
        for name in (*SCOPE.TOOLS,'update-run.py',Path(SCOPE.__file__).name):
            self.write(self.here/name,"raise RuntimeError('This tool must only be hashed')\n")
        self.rule = dict(schema=1,recipe=SCOPE.RECIPE,
            reviewed_tools={name:digest(self.here/name) for name in SCOPE.TOOLS})
        self.selector = self.knowledge/'native-materialize-inputs.json'
        self.save_rule(self.rule)
        self.registry = self.knowledge/'native-release-registry.json'
        self.write(self.registry,'{"fixture":"default registry"}\n')
        self.portable = dict(python='fixture Python',implementation='fixture',files={'runtime.py':'a'*64})
        self.runtime = dict(capstone=dict(version='fixture',record_sha256='b'*64))
        self.legacy = dict(unrelated_native_suite='legacy fixture')
        self.index = SimpleNamespace(HERE=self.here,digest=digest,
            extension=self.extension)
        self.args = SimpleNamespace(knowledge=self.knowledge)

    def extension(self, name):
        self.assertEqual(name,'stage-action-tools-v1')
        return SimpleNamespace(runtime=lambda index:copy.deepcopy(self.portable))

    def write(self, path, text):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(text,encoding='utf-8')
        return path

    def save_rule(self, rule, path=None):
        (path or self.selector).write_text(json.dumps(rule,sort_keys=True)+'\n',encoding='utf-8')

    def tools(self, knowledge=None):
        before = copy.deepcopy((self.legacy,self.runtime))
        result = SCOPE.tool_inputs(self.index,knowledge or self.knowledge,self.legacy,self.runtime)
        self.assertEqual((self.legacy,self.runtime),before)
        return result

    def definitions(self, entries, knowledge=None):
        before = copy.deepcopy(entries)
        args = self.args if knowledge is None else SimpleNamespace(knowledge=knowledge)
        result = SCOPE.definitions(self.index,args,entries)
        self.assertEqual(entries,before)
        return result

    def material(self, *paths):
        return {str(path.resolve()):digest(path) for path in paths}

    def test_reviewed_tools_keep_exact_twelve_modules_without_executing_them(self):
        self.assertEqual(len(SCOPE.TOOLS),12)
        value = self.tools()
        self.assertEqual(value['mode'],'reviewed')
        self.assertEqual(value['files'],self.material(*(self.here/name for name in SCOPE.TOOLS)))
        self.assertNotIn('legacy_tools',value)
        self.assertEqual(value['native_runtime'],self.runtime)
        self.assertEqual(value['portable_runtime'],self.portable)

    def test_definition_filter_preserves_exact_code_allowlist_and_guards(self):
        paths = [self.here/name for name in (*SCOPE.TOOLS,'update-run.py',Path(SCOPE.__file__).name)]
        paths.append(self.selector)
        entries = self.material(*paths)
        self.assertEqual(self.definitions(entries),entries)

    def test_unrelated_python_tests_and_check_registry_are_filtered(self):
        unrelated = self.write(self.here/'unrelated.py','# unrelated code')
        test = self.write(self.bots/'test_vampir_fixture.py','# unrelated offline test')
        checks = self.write(self.knowledge/'research-checks.json','{"checks":[]}')
        selected = self.material(self.here/'update-native-contexts.py')
        entries = {**selected,**self.material(unrelated,test,checks)}
        self.assertEqual(self.definitions(entries),selected)

    def test_external_python_and_all_non_python_material_are_preserved(self):
        paths = [self.write(self.workspace/'external.py','# external code'),
            self.write(self.knowledge/'native-contexts/fixture.json','{"source":"fixture"}'),
            self.write(self.here/'InspectVampirSdkProfile.java','// selected Java input'),
            self.write(self.here/'runtime.dll','bounded runtime bytes'),
            self.registry]
        entries = self.material(*paths)
        self.assertEqual(self.definitions(entries),entries)

    def test_same_basename_outside_exact_allowlist_is_filtered(self):
        same = self.write(self.bots/'another/update-bindings.py','# unrelated same basename')
        selected = self.material(self.here/'update-bindings.py')
        self.assertEqual(self.definitions({**selected,**self.material(same)}),selected)

    def test_code_drift_returns_conservative_tools_and_complete_definitions(self):
        unrelated = self.write(self.here/'unrelated.py','# remains on fallback')
        checks = self.write(self.knowledge/'research-checks.json','{"checks":[]}')
        entries = self.material(unrelated,checks,self.here/'update-bindings.py')
        self.write(self.here/'update-bindings.py','# changed concrete implementation')
        value = self.tools()
        self.assertEqual(value['mode'],'conservative')
        self.assertEqual(value['legacy_tools'],self.legacy)
        self.assertEqual(self.definitions(entries),entries)

    def test_missing_guard_file_restores_full_definitions_and_reappearance_is_seen(self):
        path = self.here/'extract-native-enums.py'
        raw = path.read_bytes()
        unrelated = self.write(self.bots/'test_vampir_fixture.py','# fallback test')
        entries = self.material(unrelated)
        path.unlink()
        value = self.tools()
        self.assertEqual(value['mode'],'conservative')
        self.assertIsNone(value['files'][str(path)])
        self.assertEqual(self.definitions(entries),entries)
        path.write_bytes(raw)
        self.assertEqual(self.tools()['mode'],'reviewed')
        self.assertEqual(self.definitions(entries),{})

    def test_custom_knowledge_uses_conservative_tools_and_complete_definitions(self):
        knowledge = self.workspace/'custom-knowledge'
        knowledge.mkdir()
        selector = knowledge/self.selector.name
        self.save_rule(self.rule,selector)
        unrelated = self.write(self.bots/'test_vampir_custom.py','# preserve on fallback')
        checks = self.write(knowledge/'research-checks.json','{"checks":[]}')
        entries = self.material(unrelated,checks,selector)
        value = self.tools(knowledge)
        self.assertEqual(value['mode'],'conservative')
        self.assertEqual(value['legacy_tools'],self.legacy)
        self.assertEqual(self.definitions(entries,knowledge),entries)

    def test_unknown_recipe_boolean_schema_and_extra_fields_are_rejected(self):
        for field,value in (('schema',True),('schema',2),('recipe','unreviewed'),('extra','field')):
            rule = copy.deepcopy(self.rule)
            rule[field] = value
            self.save_rule(rule)
            with self.subTest(field=field,value=value),self.assertRaisesRegex(ValueError,'recipe'):
                self.tools()

    def test_incomplete_extra_or_malformed_tool_hashes_are_rejected(self):
        for changed in ('missing','extra','hash'):
            rule = copy.deepcopy(self.rule)
            if changed=='missing':
                rule['reviewed_tools'].pop(SCOPE.TOOLS[0])
            elif changed=='extra':
                rule['reviewed_tools']['unreviewed.py'] = 'a'*64
            else:
                rule['reviewed_tools'][SCOPE.TOOLS[0]] = 'short'
            self.save_rule(rule)
            with self.subTest(changed=changed),self.assertRaisesRegex(ValueError,'recipe'):
                self.tools()

    def test_registry_budget_is_enforced(self):
        self.selector.write_bytes(b' '*8193)
        with self.assertRaisesRegex(ValueError,'budget'):
            self.tools()

    def test_helper_and_selector_hashes_are_present_and_rule_byte_change_invalidates(self):
        before = self.tools()
        guard = before['recipe_guard']
        self.assertEqual(guard[str(Path(SCOPE.__file__).resolve())],digest(SCOPE.__file__))
        self.assertEqual(guard[str(self.selector)],digest(self.selector))
        self.selector.write_text(self.selector.read_text()+'\n',encoding='utf-8')
        after = self.tools()
        self.assertEqual(after['mode'],'reviewed')
        self.assertNotEqual(before,after)

    def test_runtime_and_default_native_registry_changes_invalidate_keys(self):
        before = self.tools()
        self.runtime['capstone']['record_sha256'] = 'c'*64
        native = self.tools()
        self.assertNotEqual(before,native)
        self.portable['files']['runtime.py'] = 'd'*64
        portable = self.tools()
        self.assertNotEqual(native,portable)
        self.write(self.registry,'{"fixture":"changed native metadata"}\n')
        registry = self.tools()
        self.assertNotEqual(portable,registry)
        self.assertEqual(registry['native_registry'],{str(self.registry):digest(self.registry)})

    def test_returned_runtime_and_fallback_maps_do_not_mutate_callers(self):
        self.write(self.here/'update-native-contexts.py','# changed implementation')
        value = self.tools()
        value['legacy_tools']['unrelated_native_suite'] = 'changed return value'
        value['native_runtime']['capstone']['version'] = 'changed return value'
        value['portable_runtime']['files']['runtime.py'] = 'e'*64
        self.assertEqual(self.legacy['unrelated_native_suite'],'legacy fixture')
        self.assertEqual(self.runtime['capstone']['version'],'fixture')
        self.assertEqual(self.portable['files']['runtime.py'],'a'*64)


if __name__=='__main__':
    unittest.main()
