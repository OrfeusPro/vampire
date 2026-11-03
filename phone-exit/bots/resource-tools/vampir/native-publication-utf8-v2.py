"""Typed v2 publication bridge for the frozen UTF-8 report format."""
import copy
from pathlib import Path

HERE = Path(__file__).resolve().parent


def begin(index, args, sha):
    base = index.extension('native-publication-v2').Session

    class Utf8Session(base):
        def __init__(self):
            super().__init__(index, args, sha)
            path = HERE / 'native-publication-utf8-v2.py'
            self.guard[str(path)] = self.actual(path)

        def _snapshot(self, spec, tool, declaration, outcome):
            descriptor = self._descriptor('utf8')
            if spec != self.driver.spec(descriptor) or spec['adapter'] != 'utf8-v1':
                raise ValueError('UTF-8 publication bridge accepts only its exact descriptor')
            context = self.common.checked(self.root, declaration['context'], 'generated-native-contexts')
            check = dict(path=outcome['report'], sha256=outcome['sha256'])
            report = self.common.checked(self.root, check, 'native-adapter-checks')
            proof = context.get('native_admission')
            if (declaration.get('id') != spec['id'] or outcome.get('id') != spec['id']
                    or declaration.get('adapter') != 'utf8-v1' or outcome.get('state') != 'passed'
                    or context.get('family') != 'utf8' or context.get('source_sha256') != self.sha
                    or report.get('source_sha256') != self.sha or report.get('method') != 'bounded_native'
                    or report.get('scope') != 'bounded_native_utf8'
                    or declaration.get('scope') != report['scope'] or outcome.get('scope') != report['scope']
                    or report.get('proof') != proof or declaration.get('proof') != proof
                    or not isinstance(context.get('bindings'), dict) or not context['bindings']
                    or report.get('bindings') != context['bindings']
                    or report.get('context_sha256') not in (None, declaration['context']['sha256'])
                    or any(report.get(key) is not False for key in ('runtime_activated','network_used','profile_activated'))
                    or any(outcome.get(key) is not False for key in ('runtime_activated','profile_activated'))):
                raise ValueError('Frozen UTF-8 report bindings/source/admission differ')
            tools = self._tools('utf8', tool)
            if declaration.get('dependencies') != tools or report.get('runtime') != self.runtime:
                raise ValueError('UTF-8 publication tools/runtime differ')
            if not isinstance(declaration.get('artifacts'), dict):
                raise ValueError('UTF-8 publication needs explicit artifacts')
            self._source(self.sha, context.get('source'))
            files, contexts, sources = self._lineage([declaration['context'], check], declaration['artifacts'])
            sources[self.sha] = self.sources[self.sha]
            selections, eligible = {}, True
            for (family, source), pointer in sorted(contexts.items()):
                row = self._row(family, source, tool if family == 'utf8' else None)
                selections[family + '@' + source] = row
                if row is None or row['context'] != pointer:
                    eligible = False
            row = selections.get('utf8@' + self.sha)
            if row is None or row['context'] != declaration['context'] or row['check'] != check:
                eligible = False
            return copy.deepcopy(dict(schema=2, spec=spec, source_sha256=self.sha,
                declaration=declaration, outcome=outcome, files=files, sources=sources, tools=tools,
                guard=self.guard, runtime=self.runtime, python_runtime=self.python_runtime,
                binary_runtime=self.binary_runtime, publications=selections,
                registry_projection=self._registry_projection(sources, contexts),
                descriptors={family:self.used_descriptors[family] for family, _ in sorted(contexts)},
                validator_tools={family:self.validator_tools[family] for family, _ in sorted(contexts)
                    if family in self.validator_tools},
                provenance_contract='frozen_utf8_source_bindings_native_admission_v1')), eligible

    return Utf8Session()
