"""Pinned current runtime profile, real evidence and offline rejection boundaries."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent/'vampir-headless'
spec=importlib.util.spec_from_file_location('game_runtime_11318_profile',HERE/'game-source-profile.py')
profile=importlib.util.module_from_spec(spec);sys.modules[spec.name]=profile;spec.loader.exec_module(profile)
sys.path.insert(0,str(HERE))
import game_candidate_evidence as evidence


class CurrentRuntimeProfileTests(unittest.TestCase):
    def test_shared_dependency_cannot_hide_a_conflicting_proof(self):
        original=evidence.document
        changed_once=[]
        def changed(path,sha):
            value=original(path,sha)
            if 'check-results' in Path(path).parts and not changed_once:
                for filename in value['definition']['inputs']:
                    if Path(filename).name=='build-native-entry-code.py':
                        value['definition']['inputs'][filename]='0'*64
                        changed_once.append(filename)
                        break
            return value
        with patch.object(evidence,'document',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'proofs conflict'):
                profile.verify_latest_candidate_evidence()
        self.assertEqual(len(changed_once),1)

    def test_current_real_profile_keeps_bounded_scope_and_old_profile(self):
        value=profile.load_profile(selected_profile=profile.LATEST_CANDIDATE)
        self.assertEqual(value.app_version,'1.13.18')
        self.assertEqual(value.source_exe_sha256,profile.LATEST_SHA)
        self.assertEqual(value.source_snapshot_sha256,profile.LATEST_CONFIG)
        self.assertEqual(value.compiled_tag,'32283C4C6485307BCF524765A84409C3')
        self.assertTrue(value.live_probe_only and value.bounded_world_probe)
        self.assertFalse(value.active_game_cache_verified)
        self.assertEqual(profile.CANDIDATE,'candidate-11316')
        self.assertNotEqual(profile.PROFILES[profile.CANDIDATE][1],profile.LATEST_SHA)

    def test_changed_candidate_rejected_before_proof_validation(self):
        original=evidence.digest
        def changed(path):
            return '0'*64 if 'game-source-candidates' in Path(path).parts else original(path)
        with patch.object(evidence,'digest',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'proof changed'):
                profile.verify_latest_candidate_evidence()

    def test_changed_dependency_rejects_even_when_report_is_passed(self):
        original=evidence.digest
        def changed(path):
            return '0'*64 if Path(path).name=='heartbeat.py' else original(path)
        with patch.object(evidence,'digest',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'dependency changed'):
                profile.verify_latest_candidate_evidence()

    def test_current_candidate_cannot_add_quest_capability(self):
        original=evidence.document
        def changed(path,sha):
            value=original(path,sha)
            if 'game-source-candidates' in Path(path).parts:value['capabilities'].append('quests')
            return value
        with patch.object(evidence,'document',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'scope changed'):
                profile.verify_latest_candidate_evidence()

    def test_unreviewed_current_check_definition_rejects(self):
        path=HERE.parent/'resource-tools/vampir/knowledge/research-checks.json'
        original=Path.read_bytes
        def changed(at):
            raw=original(at)
            if at.resolve()==path.resolve():
                document=json.loads(raw)
                row=next(c for c in document['checks'] if c['id']=='periodic-ping-policy')
                row['offline_reviewed']=False
                return json.dumps(document).encode()
            return raw
        with patch.object(Path,'read_bytes',changed):
            with self.assertRaisesRegex(ValueError,'not reviewed'):
                profile.verify_latest_candidate_evidence()

    def test_current_tag_bytes_are_checked_without_native_imports(self):
        with patch.object(profile,'verify_file') as verify:
            # Direct tag verification reads only fixed offsets. Corruption of
            # the declared offset cannot fall back to a historical tag.
            with patch.dict(profile.WIRE_TAGS,{profile.LATEST_SHA:(0,'00',0,'wrong')}):
                with self.assertRaisesRegex(ValueError,'pointer changed'):
                    profile.verify_compiled_tag(
                        'C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe',
                        profile.LATEST_SHA)
        verify.assert_not_called()


if __name__=='__main__':unittest.main()
