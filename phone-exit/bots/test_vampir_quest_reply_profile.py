"""Admission checks for the retained 1811 observation proof in world profiles."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QuestReplyProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader = load('quest_reply_profile_loader', HERE/'vampir-headless/bounded-world-profile.py')
        cls.verifier = load('quest_reply_profile_proof', HERE/'resource-tools/vampir/verify-quest-reply-current.py')
        pointer = cls.verifier.verify()
        cls.proof = json.loads(Path(pointer['report']).read_bytes())
        cls.inputs = cls.proof['definition']['inputs']

    def test_exact_reply_proof_passes_observation_gate(self):
        self.loader._quest_reply(self.proof, self.inputs)
        self.assertEqual(self.loader.REPLY_POLICY, 'quest-reply-observation-v1')
        self.assertNotIn(self.loader.REPLY_POLICY, self.loader.POLICIES)
        self.assertNotIn('quest-reply-current', self.loader.PROOFS)

    def test_mutated_native_outcome_cannot_be_admitted(self):
        for kind in ('wire', 'applications'):
            proof = copy.deepcopy(self.proof)
            if kind == 'wire':
                proof['result'][kind][0]['decoded'][2] = 7
            else:
                proof['result'][kind][0]['applies'] = False
            with self.assertRaisesRegex(ValueError, 'matrix differs'):
                self.loader._quest_reply(proof, self.inputs)

    def test_incomplete_proof_or_lost_inputs_fail_closed(self):
        for key in ('runtime_admitted', 'action_confirmed', 'registration_executed'):
            with self.assertRaisesRegex(ValueError, 'scope differs'):
                self.loader._quest_reply(dict(self.proof, **{key: True}), self.inputs)
        proof = copy.deepcopy(self.proof)
        proof['result']['wire'].pop()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.loader._quest_reply(proof, self.inputs)
        inputs = dict(self.inputs)
        del inputs[next(iter(inputs))]
        with self.assertRaisesRegex(ValueError, 'dependency'):
            self.loader._quest_reply(self.proof, inputs)


if __name__ == '__main__':
    unittest.main()
