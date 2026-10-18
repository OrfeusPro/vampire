"""SDK config provenance and actual native mode-selector branch coverage."""
import hashlib
import importlib.util
import json
import os
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class SDKConfigEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
        path = root/'code-clues/headless-sdk-config.json'
        if not path.exists():
            raise unittest.SkipTest('Generate native SDK config evidence first')
        cls.report = json.loads(path.read_text('utf-8'))
        cls.raw = Path(cls.report['source']).read_bytes()

    def test_source_fragments_constants_and_linked_roots(self):
        r = self.report
        self.assertFalse(r['network_ready'])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), r['sha256'])
        self.assertEqual(r['missing'], [])
        self.assertEqual(r['rejected_candidates'], [])
        self.assertEqual(r['statistics'], dict(symbols=7, xrefs=8, roots=7, constants=48, native_mode_cases=256))
        rows = {i['address']: i for f in r['fragments'] for i in f['instructions']}
        for f in r['fragments']:
            data = self.raw[f['file_offset']:f['file_offset']+f['end_rva']-f['begin_rva']]
            self.assertEqual(hashlib.sha256(data).hexdigest(), f['sha256'])
            self.assertEqual(data, b''.join(bytes.fromhex(i['bytes']) for i in f['instructions']))
        for row in r['symbols']+r['referenced_constants']:
            data = bytes.fromhex(row['bytes'])
            self.assertEqual(self.raw[row['file_offset']:row['file_offset']+len(data)], data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), row['sha256'])
        for xref in r['xrefs']:
            row = rows[xref['instruction']['address']]
            self.assertEqual(row, xref['instruction'])
            self.assertEqual(row['mnemonic'], 'lea')
        constants = {row['text'] for row in r['referenced_constants']}
        self.assertTrue({'https://alpha-apis.netmarble.com/gc2', 'https://dev-apis.netmarble.com/gc2',
                         'https://apis.netmarble.com/gc2', 'https://dr-apis.netmarble.com/gc2',
                         '/template-groups/', '?game=v5&country=G9&build=', '&engine=unreal&market=',
                         'GET', 'encConstants', 'encSecretConstants', 'DECKEY'}.issubset(constants))
        # Prove the constructor field association used to interpret selector output.
        self.assertEqual(rows[0x1444bdb12]['operands'], 'rcx, [rbx + 0x170]')
        url = next(c for c in r['referenced_constants'] if c['instruction']['address'] == 0x1444bdb19)
        self.assertEqual(url['text'], 'https://apis.netmarble.com/gc2')

    def test_native_mode_mapping_including_unknown_values(self):
        selection = self.report['mode_selection']
        self.assertEqual((selection['start'], selection['end']), (0x144501a11, 0x144501a46))
        self.assertEqual(len(selection['cases']), 256)
        for mode, case in enumerate(selection['cases']):
            self.assertEqual(case, dict(mode=mode, selected_field_offset={0: 0x150, 1: 0x160, 2: 0x170, 3: 0x180}.get(mode, 0x160)))

    def test_reexecute_native_selector(self):
        path = HERE/'resource-tools/vampir/build-headless-sdk-config.py'
        spec = importlib.util.spec_from_file_location('config_replay', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        image = module.native.Image(self.raw)
        replay = module.replay_mode_selection(self.raw, image, self.report['fragments'])
        self.assertEqual(replay, self.report['mode_selection'])


if __name__ == '__main__':
    unittest.main()
