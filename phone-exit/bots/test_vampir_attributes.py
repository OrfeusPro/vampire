import csv
import hashlib
import json
import runpy
import copy
import unittest
from pathlib import Path

ROOT = Path('F:/PhoneExit Resources/Vampir')


@unittest.skipUnless((ROOT/'maps/attributes/manifest.json').exists(), 'Resource library absent')
class AttributesTests(unittest.TestCase):
    def test_special_format_switch_and_native_routes(self):
        report=json.loads((ROOT/'code-clues/stat-format-routes.json').read_text('utf-8'))
        raw=Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),report['sha256'])
        for a in report['data_anchors']:
            content=bytes.fromhex(a['bytes']);self.assertEqual(raw[a['file_offset']:a['file_offset']+len(content)],content)
        self.assertEqual(report['statistics']['native_cases'],2307)
        self.assertEqual(report['statistics']['kinds'],dict(integer=95,percent=76,scaled_number=14))
        self.assertEqual(report['rules']['315'],dict(kind='scaled_number',scale=0.01,decimals=2,suffix=''))
        self.assertEqual(report['rules']['453'],dict(kind='scaled_number',scale=0.001,decimals=1,suffix=''))
        for id in range(454,466):self.assertEqual(report['rules'][str(id)]['scale'],0.1)
        self.assertFalse(report['stat_calculation_verified'])
        module=runpy.run_path(str(Path(__file__).parent/'resource-tools/vampir/build-stat-format-routes.py'))
        emulator=module['FormatRoutesEmulator'](ROOT)
        for c in report['cases'][::61]:
            self.assertEqual(emulator.execute_route(c['operation_id'],c['value'],c['percentage']),c['result'])
        self.assertEqual(emulator.execute_route(453,100,True)['mode'],'integer_percent')
        self.assertEqual(emulator.execute_route(453,100,False)['mode'],'one_decimal_scaled')
        self.assertEqual(emulator.execute_route(-1,10,False)['mode'],'integer_unscaled')

    def test_percentage_formatter_native_scaling_and_branches(self):
        report=json.loads((ROOT/'code-clues/stat-format-evidence.json').read_text('utf-8'))
        raw=Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),report['sha256'])
        for f in report['fragments']:
            size=f['end_rva']-f['begin_rva']
            self.assertEqual(hashlib.sha256(raw[f['file_offset']:f['file_offset']+size]).hexdigest(),f['sha256'])
        for a in report['anchors']+report['data_anchors']:
            content=bytes.fromhex(a['bytes'])
            self.assertEqual(raw[a['file_offset']:a['file_offset']+len(content)],content)
        self.assertEqual(report['statistics'],dict(native_cases=1665,percentage_records=76))
        self.assertFalse(report['stat_calculation_verified'])
        module=runpy.run_path(str(Path(__file__).parent/'resource-tools/vampir/build-stat-format-evidence.py'))
        emulator=module['StatFormatEmulator'](ROOT)
        for c in report['cases'][::47]:
            self.assertEqual(emulator.execute(c['value'],c['percentage']),c['result'])
        self.assertEqual(emulator.execute(100)['scaled'],1)
        self.assertEqual(emulator.execute(100)['mode'],'integer_percent')
        self.assertEqual(emulator.execute(150)['scaled'],1.5)
        self.assertEqual(emulator.execute(150)['mode'],'two_decimals_percent')

    def test_packet_structure_bytes_64bit_payloads_and_replays(self):
        report=json.loads((ROOT/'code-clues/stat-packet-evidence.json').read_text('utf-8'))
        raw=Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),report['sha256'])
        for f in report['fragments']:
            size=f['end_rva']-f['begin_rva']
            self.assertEqual(hashlib.sha256(raw[f['file_offset']:f['file_offset']+size]).hexdigest(),f['sha256'])
        for a in report['anchors']+report['data_anchors']:
            content=bytes.fromhex(a['bytes'])
            self.assertEqual(raw[a['file_offset']:a['file_offset']+len(content)],content)
        self.assertEqual(report['statistics'],dict(roundtrips=1392,native_reader_calls=1396,native_writer_calls=1396,failures=8))
        self.assertFalse(report['formula_verified'])
        self.assertFalse(report['live_values_available'])
        self.assertFalse(report['category_names_verified'])
        module=runpy.run_path(str(Path(__file__).parent/'resource-tools/vampir/build-stat-packet-evidence.py'))
        emulator=module['StatPacketEmulator'](ROOT)
        for i in [0,623,624,767,1000,1391]:
            c=report['cases'][i];value=int.from_bytes(bytes.fromhex(c['payload_hex']),'little')
            result=emulator.execute(c['kind'],c['key'],value)
            self.assertEqual(result,c['read'])
            self.assertEqual(emulator.execute(c['kind'],result['key'],value,'write'),c['write'])
        for c in report['failure_cases']:
            self.assertEqual(emulator.execute(c['kind'],7,123,c['direction'],c['fail_at']),c['result'])

    def test_item_comparison_context_bytes_and_replays(self):
        report=json.loads((ROOT/'code-clues/attribute-score-context.json').read_text('utf-8'))
        raw=Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),report['sha256'])
        for f in report['fragments']:
            size=f['end_rva']-f['begin_rva']
            self.assertEqual(hashlib.sha256(raw[f['file_offset']:f['file_offset']+size]).hexdigest(),f['sha256'])
        for a in report['anchors']+report['data_anchors']:
            content=bytes.fromhex(a['bytes'])
            self.assertEqual(raw[a['file_offset']:a['file_offset']+len(content)],content)
        self.assertEqual(report['statistics'],dict(comparisons=320,ui_selectors=320))
        self.assertTrue(report['item_comparison_verified'])
        self.assertFalse(report['total_character_power_verified'])
        self.assertFalse(report['ui_widget_name_verified'])
        module=runpy.run_path(str(Path(__file__).parent/'resource-tools/vampir/build-attribute-score-context.py'))
        emulator=module['ComparisonEmulator'](ROOT)
        selected=report['cases'][::31]+[c for c in report['cases'] if c['info'] and c['class_allowed'] and not c['blocked'] and not c['excluded']]
        for case in selected:
            self.assertEqual(emulator.execute(case),case['result'])
            self.assertEqual(emulator.ui_branch(case['result']),case['ui_argument'])

    def test_native_weight_proof_bytes_and_selected_replays(self):
        path = ROOT/'code-clues/attribute-weight-evidence.json'
        report = json.loads(path.read_text('utf-8'))
        raw = Path(report['source']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report['sha256'])
        for f in report['fragments']:
            size = f['end_rva']-f['begin_rva']
            self.assertEqual(hashlib.sha256(raw[f['file_offset']:f['file_offset']+size]).hexdigest(), f['sha256'])
        for a in report['anchors']:
            code = bytes.fromhex(a['bytes'])
            self.assertEqual(raw[a['file_offset']:a['file_offset']+len(code)], code)
        self.assertEqual(report['statistics']['native_executions'], 2583)
        self.assertEqual(report['statistics']['blank_weights'], 14)
        self.assertFalse(report['total_character_power_verified'])
        self.assertFalse(report['stat_to_stat_formula_verified'])
        module = runpy.run_path(str(Path(__file__).parent/'resource-tools/vampir/build-attribute-weight-evidence.py'))
        emulator = module['WeightEmulator'](ROOT)
        for case in report['cases'][-6:]:
            for i in range(3):
                self.assertEqual(emulator.execute(i,case['value'],case['weight'],case['accumulator']),case['results'][i])

    def test_stat_bindings_use_exact_enum_values_and_reject_max_as_dependency(self):
        data = json.loads((ROOT/'maps/attributes/attributes.json').read_text('utf-8'))
        native = json.loads((ROOT/'code-clues/native-enums.json').read_text('utf-8'))
        enums = {str(e['value']): e for e in native['enums']['EStat']}
        raw = Path(native['source']).read_bytes()
        sentinels = []
        for entry in data['entries']:
            binding = entry['stat_binding']
            self.assertEqual(binding['value'], entry['row']['StatType'])
            self.assertEqual(binding['enum'], enums[binding['value']])
            enum = binding['enum']
            encoded = enum['name'].encode('ascii')+b'\0'
            self.assertEqual(raw[enum['name_offset']:enum['name_offset']+len(encoded)], encoded)
            self.assertFalse(binding['native_calculation_verified'])
            if binding['status']=='sentinel':
                self.assertEqual(enum['name'], 'EStat::Max')
                sentinels.append(entry['id'])
            else:
                self.assertEqual(binding['status'], 'mapped')
                self.assertNotEqual(enum['name'], 'EStat::Max')
        self.assertEqual(set(sentinels), {'2051','2052','2057','2058'})

    def test_relations_have_exact_evidence_and_no_invented_formula(self):
        data = json.loads((ROOT/'maps/attributes/attributes.json').read_text('utf-8'))
        ids = {e['id'] for e in data['entries']}
        relations = data['relations']
        self.assertEqual(len(relations), 13)
        for r in relations:
            self.assertIn(r['source'], ids)
            self.assertIn(r['target'], ids)
            self.assertIsNone(r['formula'])
            self.assertFalse(r['native_formula_verified'])
            self.assertFalse(r['runtime_verified'])
            evidence = r['evidence']
            self.assertEqual(evidence['level'], 'client_description')
            self.assertEqual(evidence['record']['Desc'], evidence['statement'])
        build = runpy.run_path(str(Path(__file__).parent/'resource-tools/vampir/attribute-relations.py'))['build']
        altered = copy.deepcopy(data['entries'])
        source = next(e for e in altered if e['enum']['name']=='EOperationType::HpRecoveryMultiplier')
        source['description'] = 'Changed client description'
        with self.assertRaises(ValueError):
            build(altered)

    def test_all_rows_and_group_joins_from_raw_csv(self):
        def rows(entry):
            with (ROOT/f'table-study/pakchunk1-Windows-{entry}.csv').open(encoding='utf-8-sig', newline='') as f:
                return list(csv.DictReader(f))
        data = json.loads((ROOT/'maps/attributes/attributes.json').read_text('utf-8'))
        expected = {r['OperationType']: r for r in rows(1427)}
        groups = {r['GroupId']: r for r in rows(1428)}
        names = {r['OperationType']: r for r in rows(486)}
        self.assertEqual(len(data['entries']), len(expected))
        for e in data['entries']:
            self.assertEqual({k: e['row'][k] for k in expected[e['id']]}, expected[e['id']])
            group = groups.get(e['row']['DisplayGroupId'])
            self.assertEqual(e['tab_id'], group['OperationTabId'] if group else 'unassigned')
            name = names.get(e['enum']['name'].split('::')[-1])
            self.assertEqual(e['name_source'] is None, name is None)
            if name:
                self.assertEqual(e['name'], name['Name'])
                self.assertEqual(e['description'], name['Desc'])

    def test_sources_output_and_native_bytes(self):
        manifest = json.loads((ROOT/'maps/attributes/manifest.json').read_text('utf-8'))
        for path, digest in manifest['sources'].items():
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(), digest, path)
        self.assertEqual(hashlib.sha256((ROOT/'maps/attributes/attributes.json').read_bytes()).hexdigest(), manifest['sha256'])
        raw = Path(manifest['client_exe']['path']).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest['client_exe']['sha256'])
        for d in manifest['diagnostics']:
            text = d['text'].encode('utf-16le')
            self.assertEqual(raw[d['offset']:d['offset']+len(text)], text)
        data = json.loads((ROOT/'maps/attributes/attributes.json').read_text('utf-8'))
        for e in data['entries']:
            if e['enum']:
                n = e['enum']; text = n['name'].encode('ascii')+b'\0'
                self.assertEqual(raw[n['name_offset']:n['name_offset']+len(text)], text)


if __name__ == '__main__':
    unittest.main()
