"""Pure full-handler matrix/outcome and proof-admission contracts."""
import copy
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent / 'resource-tools/vampir'


def load(name):
    spec = spec_from_file_location(name.replace('-', '_'), HERE/(name+'.py'))
    result = module_from_spec(spec); spec.loader.exec_module(result)
    return result


class LoginFullHandlerContractTests(unittest.TestCase):
    def setUp(self):
        self.tool = load('login-full-handler-case-contracts')
        self.context = dict(packet_bytes=352, format='login-full-handler-v1')

    def report(self):
        return dict(schema=1, method='bounded_native', cases=self.tool.expected_rows(), packet_bytes=352,
            network_used=False, profile_activated=False, runtime_activated=False,
            same_packet_reader_used=False, native_handler_used=True, native_gate_used=True,
            native_post_state_used=False, native_continuation_used=False, session_executed=False)

    def test_exact48_scenarios_and_report(self):
        self.assertEqual(self.tool.case_count(), 48)
        self.assertEqual(len(self.tool.scenarios()), 48)
        self.tool.validate_report(self.report(), self.context)

    def test_all_old_service_dimensions_and_special_gate_codes_remain(self):
        cases = self.report()['cases']
        self.assertEqual({row['field48'] for row in cases[:10]}, {0, 1, 32767, 32768, 65535})
        self.assertEqual({row['settings']['peer_flag'] for row in cases[:10]}, {0, 1})
        self.assertEqual([row['code'] for row in cases[10:20]], [1, 14, 22, 37, 54, 9400, 9818, 9819, 90021, 0xffffffff])
        self.assertEqual([row['raw16'] for row in cases[35:38]], [0, 1, 65535])
        self.assertEqual([row['code'] for row in cases[38:40]], [0x1197, 0x1197])

    def test_new_matrix_has_predicate_storage_and_poison_dimensions(self):
        cases = self.report()['cases'][40:]
        keys = {(row['settings']['trailing_predicate'], row['settings']['temp_allocated'], row['settings']['poison']) for row in cases}
        self.assertEqual(len(keys), 8)
        self.assertEqual({row['settings']['poison'] for row in cases}, {0x55, 0xaa})
        for row in cases:
            event = next(event for event in row['events'] if event['action']=='trailing_predicate')
            self.assertEqual((event['text'], event['time'], event['field150'], event['field154']),
                             ('новая🙂', 0x1234000000000000, 0x89abcdef, 0x12345678))

    def test_false_temporary_storage_allocation_is_freed_once_and_true_never_frees_input(self):
        for row in self.report()['cases'][40:]:
            settings = row['settings']; predicate = settings['trailing_predicate']
            apply = next(event for event in row['events'] if event['action']=='trailing_apply')
            frees = [event for event in row['events'] if event['action']=='trailing_free']
            self.assertEqual(apply['call_offset'], 836 if predicate else 855)
            self.assertEqual(apply['source'], 'packet' if predicate else 'empty_temporary')
            self.assertEqual(apply['text'], 'новая🙂' if predicate else '')
            expected = not predicate and settings['temp_allocated']
            self.assertEqual(len(frees), int(expected))
            self.assertEqual((row['trailing_temporary_allocated'], row['trailing_temporary_freed']), (expected, expected))
            if frees: self.assertEqual(frees[0]['call_offset'], 869)

    def test_signed_field_controls_early_and_positive_paths(self):
        rows = self.report()['cases'][:10]
        for row in rows:
            names = [event['action'] for event in row['events']]
            signed_positive = 0 < row['field48'] < 32768
            early = row['settings']['peer_flag'] == 1 and signed_positive
            self.assertEqual('early' in names, early)
            self.assertEqual('trailing_predicate' in names, not early)
            self.assertEqual('positive' in names, signed_positive and not early)
            if early: self.assertEqual(names[-2:], ['early', 'virtual_exit'])

    def test_same_optional_error_helper_uses_concrete_absent_finish_branch(self):
        rows = self.report()['cases']
        for row in rows:
            if row['code'] != 90021: continue
            present = row['settings'].get('optional_object', True)
            self.assertEqual(row['events'][-1]['call_offset'], 1341 if present else 1384)
            self.assertEqual(row['events'][-1]['action'], 'error_finish')

    def test_gate_special_code_has_error_then_success_or_suppressed_failure(self):
        rows = self.report()['cases'][38:40]
        self.assertEqual(rows[0]['events'][1], dict(action='gate_error', owner='gate', call_offset=961, arguments_checked=True))
        self.assertEqual(rows[0]['events'][2], dict(action='native_gate_return', value=1))
        self.assertEqual(rows[1]['events'][1], dict(action='native_gate_return', value=0))
        self.assertFalse(any(event['action']=='trailing_predicate' for event in rows[1]['events']))

    def test_current_writes_have_exact_field_values_and_new_instruction_offsets(self):
        row = self.report()['cases'][0]
        self.assertEqual(row['state']['text'], 'fixture')
        self.assertEqual(row['state']['qwords']['0xb0'], 0x1234000000000004)
        self.assertEqual(row['state']['flags'], {'0xa0':1,'0xe8':1})
        self.assertEqual(next(w['instruction_offset'] for w in row['writes'] if w['region']=='state' and w['offset']=='0x88'), 885)
        self.assertEqual(next(w['instruction_offset'] for w in row['writes'] if w['region']=='global'), 766)
        self.assertEqual(row['controller_server'], [42,42])
        self.assertEqual(row['derived'], -19660800000000)

    def test_error_routes_leave_state_and_controller_unchanged(self):
        for row in self.report()['cases'][10:20]:
            if row['code']==0: continue
            self.assertEqual(row['state']['text'], 'before')
            self.assertEqual(row['controller_server'], [7,7])
            self.assertFalse(any(w['region'] in ('state','controller') for w in row['writes']))
            self.assertEqual(row['special22'], int(row['code']==22))

    def test_sdk_and_post_predicate_service_routes_exact(self):
        rows = self.report()['cases']
        for index in (25,26):
            names = [event['action'] for event in rows[index]['events']]
            self.assertIn('virtual_sdk', names); self.assertIn('sdk_a0', names)
            self.assertEqual('sdk_final' in names, index==25)
        self.assertIn('predicate_action', [event['action'] for event in rows[22]['events']])
        self.assertNotIn('other_action', [event['action'] for event in rows[22]['events']])

    def test_duplicate_missing_and_uncovered_scenarios_rejected(self):
        for mutation in ('duplicate', 'missing', 'extra'):
            report = self.report()
            if mutation=='duplicate': report['cases'][1]=copy.deepcopy(report['cases'][0])
            elif mutation=='missing': report['cases'].pop()
            else: report['cases'].append(copy.deepcopy(report['cases'][0]))
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_bool_integer_types_and_all_abi_buffer_guards_strict(self):
        for field, value in (('code',False), ('field48',False), ('guards',1), ('abi',False), ('packet_guards',False), ('string_guards',False)):
            report = self.report(); report['cases'][0][field]=value
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)
        report = self.report(); report['cases'][0]['state']['qwords']['0x38']=True
        with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_new_predicate_argument_or_wrong_branch_outcome_rejected(self):
        for action, field, value in (('trailing_predicate','field150',0), ('trailing_predicate','time',0),
                                     ('trailing_apply','call_offset',855), ('trailing_apply','text','wrong')):
            report = self.report(); row = next(row for row in report['cases'][40:] if row['settings']['trailing_predicate'])
            next(event for event in row['events'] if event['action']==action)[field]=value
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_write_store_identity_value_and_order_rejected_when_changed(self):
        for field, value in (('instruction_offset',884), ('offset','0x90'), ('value',0), ('size',4)):
            report = self.report(); report['cases'][0]['writes'][0][field]=value
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_unexecuted_reader_post_state_and_session_boundaries_are_strict(self):
        for field in ('network_used','profile_activated','runtime_activated','same_packet_reader_used',
                      'native_post_state_used','native_continuation_used','session_executed'):
            report = self.report(); report[field]=True
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)
        for field, value in (('packet_bytes',320), ('method','static'), ('native_gate_used',False)):
            report = self.report(); report[field]=value
            with self.assertRaises(ValueError): self.tool.validate_report(report, self.context)

    def test_tools_pin_verifier_harness_and_custom_gate_boundary_rule(self):
        self.assertEqual({Path(path).name for path in self.tool.tools()}, set(self.tool.TOOLS))
        source = (HERE/'verify-login-full-handler-context.py').read_text('utf-8')
        self.assertIn('adapter.validate(index, args, context)',source)
        self.assertIn('gate_module.export_coverage',source)
        self.assertIn('verify_whole_exports=False',source)
        self.assertIn("'XMM'+str(i)",source)
        self.assertIn('packet_guards=True', source)


class FullLoginHandlerStandaloneAdmissionTests(unittest.TestCase):
    def run_admission(self, change=None, roots=None):
        verifier = load('verify-login-full-handler-context')
        context = dict(family='login-full-handler', transfer_proof=dict(path='proof',sha256='a'*64),
                       functions=dict(handler='0x1000',gate='0x2000'),source_sha256='b'*64)
        if change: context.update(change)
        calls = []
        def module(name):
            if name=='knowledge-index': return SimpleNamespace(api=lambda:SimpleNamespace())
            if name=='update-bindings': return SimpleNamespace(SourceStore=lambda index,root:SimpleNamespace(
                image=lambda native,sha:object(),validate=lambda:calls.append('source')))
            if name=='update-native-login-full': return SimpleNamespace(select=lambda family:SimpleNamespace(
                roots=lambda c:{0x1000,0x2000} if roots is None else roots,
                validate=lambda *args:calls.append('proof'),export_coverage=lambda *args:calls.append('exports')))
            if name=='build-native-entry-code': return object()
            raise AssertionError(name)
        with patch.object(verifier,'load',module): verifier.admit(context,Path('F:/PhoneExit Resources/Vampir'))
        return calls

    def test_exact_roots_proof_and_full_export_source_guard(self):
        self.assertEqual(self.run_admission(),['proof','exports','source'])

    def test_missing_proof_extra_native_pipeline_and_root_alias_rejected(self):
        for change in (dict(transfer_proof=None),dict(family='other'),dict(function_budget=16),dict(native_input={})):
            with self.assertRaises(ValueError): self.run_admission(change)
        for roots in ({0x1000},{0x1000,0x2000,0x3000}):
            with self.assertRaises(ValueError): self.run_admission(roots=roots)


class FullLoginHandlerPopupSelectorTests(unittest.TestCase):
    def fixture(self):
        handler, target = 0x1000, 0x1180
        address = handler + 289
        instruction = b'\x8b\x1d' + struct.pack('<i', target-(address+6))
        data = bytearray(512); data[289:295] = instruction; data[384:388] = struct.pack('<I', 250)
        image = SimpleNamespace(pe=SimpleNamespace(base=handler), data=bytes(data), offset=lambda rva:rva)
        rows = [dict(address=address, bytes=instruction.hex(), mnemonic='mov', rip_references=[target])]
        return image, handler, rows

    def test_popup_selector_comes_from_source_ui_constant_not_error_result(self):
        verifier = load('verify-login-full-handler-context')
        image, handler, rows = self.fixture()
        value = verifier.read_popup_selector(image, handler, rows)
        self.assertEqual(value, 250)
        self.assertNotEqual(value, 1)  # The scenario's LoginResult code is 1.
        source = (HERE/'verify-login-full-handler-context.py').read_text('utf-8')
        self.assertIn('c & 0xffffffff == popup_selector', source)
        self.assertNotIn("c & 0xffffffff == current['code'], 'Handler error popup", source)

    def test_wrong_load_rip_boundary_or_source_bytes_fail_closed(self):
        verifier = load('verify-login-full-handler-context')
        for change in ('missing','duplicate','opcode','mnemonic','rip','codebytes','shortdata'):
            image, handler, rows = self.fixture()
            if change=='missing': rows.clear()
            if change=='duplicate': rows *= 2
            if change=='opcode': rows[0]['bytes']='8b05'+rows[0]['bytes'][4:]
            if change=='mnemonic': rows[0]['mnemonic']='lea'
            if change=='rip': rows[0]['rip_references']=[0x1184]
            if change=='codebytes': image.data=image.data[:289]+b'\x90'+image.data[290:]
            if change=='shortdata': image.data=image.data[:386]
            with self.subTest(change=change), self.assertRaises(ValueError):
                verifier.read_popup_selector(image, handler, rows)


if __name__=='__main__': unittest.main()
