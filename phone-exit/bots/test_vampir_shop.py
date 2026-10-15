import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent / 'vampir'
spec = importlib.util.spec_from_file_location('vampir_shop', ROOT / 'shop.py')
shop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shop)
binding_spec = importlib.util.spec_from_file_location('vampir_shop_binding', ROOT.parent / 'resource-tools/vampir/build-shop-binding.py')
binding = importlib.util.module_from_spec(binding_spec)
binding_spec.loader.exec_module(binding)


class Host:
    def __init__(self):
        self.visible, self.taps = set(), []
        self.fail_tap = False
        self.geometry = dict(point=[640, 360], rect=[620, 340, 660, 380])

    def call(self, command, **args):
        if command == 'match':
            return dict(found=args['name'] in self.visible, **self.geometry)
        if command == 'tap':
            self.taps.append(args)
            if self.fail_tap:
                raise RuntimeError('result_unknown')
        return {}


class ShopTransaction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'payload-sha256'
        self.directory.mkdir()
        self.host, self.state, self.now = Host(), {}, 1000
        self.config = json.loads((ROOT / 'vision.json').read_text(encoding='utf-8'))
        self.config['_chain_catalog'] = json.loads((ROOT / 'quest-runtime.json').read_text(encoding='utf-8'))
        self.reference = json.loads((ROOT / 'shop-reference.json').read_text(encoding='utf-8'))
        self.flow = self.config['shop_flow']

    def tick(self, *visible, after=3):
        self.now += after
        self.host.visible = set(visible)
        return shop.tick(self.host, self.state, dict(width=1280, height=720), self.config,
                         self.now, str(self.directory), self.reference)

    def prepare(self):
        self.assertEqual(self.tick(*self.flow['guide'])['step'], 'quest_shop_open')
        self.assertEqual(self.tick(*self.flow['listing'])['step'], 'quest_shop_selected')

    def confirm(self):
        return self.tick(*self.flow['confirmation'], self.flow['buy'])

    def test_unknown_screen_or_manual_shop_never_authorizes_purchase(self):
        self.assertIsNone(self.tick(*self.flow['listing']))
        self.assertIsNone(self.confirm())
        self.assertEqual(self.host.taps, [])

    def test_full_flow_persists_before_purchase_then_verifies_guide(self):
        self.prepare()
        self.assertEqual(self.confirm()['step'], 'quest_shop_purchased')
        self.assertEqual(shop.read_journal(self.directory), {'901030010': 'reserved'})
        self.assertEqual(self.tick(*self.flow['merchant'])['step'], 'quest_shop_verify_result')
        self.assertIsNone(self.tick(*self.flow['completed']))
        self.assertEqual(shop.read_journal(self.directory), {'901030010': 'completed'})
        self.assertEqual(len(self.host.taps), 4)

    def test_missing_price_quantity_or_item_never_confirms(self):
        for missing in self.flow['confirmation']:
            with self.subTest(missing=missing):
                self.state = {}
                self.host.taps = []
                self.prepare()
                self.tick(*(n for n in self.flow['confirmation'] if n != missing), self.flow['buy'])
                self.assertEqual(len(self.host.taps), 2)
                self.assertEqual(shop.read_journal(self.directory), {})

    def test_stuck_popup_is_not_purchased_twice(self):
        self.prepare()
        self.confirm()
        for _ in range(5):
            self.confirm()
        result = self.tick(*self.flow['confirmation'], self.flow['buy'], after=21)
        self.assertEqual(result['error'], 'quest_shop_purchase_outcome_unknown')
        self.assertFalse(result['retryable'])
        self.assertEqual(len(self.host.taps), 3)

    def test_restart_and_package_update_keep_reserved_purchase_blocked(self):
        self.prepare()
        self.confirm()
        self.state = {}
        self.directory = Path(self.temp.name) / 'new-payload-sha256'
        self.directory.mkdir()
        self.tick(*self.flow['guide'])
        self.confirm()
        self.assertEqual(len(self.host.taps), 3)
        self.assertEqual(self.tick(after=21)['error'], 'quest_shop_purchase_outcome_unknown')

    def test_transport_exception_retains_no_repeat_marker(self):
        self.prepare()
        self.host.fail_tap = True
        with self.assertRaises(RuntimeError):
            self.confirm()
        self.assertEqual(shop.read_journal(self.directory)['901030010'], 'reserved')
        self.state = {}
        self.host.fail_tap = False
        self.confirm()
        self.assertEqual(len(self.host.taps), 3)

    def test_storage_failure_prevents_purchase(self):
        self.prepare()
        with patch.object(shop, 'write_journal', side_effect=OSError('disk')):
            self.assertEqual(self.confirm()['error'], 'quest_shop_journal_write_failed')
        self.assertEqual(len(self.host.taps), 2)

    def test_directory_sync_failure_prevents_purchase_and_retains_marker(self):
        self.prepare()
        with patch.object(shop, 'sync_directory', side_effect=OSError('sync unavailable')):
            self.assertEqual(self.confirm()['error'], 'quest_shop_journal_write_failed')
        self.assertEqual(len(self.host.taps), 2)
        self.assertEqual(shop.read_journal(self.directory), {'901030010': 'reserved'})
        self.state = {}
        self.confirm()
        self.assertEqual(len(self.host.taps), 2)

    def test_android_directory_is_synced_and_descriptor_closed(self):
        with patch.object(shop.os, 'name', 'posix'), patch.object(shop.os, 'O_DIRECTORY', 65536, create=True), \
                patch.object(shop.os, 'open', return_value=123) as opened, \
                patch.object(shop.os, 'fsync') as synced, patch.object(shop.os, 'close') as closed:
            shop.sync_directory('private-bot-directory')
            opened.assert_called_once_with('private-bot-directory', shop.os.O_RDONLY | 65536)
            synced.assert_called_once_with(123)
            closed.assert_called_once_with(123)

    def test_android_directory_descriptor_closes_on_sync_error(self):
        with patch.object(shop.os, 'name', 'posix'), patch.object(shop.os, 'open', return_value=123), \
                patch.object(shop.os, 'fsync', side_effect=OSError('disk')), patch.object(shop.os, 'close') as closed:
            with self.assertRaises(OSError):
                shop.sync_directory('private-bot-directory')
            closed.assert_called_once_with(123)

    def test_corrupt_or_oversized_journal_prevents_all_input(self):
        for text in ('{', '[]', '{"901030010":"unknown"}', 'x' * 4097):
            shop.journal_path(self.directory).write_text(text, encoding='utf-8')
            self.assertEqual(self.tick(*self.flow['guide'])['error'], 'quest_shop_journal_unreadable')
        self.assertEqual(self.host.taps, [])

    def test_completed_purchase_does_not_rebuy_on_another_character(self):
        shop.write_journal(self.directory, 'completed')
        self.assertEqual(self.tick(*self.flow['guide'])['error'], 'quest_shop_already_recorded_for_device')
        self.assertEqual(self.host.taps, [])

    def test_lag_waits_without_repeated_selection(self):
        self.tick(*self.flow['guide'])
        self.tick(*self.flow['listing'], after=.2)
        self.assertEqual(len(self.host.taps), 1)
        self.assertEqual(self.tick(after=21)['error'], 'quest_shop_screen_not_advanced')

    def test_reference_change_prevents_all_input(self):
        self.reference['amount'] = 76
        self.assertEqual(self.tick(*self.flow['guide'])['error'], 'quest_shop_reference_mismatch')
        self.assertEqual(self.host.taps, [])

    def source_product(self):
        return next(p for p in self.config['_chain_catalog']['shopTasks']['901030010']['products'] if p['row']['Id'] == '10500003')

    def assert_source_rejected(self, error):
        result = self.tick(*self.flow['guide'])
        self.assertEqual(result['error'], error)
        self.assertTrue(result['pause'])
        self.assertFalse(result['retryable'])
        self.assertEqual(self.host.taps, [])
        self.assertEqual(shop.read_journal(self.directory), {})

    def test_full_source_catalog_required_before_input(self):
        self.config.pop('_chain_catalog')
        self.assert_source_rejected('quest_shop_source_catalog_missing')

    def test_numeric_task_type_must_match_native_symbol(self):
        self.config['_chain_catalog']['tasks']['901030010']['type'] = '25'
        self.assert_source_rejected('quest_shop_source_task_mismatch')

    def test_source_table_and_native_executable_versions_must_match(self):
        self.reference['nativeEnumSource']['sha256'] = '0' * 64
        self.assert_source_rejected('quest_shop_native_source_mismatch')

    def test_different_table_hash_blocks_even_if_visible_values_look_equal(self):
        next(iter(self.reference['sources'].values()))['sha256'] = '0' * 64
        self.assert_source_rejected('quest_shop_table_source_mismatch')

    def test_changed_product_binding_does_not_use_old_cost_header(self):
        self.reference['product']['row']['CostValue'] = '76'
        self.assert_source_rejected('quest_shop_source_product_mismatch')

    def test_closed_sale_in_both_catalog_and_binding_is_still_blocked(self):
        self.reference['product']['row']['IsSaleClosed'] = '1'
        self.source_product()['row']['IsSaleClosed'] = '1'
        self.assert_source_rejected('quest_shop_source_cost_or_sale_changed')

    def test_new_condition_in_both_sources_is_not_assumed_satisfied(self):
        self.reference['product']['row']['NeedConditionParam01'] = '65'
        self.source_product()['row']['NeedConditionParam01'] = '65'
        self.assert_source_rejected('quest_shop_source_conditions_changed')

    def test_changed_receipt_count_is_not_silently_accepted(self):
        self.reference['product']['rewards'][0]['row']['MaxCount'] = '2'
        self.source_product()['rewards'][0]['row']['MaxCount'] = '2'
        self.assert_source_rejected('quest_shop_source_receipt_changed')

    def test_geometry_missing_cannot_tap(self):
        self.host.geometry = dict(point=[640, 360])
        self.assertEqual(self.tick(*self.flow['guide'])['error'], 'quest_shop_target_geometry')
        self.assertEqual(self.host.taps, [])

    def test_source_binding_rejects_cost_and_task_drift(self):
        product = self.reference['product']
        task = dict(task=self.reference['task'], param=dict(npcSpawnInfoId=1101101,
                    interactionType='MoveContents', shopCategoryInfoId=3, count=1),
                    typeName='EQuestTaskType::NpcShopBuy', products=[product],
                    category=self.reference['category'], npcSpawn=self.reference['npcSpawn'])
        report = dict(tasks=[task], sources={}, nativeEnumSource={}, unresolvedTabLockKeywords=['76'])
        self.assertEqual(binding.reference(report)['amount'], 75)
        product['row']['CostValue'] = '76'
        with self.assertRaises(ValueError):
            binding.reference(report)
