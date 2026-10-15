"""One source-bound Guide purchase, with a durable no-repeat marker before input."""
import json
import os
import random
from pathlib import Path


def journal_path(directory):
    # BotManager installs immutable payloads under files/bots/vampir/<sha256>.
    # The module's data stays in the game base across updates/rollback.
    return Path(directory).resolve().parent / 'vampir-purchases.json'


def read_journal(directory):
    path = journal_path(directory)
    if not path.exists():
        return {}
    if path.stat().st_size > 4096:
        raise ValueError('shop_journal_invalid')
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or any(k != '901030010' or v not in ('reserved', 'completed') for k, v in value.items()):
        raise ValueError('shop_journal_invalid')
    return value


def write_journal(directory, status):
    value = read_journal(directory)
    value['901030010'] = status
    path = journal_path(directory)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def sync_directory(path):
    # Android/Linux needs the rename itself persisted, not only file contents.
    # Windows is used for offline replay and cannot open a directory this way.
    if os.name == 'nt':
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_reference(reference, catalog):
    """Cross-check the executable purchase against the complete source catalog."""
    if not catalog or catalog.get('referenceRevision', 0) < 2:
        raise ValueError('quest_shop_source_catalog_missing')
    try:
        tid, qid = reference['taskId'], reference['questId']
        task, quest = catalog['tasks'][tid], catalog['quests'][qid]
        source = catalog['shopTasks'][tid]
        if (task['quest'] != qid or tid not in quest['tasksInFileOrder'] or task['typeName'] != 'EQuestTaskType::NpcShopBuy'
                or catalog['nativeValueSymbols']['EQuestTaskType'].get(task['type']) != task['typeName']):
            raise ValueError('quest_shop_source_task_mismatch')
        if task['param'] != source['param'] or json.loads(reference['task']['Param']) != task['param']:
            raise ValueError('quest_shop_source_parameter_mismatch')
        if (type(task['param']['count']) is not int or task['param']['count'] != reference['count'] or task['param']['interactionType'] != 'MoveContents'
                or str(task['param']['shopCategoryInfoId']) != reference['category']['Id']
                or str(task['param']['npcSpawnInfoId']) != reference['npcSpawn']['Id']
                or reference['task']['Id'] != tid or reference['task']['QuestInfoId'] != qid
                or reference['task']['TargetSpotInfoId'] != task['worldSpot']):
            raise ValueError('quest_shop_source_parameter_mismatch')
        if reference['category'] != source['category'] or reference['npcSpawn'] != source['npcSpawn']:
            raise ValueError('quest_shop_source_destination_mismatch')
        products = [p for p in source['products'] if p['row']['Id'] == reference['productId']]
        if len(products) != 1 or products[0] != reference['product']:
            raise ValueError('quest_shop_source_product_mismatch')
        product = products[0]
        row = product['row']
        if row['IsSaleClosed'] != '0' or product['costTypeName'] != 'ECostType::Asset' or row['CostParam'] != reference['asset'] or row['CostValue'] != str(reference['amount']):
            raise ValueError('quest_shop_source_cost_or_sale_changed')
        if (product['conditionTypeName'] != 'EPurchaseCondition::Max' or product['condition2TypeName'] != 'EPurchaseCondition::Max'
                or any(row[k] for k in ('NeedConditionParam01', 'NeedConditionParam02', 'NeedCondition02Param01', 'NeedCondition02Param02'))):
            raise ValueError('quest_shop_source_conditions_changed')
        rewards = product['rewards']
        if (len(rewards) != 1 or rewards[0]['typeName'] != 'ERewardType::Item'
                or rewards[0]['row']['Param'] != reference['itemId']
                or rewards[0]['row']['MinCount'] != '1' or rewards[0]['row']['MaxCount'] != '1'):
            raise ValueError('quest_shop_source_receipt_changed')
        if reference['nativeEnumSource'] != catalog['nativeEnumSource']:
            raise ValueError('quest_shop_native_source_mismatch')
        sources = {meta['entry']: meta for meta in catalog['sources'].values()}
        for meta in reference['sources'].values():
            entry = sources[meta['entry']]
            if entry['sha256'] != meta['sha256'] or entry['file'] != meta['file']:
                raise ValueError('quest_shop_table_source_mismatch')
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError('quest_shop_source_reference_invalid') from error


def tick(host, state, frame, config, now, directory, reference):
    flow = config.get('shop_flow')
    if not flow:
        return None

    def report(step, error=None):
        result = dict(status='running', step=step, error=error, activePoint='quest:901030/task:901030010')
        if error:
            result.update(status='error', pause=True, retryable=False)
        return result

    if (reference.get('schemaVersion'), reference.get('questId'), reference.get('taskId'), reference.get('productId'),
            reference.get('itemId'), reference.get('count'), reference.get('asset'), reference.get('amount')) != (
            1, '901030', '901030010', '10500003', '91100005', 1, 'Gold', 75):
        return report('quest_shop_reference', 'quest_shop_reference_mismatch')
    try:
        validate_reference(reference, config.get('_chain_catalog'))
    except ValueError as error:
        return report('quest_shop_reference', str(error))

    def match(name):
        if callable(config.get('_match')):
            return config['_match'](name)
        return host.call('match', name=name, spec=config['templates'][name])

    def visible(names):
        return all(match(name).get('found') for name in names)

    def tap(name, stage):
        button = match(name)
        if not button.get('found'):
            return report('quest_shop_wait_target')
        point, rect = button.get('point'), button.get('rect')
        if not rect or not point or not (0 <= rect[0] < rect[2] <= frame['width'] and
                0 <= rect[1] < rect[3] <= frame['height'] and
                rect[0] + 2 < point[0] < rect[2] - 2 and rect[1] + 2 < point[1] < rect[3] - 2):
            return report('quest_shop_target', 'quest_shop_target_geometry')
        radius = min(2 * min(frame['width'] / 1280, frame['height'] / 720),
                     point[0] - rect[0] - 2, rect[2] - point[0] - 2,
                     point[1] - rect[1] - 2, rect[3] - point[1] - 2)
        state['shop'] = dict(stage=stage, at=now, settle_until=now + random.uniform(2.15, 2.65))
        host.call('tap', x=round(point[0] + random.uniform(-radius, radius)),
                  y=round(point[1] + random.uniform(-radius, radius)), width=frame['width'], height=frame['height'])
        return report('quest_shop_' + stage)

    try:
        journal = read_journal(directory)
    except (OSError, ValueError):
        return report('quest_shop_journal', 'quest_shop_journal_unreadable')
    pending = journal.get('901030010')
    current = state.get('shop')
    if pending == 'completed':
        if visible(flow['guide']):
            return report('quest_shop_completed', 'quest_shop_already_recorded_for_device')
        return None
    if pending == 'reserved' and not current:
        current = state['shop'] = dict(stage='purchased', at=now, settle_until=now)
    if current and now < current.get('settle_until', 0):
        return report('quest_shop_wait_action')
    if pending == 'reserved':
        if visible(flow['completed']):
            try:
                write_journal(directory, 'completed')
            except (OSError, ValueError):
                return report('quest_shop_journal', 'quest_shop_journal_write_failed')
            state.pop('shop', None)
            return None  # Existing reward handler can now claim the observed Guide.
        if current['stage'] == 'purchased' and visible(flow['merchant']) and not visible(flow['confirmation']):
            return tap(flow['close'], 'verify_result')
        if now - current['at'] >= flow['timeout_sec']:
            return report('quest_shop_verify_result', 'quest_shop_purchase_outcome_unknown')
        return report('quest_shop_verify_result')
    if not current:
        if visible(flow['guide']):
            return tap(flow['open'], 'open')
        return None
    if now - current['at'] >= flow['timeout_sec']:
        return report('quest_shop_' + current['stage'], 'quest_shop_screen_not_advanced')
    if current['stage'] == 'open' and visible(flow['listing']):
        return tap(flow['select'], 'selected')
    if current['stage'] == 'selected' and visible(flow['confirmation']) and match(flow['buy']).get('found'):
        # A crash/transport error after this point has an unknown outcome.
        # Persist before sending any purchase tap and never retry it blindly.
        try:
            write_journal(directory, 'reserved')
        except (OSError, ValueError):
            return report('quest_shop_journal', 'quest_shop_journal_write_failed')
        return tap(flow['buy'], 'purchased')
    return report('quest_shop_wait_' + current['stage'])
