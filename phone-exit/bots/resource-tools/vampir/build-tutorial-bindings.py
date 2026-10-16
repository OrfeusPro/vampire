"""Bind explicitly observed vision actions to verified tutorial records.

Never turns arbitrary table rows (purchase, salvage, etc.) into executable taps.
"""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(os.environ.get('PHONEEXIT_VAMPIR_RESOURCES', 'F:/PhoneExit Resources/Vampir'))
MODULE = Path(__file__).resolve().parents[2] / 'vampir'
BINDINGS = {
    'tutorial_quest': ('1001002', 'QuestPanel_PanelTouch'),
    'tutorial_drain': ('4002004', 'Deadly_Target'),
    'tutorial_drain_menu': ('4002006', 'Hud_Menu'),
    'tutorial_skill_menu': ('4002008', 'Menu_Skill'),
    'tutorial_drain_select': ('4002010', 'SkillSetting_SecondSkill_Select'),
    'tutorial_drain_effects': ('4002012', 'Skill_Tooltip'),
    'tutorial_auto_drain': ('4002013', 'SkillSetting_SecondSkill_Auto'),
    'tutorial_close_skills': ('4002014', 'SkillSetting_Close'),
    'tutorial_adrenaline': ('4002016', 'Deadly_AdrenalineGauge'),
    'tutorial_adrenaline_buff': ('4002018', 'Deadly_AdrenalineTooltip'),
    'tutorial_bag': ('4003003', 'Hud_Inventory'),
    'tutorial_enhance_bag': ('4007004', 'Hud_Inventory'),
    'tutorial_enhance_select': ('4007007', 'Inventory_EnchantItem'),
    'tutorial_enhance_open': ('4007009', 'ItemInfoPopup_Enchant'),
    'tutorial_enhance_material': ('4007011', 'ItemEnchant_MaterialSlot'),
    'tutorial_enhance_attempt': ('4007012', 'ItemEnchant_Enchant'),
    'tutorial_equipment_select': ('4003007', 'Inventory_EquipmentItem_Class1'),
    'tutorial_equip': ('4003009', 'ItemInfoPopup_Equip'),
    'tutorial_bloodshape_menu': ('4009004', 'Hud_Menu'),
    'tutorial_bloodshape_open': ('4009006', 'Menu_CostumeArmor'),
    'tutorial_bloodshape_class': ('4009008', 'CostumeArmor_ClassIcon'),
    'tutorial_bloodshape_skill': ('4009009', 'CostumeArmor_ClassSkill'),
    'tutorial_bloodshape_select': ('4009011', 'CostumeArmor_SelectCostume_Class1'),
    'tutorial_bloodshape_equip': ('4009012', 'CostumeArmor_EquipCostume'),
}


def main():
    graph = json.loads((ROOT / 'quest-graph/index.json').read_text(encoding='utf-8'))
    config_path = MODULE / 'vision.json'
    config = json.loads(config_path.read_text(encoding='utf-8'))
    sources = {}
    for name in ('Tutorial', 'TutorialStep', 'TutorialUI', 'TutorialStep_Name_en'):
        meta = graph['sources'][name]
        if hashlib.sha256((ROOT / 'table-study' / meta['file']).read_bytes()).hexdigest() != meta['sha256']:
            raise ValueError('Changed source: rebuild quest graph')
        sources[name] = {key: meta[key] for key in ('file', 'entry', 'offset', 'sha256')}
    tutorials = {t['Id']: t for t in graph['tutorials']}
    steps = {s['Id']: s for t in graph['tutorials'] for s in t['steps']}
    bindings = []
    for action in config['tutorial_actions']:
        if action['prompt'] not in BINDINGS:
            raise ValueError('Unreviewed vision action: ' + action['prompt'])
        step_id, key = BINDINGS[action['prompt']]
        step = steps[step_id]
        if step['TaskParam'] != key or not step['ui'] or step['ui']['Key'] != key or not step['dialog_en']:
            raise ValueError('Source binding mismatch: ' + step_id)
        minimum_delay, delay_rows = 0.0, []
        ordered = tutorials[step['TutorialId']]['steps']
        for following in ordered[ordered.index(step) + 1:]:
            if following['TaskType'] != '4' or not following['TaskParam']:
                break
            value = float(following['TaskParam'])
            if not 0 <= value <= 60:
                raise ValueError('Unexpected timing parameter')
            minimum_delay += value
            delay_rows.append(following['Id'])
        ui = step['ui']
        binding = dict(tutorial_id=step['TutorialId'], step_id=step_id, step=int(step['Step']),
                       ui_key=key, wbp=ui['WBPName'], widget=ui['WidgetName'], control=ui['ControlName'],
                       dialog_en=step['dialog_en']['DialogText'], minimum_delay_sec=minimum_delay,
                       delay_records=delay_rows, server_process_request=step['ServerProcessRequest'],
                       provenance=step['provenance'])
        action['source_tutorial'] = binding
        bindings.append(dict(prompt=action['prompt'], target=action['target'], source=binding))
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (MODULE / 'tutorial-reference.json').write_text(json.dumps(dict(sources=sources, bindings=bindings,
        limitations=['Only visually recognized registered actions execute',
                     'Timing rows Type=4 interpreted as minimum waits; native implementation not decompiled',
                     'PC vs Android data version not verified; missing prompt never authorizes a tap']),
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Bound', len(bindings), 'observed actions to source tutorial steps')


if __name__ == '__main__':
    main()
