"""Curated semantic links backed by exact localized statements, not native formulas."""


def build(entries):
    by_key = {e['enum']['name'].split('::')[-1]: e for e in entries if e['enum']}
    relations = []

    def add(source, target, text, statement, kind='modifier', evidence_key=None):
        a, b = by_key[source], by_key[target]
        evidence = by_key[evidence_key or source]
        if evidence['description'] != statement:
            raise ValueError('Changed dependency description: '+(evidence_key or source))
        relations.append(dict(source=a['id'], target=b['id'], kind=kind, explanation=text,
            evidence=dict(level='client_description', statement=statement,
                          record=evidence['name_source'], parameter=evidence['row']),
            formula=None, native_formula_verified=False, runtime_verified=False))

    for source, target, text, statement in [
        ('HpRecoveryMultiplier', 'HpRecovery', 'Увеличивает естественное восстановление HP на процент. Порядок применения и масштаб коэффициента не установлены.', 'Increases the Natural HP Recovery Amount by a percentage.'),
        ('MpRecoveryMultiplier', 'MpRecovery', 'Увеличивает естественное восстановление MP на процент. Порядок применения и масштаб коэффициента не установлены.', 'Increases Natural MP Recovery Amount by a percentage.'),
        ('HpPotionRecoveryMultiplier', 'HpPotionRecovery', 'Усиливает количество HP, восстанавливаемое зельями. Не доказано, что множитель применяется только к добавке этого стата.', 'Increases HP Recovery Amount by a percentage when using HP Recovery Potions.'),
        ('MpPotionRecoveryMultiplier', 'MpPotionRecovery', 'Усиливает количество MP, восстанавливаемое зельями. Не доказано, что множитель применяется только к добавке этого стата.', 'Increases MP Recovery Amount by a percentage when using MP Recovery Potions.'),
        ('ItemDropRateMultiplier', 'ItemDropRate', 'Увеличивает показатель выпадения предметов на процент. Итоговый шанс и пределы из описания не следуют.', 'Increases Item Drop Rate by a percentage.'),
        ('MoveSpeedMultiplier', 'MoveSpeed', 'Увеличивает скорость передвижения персонажа. Формула пересчёта не восстановлена.', 'Increases player MOV SPD.'),
        ('HealMultiplier', 'HealValue', 'Процентное усиление и добавка к лечению участвуют в величине лечения HP-навыками. База, порядок сложения и умножения неизвестны.', 'Increases healing amount of HP Recovery Skills by a percentage.'),
        ('ReceiveHealMultiplier', 'HealValue', 'Усиливает получаемое лечение у получателя. Это другая роль участника боя; прямое изменение HealValue не подтверждено.', 'Increases the healing amount received from HP Recovery Skills by a percentage.'),
    ]:
        add(source, target, text, statement)
    add('HitValue', 'DodgeValue', 'Точность атакующего сравнивается с уклонением цели при расчёте попадания. Это взаимодействие двух участников, а не изменение EVA от ACC.',
        "Increases the chance to hit a target with attacks.\r\nHit Rate is determined by the difference to the opponent's EVA.", 'opposed')
    add('DefensePower', 'AttackPower', 'Защита получателя сравнивается с атакой противника при расчёте входящего урона. Это взаимодействие, а не прибавка к ATK.',
        "DEF that decreases incoming DMG from opponents.\r\nDMG taken additionally increases or decreases based on the difference to the opponent's ATK.", 'opposed')
    add('CriticalResistanceRate', 'CriticalRate', 'Сопротивление получателя уменьшает входящий критический шанс противника. Вычитание один к одному, пороги и итоговая формула не подтверждены.',
        'Decreases incoming CRIT Rate from opponents.', 'opposed')
    add('IgnoreCriticalDamageMultiplier', 'CriticalDamageMultiplier', 'Уменьшает входящий критический урон противника на процент. Это противодействие усилению критического урона, не изменение стата атакующего. Порядок расчёта неизвестен.',
        'Decreases incoming CRIT DMG from opponents by a percentage.', 'opposed')
    add('CharacterAntiDeadlySkillFireRate', 'CharacterDeadlySkillFireRate', 'Подавляет шанс активации PvP Drain у противника. Формула и пределы подавления не установлены.',
        "Negates the opponent's PvP Drain Skill Activation Chance.", 'opposed')
    return relations
