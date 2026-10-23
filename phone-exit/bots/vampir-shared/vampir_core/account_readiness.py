"""Read-only account checklist from saved observations; never infers live access."""


def account_readiness(account, catalogs, character_lists):
    catalog = catalogs.get(account['region'])
    server = next((row for row in (catalog or {}).get('servers', [])
                   if row['id'] == account.get('server_id')), None)
    listing = character_lists.get('|'.join(map(str, (account['id'], account['region'], account.get('server_id')))))
    characters = listing['characters'] if listing is not None else None
    selected = next((row for row in characters or []
                     if account.get('character_key') is not None and row['key'] == account['character_key']), None)
    confirmed = account.get('registration_status') in ('registered', 'nid_verified', 'sdk_created')
    steps = [dict(id='netmarble', observed=confirmed, text='Регистрация или вход Netmarble подтверждены'),
             dict(id='sdk', observed=account.get('registration_status') == 'sdk_created', text='Вход игрового SDK подтверждён'),
             dict(id='catalog', observed=catalog is not None, text='Каталог региона сохранён'),
             dict(id='server', observed=server is not None and not server.get('excluded'), text='Сервер назначен из сохранённого каталога'),
             dict(id='characters', observed=listing is not None, text='Список персонажей сохранён для этого сервера'),
             dict(id='character', observed=selected is not None, text='Назначенный персонаж найден по серверному ключу')]
    if not confirmed:
        next_step = 'Проверить обычный вход Netmarble; неизвестный статус не означает, что аккаунта нет.'
    elif catalog is None:
        next_step = 'После восстановления доступа загрузить серверы выбранного региона.'
    elif server is None or server.get('excluded'):
        next_step = 'Выбрать доступный сервер и сохранить настройки.'
    elif listing is None:
        next_step = 'При доступе к серверу войти и прочитать персонажей.'
    elif characters:
        next_step = 'Персонажи уже есть: выбрать существующего; нового не создавать.' if selected is None else 'Персонаж назначен; живой вход проверяется отдельно.'
    else:
        next_step = 'Сохранён пустой список: настроить класс и ник. Перед созданием бот снова проверит список.'
    return dict(steps=steps, next_step=next_step, route='direct',
                route_text='Прямой выход ПК; выбор региона не включает VPN.',
                live_access_verified=False, catalog_observed_utc=(catalog or {}).get('observed_utc'),
                characters_observed_utc=(listing or {}).get('observed_utc'))
