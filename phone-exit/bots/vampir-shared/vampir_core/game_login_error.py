"""Only source-verified game LoginResult labels; no retry or route policy."""


def describe_game_login_error(code):
    if type(code) is not int or not 0 <= code <= 0xffffffff:
        raise ValueError('Expected raw uint32 game result code')
    # Current mapper 0x145814800, complete native call; HEADLESS-RELEASE-WIRE-TAG.md.
    if code == 1:
        return ('InvalidPacketVersion', 'Несовместимая версия игровых пакетов.')
    # ResultError_Text 0x1458091b0, native case 58 -> literal 0x1498ff2b0.
    # HEADLESS-RESULT-ERROR-58.md; this does not identify why an IP is blocked.
    if code == 58:
        return ('BlockedIp', 'Доступ с этого IP ограничен сервером.')
    # Current 1457da4e0 dictionary pair; HEADLESS-LIVE-GLOBAL-EU.md.
    # A generic access restriction does not identify its server-side cause.
    if code == 59:
        return ('BlockedInfo', 'Доступ к игровому сервису ограничен сервером.')
    # Complete native mapper 16 -> InvalidState; no particular invalid state inferred.
    # HEADLESS-RESULT-ERROR-16.md / result-error-16-replay.json.
    if code == 16:
        return ('InvalidState', 'Недопустимое состояние при входе.')
    # 1.13.16 dictionary pair and current RU ResultCodeString_Name.csv.
    # HEADLESS-MESSAGE-COMPONENTS-11316.md; no automatic retry/server switch.
    if code == 37:
        return ('CreateRestrictedServer', 'Создание персонажа недоступно на этом сервере.')
    return None
