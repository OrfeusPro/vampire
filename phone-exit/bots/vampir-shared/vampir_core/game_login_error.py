"""Only source-verified game LoginResult labels; no retry or route policy."""


def describe_game_login_error(code):
    if type(code) is not int or not 0 <= code <= 0xffffffff:
        raise ValueError('Expected raw uint32 game result code')
    # ResultError_Text 0x1458091b0, native case 58 -> literal 0x1498ff2b0.
    # HEADLESS-RESULT-ERROR-58.md; this does not identify why an IP is blocked.
    if code == 58:
        return ('BlockedIp', 'Доступ с этого IP ограничен сервером.')
    return None
