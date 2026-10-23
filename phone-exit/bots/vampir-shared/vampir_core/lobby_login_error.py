"""Source-verified lobby labels, separate from game results and Winsock codes."""


def describe_lobby_login_error(code):
    if type(code) is not int or not 0<=code<=0xffffffff:
        raise ValueError('Expected raw uint32 lobby result code')
    # Historical 1458050e0; current 145810700 (SHA 98802d...),
    # HEADLESS-RELEASE-LOBBY-ERRORS.md. Both explicit replay paths verified.
    # No automatic retry, table override or particular server cause inferred.
    if code==10036:
        return ('IsInspect','Сервер сообщил о технических работах.')
    if code==10048:
        return ('BlockedInfo','Доступ к игре ограничен сервером.')
    return None
