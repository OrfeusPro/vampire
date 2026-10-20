"""Source-bound base NID collector order, requiring explicit proven field values.

Optional DeviceKey/marketing branches are unsupported. No device discovery or IO.
"""

NID_METADATA_KEYS = (
    'I_GameCode', 'I_GameVersion', 'I_TID', 'I_CountryCD', 'I_PID', 'I_ChannelType',
    'I_SDKVersion', 'I_World', 'I_PlatformADID', 'I_ConnectIP', 'I_UDID',
    'I_JoinedCountryCode', 'I_DeviceOSVersion', 'I_DeviceModel', 'I_OS', 'I_Region',
    'I_TimeZone', 'I_LanguageCD', 'I_NMDeviceKey', 'I_NMIDFV', 'I_World',
    'I_NMMarket', 'I_NMNID', 'I_PCSeq', 'I_NMCPU', 'I_NMRAM', 'I_NMVGA',
)


def encode_base_nid_metadata(values, *, user_info_available, optional_device_key, marketing_attribution):
    """Match the observed base collector, including repeated I_World.

    Local policy accepts only bounded strings needing no JSON escaping, since
    native uses a literal %s formatter. Missing fields are skipped, not invented.
    Caller establishes source/freshness; supplying fields does not prove a live
    NID UserInfo object or make metadata alone sufficient for authentication.
    """
    if type(user_info_available) is not bool or type(optional_device_key) is not bool or type(marketing_attribution) is not bool:
        raise TypeError('Explicit NID branch states required')
    if optional_device_key or marketing_attribution:
        raise NotImplementedError('Optional NID collector branches are not supported')
    if type(values) is not dict or len(values) > 64:
        raise ValueError('Expected bounded explicit NID field map')
    if not user_info_available:
        if values: raise ValueError('NID fields supplied without UserInfo')
        return ''
    parts = []
    for key in NID_METADATA_KEYS:
        if key not in values: continue
        value = values[key]
        if type(value) is not str or len(value) > 4096 or any(ord(c) < 32 or c in '"\\' for c in value):
            raise ValueError('Unsupported NID metadata string')
        try: value.encode('utf-8', 'strict')
        except UnicodeError: raise ValueError('Invalid NID metadata Unicode') from None
        parts.append('"' + key + '":"' + value + '"')
    result = '{' + ','.join(parts) + '}'
    if len(result.encode('utf-8')) > 65535: raise ValueError('NID metadata exceeds byte budget')
    return result
