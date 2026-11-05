"""Explicit per-bot inputs, independent of the transport's observed public address."""
from dataclasses import replace
from .nid_metadata import _metadata_text
from .version_cpu import VersionCpuInput
from .windows_version import WindowsVersion
import secrets

KEYS = ('device_key', 'nm_device_key', 'nid_device_key')
METADATA_FIELDS = ('I_DeviceModel', 'I_DeviceOSVersion', 'I_TimeZone', 'I_LanguageCD',
                   'I_NMCPU', 'I_NMRAM', 'I_NMVGA')

def connection_presets():
    return [dict(id='default', name='По умолчанию · текущий ПК / прямой выход',
                 device_profile='current-pc', device_settings={}, socks_port=None)]


def new_identity():
    return {key: secrets.token_hex(16) for key in KEYS}


def metadata_values(value):
    settings = validate(value)
    result = dict(settings.get('metadata', {}))
    if 'cpu' in settings: result['I_NMCPU'] = VersionCpuInput(**settings['cpu']).text()
    if 'windows' in settings: result['I_DeviceOSVersion'] = WindowsVersion(**settings['windows']).suffix()
    return result


def validate(value=None):
    if value is None: value = {}
    if type(value) is not dict or set(value) - {'identity', 'metadata', 'cpu', 'windows'}:
        raise ValueError('Unknown device setting')
    result = {}
    identity = value.get('identity', {})
    if type(identity) is not dict or (identity and set(identity) != set(KEYS)):
        raise ValueError('Укажите все три отдельных ключа устройства или оставьте все пустыми')
    if identity:
        for key in KEYS:
            text = identity[key]
            if type(text) is not str or not 1 <= len(text) <= 128 or not text.isascii() or not text.isalnum():
                raise ValueError('Ключ устройства: 1–128 латинских букв или цифр')
        result['identity'] = dict(identity)
    metadata = value.get('metadata', {})
    if type(metadata) is not dict or set(metadata) - set(METADATA_FIELDS):
        raise ValueError('Unsupported device metadata field')
    if metadata:
        result['metadata'] = {key: _metadata_text(text) for key, text in metadata.items()}
    if 'cpu' in value:
        cpu = value['cpu']
        if type(cpu) is not dict or set(cpu) != {'vendor', 'brand'}: raise ValueError('Invalid CPU settings')
        VersionCpuInput(**cpu); result['cpu'] = dict(cpu)
    if 'windows' in value:
        windows = value['windows']
        if type(windows) is not dict or set(windows) != {'major', 'minor', 'build', 'product_type', 'suite_mask'}:
            raise ValueError('Invalid Windows settings')
        WindowsVersion(**windows); result['windows'] = dict(windows)
    return result


def apply_binding(binding, value):
    settings = validate(value)
    if binding.confirmation == 'required': raise PermissionError('Device confirmation is required')
    if not settings.get('identity'): return binding
    # Preserve the original registry record. Explicit alternate identity is not a confirmed device.
    return replace(binding, **settings['identity'], confirmation='unknown', confirmation_evidence='',
                   identity_source='Explicit bot profile', nid_identity_source='Explicit bot profile')


def apply_system(cpu, windows, value):
    settings = validate(value)
    return (VersionCpuInput(**settings['cpu']) if 'cpu' in settings else cpu,
            WindowsVersion(**settings['windows']) if 'windows' in settings else windows)


def route_port(value):
    if value is not None and (type(value) is not int or not 1 <= value <= 65535):
        raise ValueError('SOCKS port must be 1..65535 or empty for direct access')
    return value
