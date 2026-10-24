"""Read allowlisted saved display fields; never treat render resolution as UI scale."""
import configparser
import hashlib
from pathlib import Path

DEFAULT = Path('C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Saved/Config/Windows/GameUserSettings.ini')
SECTION = '/Script/Engine.GameUserSettings'
DIMENSIONS = ('ResolutionSizeX', 'ResolutionSizeY', 'LastUserConfirmedResolutionSizeX',
    'LastUserConfirmedResolutionSizeY', 'DesiredScreenWidth', 'DesiredScreenHeight',
    'LastUserConfirmedDesiredScreenWidth', 'LastUserConfirmedDesiredScreenHeight')
MODES = ('FullscreenMode', 'LastConfirmedFullscreenMode')


def collect(path=DEFAULT):
    result = dict(schema=1, source=dict(path=str(path), status='not_found'), saved={}, issues=[],
        ui_scale=dict(status='unresolved_active_setting', value=None),
        limits=['Сохранённое разрешение не является текущим viewport или UI Scale.',
            'Неизвестные параметры не применяются; реальные настройки и профили не изменяются.'])
    try:
        if not path.is_file():
            return result
        with path.open('rb') as stream:
            data = stream.read(262145)
    except OSError:
        result['source']['status'] = 'unreadable'; return result
    if len(data) > 262144:
        result['source']['status'] = 'size_limit'; return result
    result['source'].update(sha256=hashlib.sha256(data).hexdigest(), status='saved_config_only')
    try:
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read_string(data.decode('utf-8-sig'))
    except (configparser.Error, UnicodeError):
        result['source']['status'] = 'invalid_config'; return result
    if SECTION not in parser:
        result['issues'].append('engine_section_not_found'); return result
    values = parser._sections[SECTION]
    for key in DIMENSIONS + MODES:
        value = values.get(key)
        if value is None:
            continue
        if not value.isascii() or not value.isdecimal():
            result['issues'].append('invalid_' + key); continue
        number = int(value)
        if (key in DIMENSIONS and not 0 < number <= 32768) or (key in MODES and number not in (0, 1, 2)):
            result['issues'].append('invalid_' + key); continue
        result['saved'][key] = dict(value=number, section=SECTION, status='saved_not_live_viewport')
    return result
