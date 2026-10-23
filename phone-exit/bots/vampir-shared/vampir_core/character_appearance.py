"""Current numeric appearance keys; caller explicitly chooses Latin key rules."""
import json
import math
import struct

from .world_move_start import SOURCE_SHA256

GROUP_IDS = {'Height': 1, 'Chest': 2, 'Pelvis': 3, 'Shape': 4,
             'Waist': 5, 'Thigh': 6, 'Head': 7}


def encode_character_appearance(settings, voice, *, source_sha256, key_profile):
    """Encode numeric semantics, without claiming native JSON byte formatting.

    No range or server-acceptance claim: the caller supplies selected settings.
    Latin keys are an explicit client policy; live engine culture is not inferred.
    """
    if source_sha256 != SOURCE_SHA256 or key_profile != 'latin':
        raise ValueError('Unsupported appearance source or numeric key profile')
    if type(settings) is not dict or len(settings) > 7:
        raise ValueError('Invalid appearance settings')
    if type(voice) is not int or not 0 <= voice <= 255:
        raise ValueError('Invalid appearance voice byte')
    values = {}
    for name, value in settings.items():
        if name not in GROUP_IDS or type(value) not in (int, float):
            raise ValueError('Unknown appearance setting or nonnumeric value')
        try:
            rounded = struct.unpack('<f', struct.pack('<f', value))[0]
        except (OverflowError, struct.error) as error:
            raise ValueError('Appearance value exceeds float32') from error
        if not math.isfinite(rounded):
            raise ValueError('Appearance value must be finite')
        values[str(GROUP_IDS[name])] = rounded
    values['VoiceType'] = voice
    return json.dumps(values, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
