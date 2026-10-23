"""Explicit Carnage/F candidate from current preset; no loaded-asset claim."""
from .character_appearance import encode_character_appearance
from .character_create import CharacterCreatePayload
from .world_move_start import SOURCE_SHA256


def carnage_creation_candidate(name, *, source_sha256):
    """User may choose any appearance; inferred decal zeros are explicit policy.

    Evidence: HEADLESS-CREATE-PRESET-OBJECT / HEADLESS-CREATE-PRODUCER /
    HEADLESS-CREATE-APPEARANCE-JSON-KEYS. Not a server-acceptance guarantee.
    """
    if source_sha256 != SOURCE_SHA256 or type(name) is not str or not name or '\0' in name:
        raise ValueError('Unsupported creation candidate source or nickname')
    appearance_json = encode_character_appearance({'Height': 0.4, 'Chest': 0.3,
        'Pelvis': 0.5, 'Shape': 0.4, 'Waist': 0.5, 'Thigh': 0.5, 'Head': 0.5},
        0, source_sha256=source_sha256, key_profile='latin')
    return CharacterCreatePayload(3, name, (1, 8, 16, 9, 2, 2, 2, 9, 0, 0), appearance_json, (0, 0), ())
