"""Bounded GMC2 UTF-16-unit XOR primitive; no Base64/JSON/key acquisition.

Evidence: HEADLESS-GMC2-XOR.md. Native FString append drops zero output units.
Raw little-endian units preserve unpaired surrogates for the later decoder;
this function does not claim the result is valid Unicode or configuration.
"""
import struct

MAX_XOR_BYTES = 2 * 1024 * 1024
MAX_KEY_BYTES = 8192


def xor_gmc2_utf16_units(source: bytes, key: bytes) -> bytes:
    """Repeat key units, XOR each source unit, omit zero units from output.

    source contains exactly the units supplied to the native source array.
    key contains logical FString key units, excluding its storage terminator.
    Neither argument is implicitly decoded, NUL-trimmed or Base64-decoded.
    Local bounds: source <=2 MiB, nonempty key <=8192 bytes, even byte lengths.
    Empty key is rejected even for empty source; native nonempty-source path
    would divide by zero. Return raw units without a storage terminator.
    """
    if (not isinstance(source, bytes) or len(source) > MAX_XOR_BYTES or len(source) % 2 or
            not isinstance(key, bytes) or not 0 < len(key) <= MAX_KEY_BYTES or len(key) % 2):
        raise ValueError('Invalid GMC2 XOR unit buffers or local budget exceeded')
    keys = [unit[0] for unit in struct.iter_unpack('<H', key)]
    output = bytearray()
    for index, (unit,) in enumerate(struct.iter_unpack('<H', source)):
        value = unit ^ keys[index % len(keys)]
        if value:
            output.extend(struct.pack('<H', value))
    return bytes(output)
