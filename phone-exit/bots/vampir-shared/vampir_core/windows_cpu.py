"""Read CPU vendor/brand through the bot's own small, hash-checked Windows DLL."""
import hashlib
from pathlib import Path
import sys

from .version_cpu import VersionCpuInput


def observe_windows_cpu(library_path, *, expected_sha256):
    """Only CPUID; no game process, registry fallback or hardware generation.

    The owner supplies the trusted build receipt's hash. The DLL must be built
    before runtime; no compiler, analysis tools or downloaded code is loaded.
    """
    if sys.platform != 'win32': raise RuntimeError('CPU input reader requires Windows')
    import ctypes
    if ctypes.sizeof(ctypes.c_void_p) != 8: raise RuntimeError('CPU input reader requires a 64-bit process')
    if (type(expected_sha256) is not str or len(expected_sha256) != 64 or
            any(char not in '0123456789abcdef' for char in expected_sha256)):
        raise ValueError('Expected explicit SHA256 of the CPU input library')
    path = Path(library_path).resolve(strict=True)
    if not path.is_file() or path.suffix.lower() != '.dll' or path.stat().st_size > 1048576:
        raise ValueError('Invalid CPU input library')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != expected_sha256: raise ValueError('CPU input library hash differs from build receipt')
    library = ctypes.WinDLL(str(path))
    query = library.vampir_read_cpu
    query.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_uint32, ctypes.POINTER(ctypes.c_char), ctypes.c_uint32]
    query.restype = ctypes.c_int
    vendor = ctypes.create_string_buffer(13)
    brand = ctypes.create_string_buffer(49)
    if query(vendor, len(vendor), brand, len(brand)) != 1:
        raise RuntimeError('CPU input library could not read the explicit buffers')
    if vendor.raw[-1:] != b'\0' or brand.raw[-1:] != b'\0':
        raise ValueError('CPU input library returned unterminated fields')
    try:
        return VersionCpuInput(vendor.value.decode('ascii'), brand.value.decode('ascii'))
    except UnicodeError:
        raise ValueError('CPU input is outside the verified ASCII profile') from None
