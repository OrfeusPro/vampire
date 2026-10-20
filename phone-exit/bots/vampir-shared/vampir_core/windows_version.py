"""Windows version input for the bot's own process, using the observed API/layout.

Native source: Version_CombinedSuffix 0x1415c3960, client SHA below. This does
not read a game process or assume the same application compatibility manifest.
"""
from dataclasses import dataclass
import sys

SOURCE_SHA256 = 'c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8'


@dataclass(frozen=True, slots=True)
class WindowsVersion:
    major: int
    minor: int
    build: int
    product_type: int
    suite_mask: int

    def __post_init__(self):
        for value, maximum in ((self.major, 0xffffffff), (self.minor, 0xffffffff),
                (self.build, 0xffffffff), (self.product_type, 255), (self.suite_mask, 65535)):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError('Invalid Windows version field')

    def suffix(self):
        # Native printf uses signed %d for the DWORDs; preserve those raw bits.
        signed = lambda value: value if value < 0x80000000 else value - 0x100000000
        return '.'.join(map(str, (signed(self.major), signed(self.minor), signed(self.build),
            self.product_type, self.suite_mask))) + '.64bit'


def observe_windows_version():
    """Query GetVersionExW once; None means the API returned failure.

    Result is subject to the calling Python process's Windows manifest and
    compatibility policy. It is not advertised as the kernel's newest version
    or the game executable's cached value. No fallback to another API.
    """
    if sys.platform != 'win32': raise RuntimeError('Windows version input requires Windows')
    import ctypes
    if ctypes.sizeof(ctypes.c_void_p) != 8: raise RuntimeError('Windows version input requires a 64-bit process')

    class OsVersionInfoEx(ctypes.Structure):
        _fields_ = [('size', ctypes.c_uint32), ('major', ctypes.c_uint32), ('minor', ctypes.c_uint32),
            ('build', ctypes.c_uint32), ('platform', ctypes.c_uint32), ('service_pack', ctypes.c_uint16 * 128),
            ('service_pack_major', ctypes.c_uint16), ('service_pack_minor', ctypes.c_uint16),
            ('suite_mask', ctypes.c_uint16), ('product_type', ctypes.c_uint8), ('reserved', ctypes.c_uint8)]

    if ctypes.sizeof(OsVersionInfoEx) != 0x11c: raise RuntimeError('Windows version structure layout differs')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    query = kernel.GetVersionExW
    query.argtypes = [ctypes.POINTER(OsVersionInfoEx)]
    query.restype = ctypes.c_int
    value = OsVersionInfoEx()
    value.size = ctypes.sizeof(value)
    if not query(ctypes.byref(value)): return None
    return WindowsVersion(value.major, value.minor, value.build, value.product_type, value.suite_mask)
