"""Bind verified Windows platform/CPU inputs into an explicit Version template.

Does not choose AppVersion, server, key, sequence, token or remaining fields.
"""
from dataclasses import replace

from .version_packet import VersionPayload
from .version_cpu import VersionCpuInput
from .windows_version import WindowsVersion


def bind_windows_version_inputs(payload, *, cpu, windows_version):
    """Fill Version+0x28 (Windows_suffix) and +0x38 (CPU text).

    ENnOsType source descriptor form 2 yields Windows. String composition
    order follows Version_Prepare; complete FString concatenation internals
    are not emulated here. None explicitly represents GetVersionExW failure.
    """
    if not isinstance(payload, VersionPayload) or not isinstance(cpu, VersionCpuInput):
        raise TypeError('Expected Version template and explicit CPU inputs')
    if windows_version is not None and not isinstance(windows_version, WindowsVersion):
        raise TypeError('Expected observed Windows version or explicit API failure')
    context = 'Windows_' + (windows_version.suffix() if windows_version is not None else '')
    strings = list(payload.strings)
    for index, value in ((1, context), (2, cpu.text())):
        if strings[index] not in ('', value):
            raise ValueError('Version template conflicts with Windows input context')
        strings[index] = value
    return replace(payload, strings=tuple(strings))
