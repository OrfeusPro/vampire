"""Observed ASCII CPU-input formatting for the compiled Windows Version path.

No CPU query, guessed hardware or emulation dependency. The caller supplies
raw vendor/brand strings from an explicitly selected source. Native trim and
format evidence: HEADLESS-VERSION-CPU-STRING.md.
"""
from dataclasses import dataclass, field

ASCII_SPACE = ' \t\r\n\v\f'


@dataclass(frozen=True, slots=True)
class VersionCpuInput:
    vendor: str = field(repr=False)
    brand: str = field(repr=False)

    def __post_init__(self):
        for value, bound in ((self.vendor, 12), (self.brand, 48)):
            if type(value) is not str or len(value) > bound or any(
                    ord(char) > 127 or (ord(char) < 32 and char not in ASCII_SPACE) or
                    ord(char) == 127 for char in value):
                raise ValueError('Expected bounded ASCII CPU input')

    def text(self):
        """Only ASCII CRT whitespace parity; preserve internal spaces and '|'."""
        return self.vendor.strip(ASCII_SPACE) + '|' + self.brand.strip(ASCII_SPACE)
