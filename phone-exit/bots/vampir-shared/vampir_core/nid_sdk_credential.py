"""Provider email credential to the observed SDK credential object, without I/O.

Provider channel 20 is distinct from SDK credential channelCode 33. This object
is an input to SDK sign-in, not its HTTP request, server token or game session.
"""
from dataclasses import dataclass, field

from .nid_result import NidEmailCredential, validate_nid_email_result_fields


@dataclass(frozen=True, slots=True)
class NidSdkCredential:
    channel_access_token: str = field(repr=False)
    channel_code: int = field(default=33, init=False)

    def as_object(self) -> dict[str, str | int]:
        """Return a fresh object containing the two observed GetObject fields."""
        return dict(channelAccessToken=self.channel_access_token, channelCode=self.channel_code)


def build_nid_sdk_credential(email: NidEmailCredential) -> NidSdkCredential:
    if not isinstance(email, NidEmailCredential) or email.channel_type != 20:
        raise ValueError('Expected an explicitly validated NID email credential')
    checked = validate_nid_email_result_fields(dict(resultCode='0', channelKey='mailUserKey',
        accessToken=email.access_token, refreshToken=email.refresh_token,
        netmarbleId=email.netmarble_id, joinedCountryCode=email.joined_country_code))
    return NidSdkCredential(checked.access_token)
