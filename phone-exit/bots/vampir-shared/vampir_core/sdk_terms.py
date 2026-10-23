"""Bounded BasicTerms read plan/summary; never consent or SDK player creation.

Source: HEADLESS-RELEASE-BASIC-TERMS-RESPONSE.md. Query inputs are explicit;
no locale/country fallback or official-client cache acquisition is performed.
"""
from dataclasses import dataclass, field
import json
import re
from urllib.parse import urlencode

from .sdk_config import lookup_sdk_url_value
from .sdk_sign_in_response import _object_pairs, _invalid_constant


@dataclass(frozen=True, slots=True)
class BasicTermsReadPlan:
    url: str = field(repr=False)
    method: str = 'GET'


@dataclass(frozen=True, slots=True)
class IndividualTermsReadPlan:
    url: str = field(repr=False)
    method: str = 'GET'


@dataclass(frozen=True, slots=True)
class BasicTermsSummary:
    state: str
    result_code: int
    terms_count: int
    consent_confirmed: bool = False
    sdk_creation_ready: bool = False


@dataclass(frozen=True, slots=True)
class IndividualTermsSummary:
    state: str
    result_code: int
    consent_confirmed: bool = False


def _validate_terms_inputs(constants, game_code, country, locale, platform):
    if lookup_sdk_url_value(constants, 'termsUrl') != 'https://terms-api.netmarble.com':
        raise ValueError('Unsupported explicit terms endpoint')
    if type(game_code) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', game_code):
        raise ValueError('Invalid terms game code')
    if type(country) is not str or not re.fullmatch(r'[A-Z]{2}', country):
        raise ValueError('Invalid explicit terms country')
    if type(locale) is not str or not re.fullmatch(r'[A-Za-z]{2,8}(?:-[A-Za-z0-9]{2,8}){0,3}', locale):
        raise ValueError('Invalid explicit terms locale')
    if platform != 'PC':
        raise ValueError('Explicit supported terms platform required')


def plan_basic_terms_read(*, constants, game_code, country, locale, platform, filtered):
    """Current public production endpoint only; local restrictive query policy."""
    _validate_terms_inputs(constants, game_code, country, locale, platform)
    if type(filtered) is not bool:
        raise ValueError('Explicit supported terms platform/branch required')
    suffix = '/filtered/unique' if filtered else ''
    query = urlencode(dict(country=country, locale=locale, platform=platform))
    return BasicTermsReadPlan(f'https://terms-api.netmarble.com/game/v2/{game_code}/terms{suffix}?{query}')


def plan_individual_terms_read(*, constants, game_code, country, locale, platform, terms_name):
    """No-player-ID branch only; exact current game argument and termsType getter.

    Existing-player agreementUrl branch and response/UI handling remain separate.
    Source: HEADLESS-RELEASE-INDIVIDUAL-TERMS-DISPATCH.md.
    """
    _validate_terms_inputs(constants, game_code, country, locale, platform)
    if terms_name != 'terms_of_service_ko':
        raise ValueError('Unsupported explicit individual terms name')
    query = urlencode(dict(country=country, locale=locale, termsType='I', platform=platform))
    return IndividualTermsReadPlan(f'https://terms-api.netmarble.com/game/v2/{game_code}/terms/{terms_name}?{query}')


def parse_basic_terms_summary(*, status, body):
    """Do not expose raw term URLs/text or treat NO DATA as accepted consent.

    Native has optional/coercing JSON getters. This local subset is stricter:
    explicit integer resultCode, resultData object and bounded terms array.
    """
    if type(status) is not int or not 200 <= status <= 206:
        raise ValueError('Terms HTTP status rejected')
    if type(body) is not bytes or not 0 < len(body) <= 524288:
        raise ValueError('Invalid terms response size')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_object_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid terms JSON') from None
    if type(value) is not dict or type(value.get('resultCode')) is not int:
        raise ValueError('Terms requires explicit integer resultCode')
    code = value['resultCode']
    data = value.get('resultData')
    terms = data.get('terms') if type(data) is dict else None
    if type(terms) is not list or len(terms) > 256 or any(type(row) is not dict for row in terms):
        raise ValueError('Invalid bounded terms array')
    if code == -1 and not terms:
        state = 'no_data'
    elif code == 0:
        state = 'terms_available' if terms else 'empty'
    else:
        raise ValueError('Unsupported terms result')
    return BasicTermsSummary(state, code, len(terms))


def parse_individual_terms_summary(*, status, body):
    """Strict current object shape; no term text, URLs or acceptance are returned."""
    if type(status) is not int or not 200 <= status <= 206:
        raise ValueError('Individual terms HTTP status rejected')
    if type(body) is not bytes or not 0 < len(body) <= 524288:
        raise ValueError('Invalid individual terms response size')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_object_pairs, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid individual terms JSON') from None
    if type(value) is not dict or type(value.get('resultCode')) is not int:
        raise ValueError('Individual terms requires integer resultCode')
    data = value.get('resultData')
    terms = data.get('terms') if type(data) is dict else None
    fields = {'title', 'url', 'required', 'contentExists', 'useAgree', 'useNotice',
              'agreeNotice', 'disagreeNotice', 'termsCode', 'imageContent'}
    if type(terms) is not dict or set(terms) != fields:
        raise ValueError('Unsupported individual terms object')
    if value['resultCode'] == -1 and all(item is None for item in terms.values()):
        return IndividualTermsSummary('no_data', -1)
    if value['resultCode'] == 0:
        # Content/UI interpretation remains separate; the first-login flow stops.
        return IndividualTermsSummary('terms_available', 0)
    raise ValueError('Unsupported individual terms result')
