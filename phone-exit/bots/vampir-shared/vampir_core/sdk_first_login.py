"""Explicit Fetch -> absent terms -> first SDK profile -> SignIn, once only.

Separate from NID account registration and character creation. Existing login
paths never fall back here. Available terms require a future UI acceptance flow.
"""
from .sdk_fetch import plan_nid_sdk_fetch, SdkFetchSummary
from .sdk_sign_in import plan_nid_sdk_sign_up, plan_nid_sdk_sign_in
from .sdk_sign_in_http import (execute_sdk_fetch, execute_sdk_sign_up, execute_sdk_sign_in, SdkSignInHttpError)
from .sdk_sign_up_response import SdkSignUpData
from .sdk_sign_in_response import SdkSignInData
from .sdk_terms import (plan_basic_terms_read, plan_individual_terms_read,
                        BasicTermsSummary, IndividualTermsSummary)
from .sdk_terms_http import execute_terms_read


class FirstSdkLoginStopped(RuntimeError):
    def __init__(self, kind):
        self.kind = kind
        super().__init__('First SDK login stopped: ' + kind)


def execute_first_sdk_login(*, credential, inputs, terms_country, terms_locale, basic_filtered,
                            route=None, progress=None, check_context=None,
                            _fetch=execute_sdk_fetch, _terms=execute_terms_read,
                            _signup=execute_sdk_sign_up, _signin=execute_sdk_sign_in):
    """All three terms query choices are explicit; no guessed native defaults.

    Fresh Fetch alone owns the challenge classification. Every failed or unknown
    creation attempt stops; another call must start with a new Fetch observation.
    """
    query = dict(constants=inputs['constants'], game_code=inputs['game_code'],
                 country=terms_country, locale=terms_locale, platform=inputs['os_type'])
    basic = plan_basic_terms_read(**query, filtered=basic_filtered)
    individual = plan_individual_terms_read(**query, terms_name='terms_of_service_ko')

    def stage(name):
        if check_context: check_context()
        if progress: progress(name)

    stage('sdk_fetch_player')
    request = plan_nid_sdk_fetch(credential=credential, **inputs)
    created = None
    try:
        fetched = _fetch(request, expected_url=request.url, route=route)
    except SdkSignInHttpError as error:
        if (error.kind, error.status, error.sdk_code) != ('http_status', 400, 1203): raise
        stage('sdk_basic_terms')
        summary = _terms(basic, route=route)
        if type(summary) is not BasicTermsSummary or (summary.state, summary.result_code, summary.terms_count) != ('no_data', -1, 0):
            raise FirstSdkLoginStopped('basic_terms_require_review')
        stage('sdk_individual_terms')
        summary = _terms(individual, route=route)
        if type(summary) is not IndividualTermsSummary or (summary.state, summary.result_code) != ('no_data', -1):
            raise FirstSdkLoginStopped('individual_terms_require_review')
        stage('sdk_first_profile')
        request = plan_nid_sdk_sign_up(credential=credential, **inputs)
        created = _signup(request, expected_url=request.url, route=route)
        if type(created) is not SdkSignUpData or not created.player_id:
            raise FirstSdkLoginStopped('sdk_creation_result_unknown')
    else:
        if type(fetched) is not SdkFetchSummary or fetched.result_object_present is not True:
            raise FirstSdkLoginStopped('fetch_result_unknown')
    stage('sdk_sign_in')
    request = plan_nid_sdk_sign_in(credential=credential, **inputs)
    signed_in = _signin(request, expected_url=request.url, route=route)
    if type(signed_in) is not SdkSignInData or not signed_in.player_id or not signed_in.access_token:
        raise FirstSdkLoginStopped('sdk_sign_in_result_unknown')
    if created is not None and signed_in.player_id != created.player_id:
        raise FirstSdkLoginStopped('sdk_sign_in_player_mismatch')
    return signed_in
