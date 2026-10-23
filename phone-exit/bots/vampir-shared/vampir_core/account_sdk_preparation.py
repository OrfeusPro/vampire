"""Validation for the separate, explicit first SDK login console operation."""
import re


def validate_sdk_preparation(account, *, country, locale, mode):
    if account['registration_status'] == 'sdk_created':
        raise ValueError('Профиль SDK уже подтверждён. Используйте обычный вход.')
    if account.get('character_key') is not None or account.get('character_index') is not None:
        raise ValueError('Персонаж уже назначен. Используйте обычный вход.')
    if type(country) is not str or not re.fullmatch(r'[A-Z]{2}', country):
        raise ValueError('Укажите страну условий двумя заглавными буквами.')
    if type(locale) is not str or not re.fullmatch(r'[A-Za-z]{2,8}(?:-[A-Za-z0-9]{2,8}){0,3}', locale):
        raise ValueError('Укажите язык условий, например en-US.')
    if mode not in ('all', 'filtered-unique'):
        raise ValueError('Выберите вариант запроса условий.')
    return mode == 'filtered-unique'
