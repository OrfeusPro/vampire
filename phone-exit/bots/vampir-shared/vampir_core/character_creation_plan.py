"""Local creation choices; no packet IDs, game calls or guessed wire class values."""
import secrets

# Human choices from the extracted Class / ClassName catalogue, not wire IDs.
# maps/catalog-classes.json SHA256 5af03a839e38ada2e1e247da6b5b22c6bb116496bc816be572c7f19c188b768e.
# Source EXE c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8;
# Class entry 36 records 2..6, ClassName-en entry 401 records 2..6.
CLASS_CHOICES = (('DarkMage', 'Viper'), ('Reaper', 'Grim Reaper'), ('Gunner', 'Carnage'),
                 ('SwordMan', 'Bloodstained'), ('Fighter', 'Akasha'))
DEFAULT_CLASS = 'Gunner'
MAX_NAME_ATTEMPTS = 5


def random_nickname(excluded=()):
    """Ten ASCII letters is a local proposal; server eligibility is not established."""
    used = {name.casefold() for name in excluded}
    for _ in range(128):
        name = ''.join(secrets.choice('bcdfghklmnprstvz') + secrets.choice('aeiou') for _ in range(5)).capitalize()
        if name.casefold() not in used:
            return name
    raise RuntimeError('Unable to propose an unused nickname')
