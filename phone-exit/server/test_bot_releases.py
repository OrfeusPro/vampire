import json
import unittest
from bot_releases import latest_releases


def release(version, bot='lordnine', sha='a'):
    return {'payload': json.dumps({'id': bot, 'version': version, 'sha256': sha * 64}), 'signature': 'test'}


class Releases(unittest.TestCase):
    def test_numeric_versions_and_one_per_bot(self):
        self.assertEqual(latest_releases([release('1.1.2'), release('1.1.10'), release('2.0.0', 'other')]),
                         [release('1.1.10'), release('2.0.0', 'other')])

    def test_old_local_packages_cannot_downgrade_remote(self):
        self.assertEqual(latest_releases([release('1.1.23'), release('1.0.0')]), [release('1.1.23')])

    def test_same_version_must_remain_immutable(self):
        with self.assertRaisesRegex(RuntimeError, 'immutable'):
            latest_releases([release('1.1.23'), release('1.1.23', sha='b')])

    def test_package_paths_reject_invalid_hash(self):
        invalid = release('1.1.23', sha='/')
        with self.assertRaisesRegex(RuntimeError, 'hash'):
            latest_releases([invalid])


if __name__ == '__main__':
    unittest.main()
