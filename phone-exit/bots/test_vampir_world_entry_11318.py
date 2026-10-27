"""Bounded current select/world IO slices; historical nested boundaries stay explicit."""
import json
from pathlib import Path
import unittest
from test_vampir_update_contracts import load,HERE

ROOT=Path('F:/PhoneExit Resources/Vampir')


class WorldEntry11318Tests(unittest.TestCase):
    def test_current_native_io_slices(self):
        report=load('run-clock-world-batch-11318').run(ROOT)[1]['reports']['world']
        self.assertEqual(len(report['cases']),201)
        self.assertTrue({'reserve-prefix','start-result','writer','ping-receiver'}<=
                        {row['kind'] for row in report['cases']})
        self.assertFalse(report['network_used'] or report['profile_activated'])

    def test_unreviewed_export_set_rejected(self):
        context=json.loads((HERE/'knowledge/native-contexts/ping-world-11318.json').read_bytes())
        with self.assertRaisesRegex(ValueError,'exports differ'):
            load('replay-world-entry-11318').verify({k:'0'*64 for k in context['exports']})


if __name__=='__main__':unittest.main()
