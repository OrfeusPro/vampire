"""One offline runtime admission suite; HTTP, auth and owners never start externally."""
import unittest
from test_vampir_game_runtime_11318 import CurrentRuntimeProfileTests
from test_vampir_live_runtime_11318 import LiveRuntime11318Tests
from test_vampir_probe_runtime_11318 import ProbeRuntime11318Tests
from test_vampir_candidate_cdn_11318 import CandidateCdn11318Tests
from test_vampir_bounded_owner_11318 import BoundedOwner11318Tests


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(loader.loadTestsFromTestCase(case) for case in (
        CurrentRuntimeProfileTests,LiveRuntime11318Tests,ProbeRuntime11318Tests,
        CandidateCdn11318Tests,BoundedOwner11318Tests))


if __name__=='__main__':unittest.main()
