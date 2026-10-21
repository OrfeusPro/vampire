"""Actual current map-source audit, without live session or game IO."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ReleaseMapProjectionTests(unittest.TestCase):
    def test_current_sources_and_projection_scope(self):
        tool=Path(__file__).parent/'resource-tools/vampir/audit-release-map-projection.py'
        result=subprocess.run([sys.executable,'-X','utf8',str(tool)],capture_output=True,
            text=True,encoding='utf-8',check=True,timeout=120)
        report=json.loads(Path(json.loads(result.stdout)['report']).read_text('utf-8'))
        self.assertEqual(report['source_sha256'],'98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e')
        self.assertEqual(len(report['worlds']),36)
        self.assertEqual(report['tables']['World']['added_columns'],['IsNavMoveLimit'])
        for table in report['tables'].values():
            self.assertEqual(table['changed_previous_fields'],{})
            self.assertEqual(len(table['added_ids']),8)
        self.assertEqual(report['map_ids'],['10','11'])
        self.assertEqual(len(report['anchors']),15)
        sys.path.insert(0,str(Path(__file__).parent/'vampir-shared'))
        from vampir_core.map_position import MapProjection
        MapProjection(report,source_sha256=report['source_sha256'])


if __name__=='__main__':unittest.main()
