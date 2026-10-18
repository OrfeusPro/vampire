"""Pipeline orchestration: use projected points and withhold incomplete lines."""
import importlib.util
import unittest
from pathlib import Path
p=Path(__file__).parent/'resource-tools/vampir/recast-navigation-pipeline.py'
s=importlib.util.spec_from_file_location('pipeline_policy_tests',p);native=importlib.util.module_from_spec(s);s.loader.exec_module(native)

def route(status=0x40000000):
    return dict(start_projection=dict(polygon=[0,0],point_nav=[1.,2.,3.]),
        end_projection=dict(polygon=[1,0],point_nav=[4.,5.,6.]),
        corridor_query=dict(status=status,corridor=[[0,0],[1,0]]))

class NavigationPipelineTests(unittest.TestCase):
    def test_line_receives_projected_coordinates_not_requested_offsets(self):
        instance=object.__new__(native.NavigationPipelineEmulator);calls=[]
        instance.route_between_points=lambda *args:route()
        def straight(*args):calls.append(args);return dict(status=0x40000000,points=[])
        instance.straight=straight
        result=instance.navigate([1.,22.,3.],[4.,-15.,6.],[25.,50.,25.],1)
        self.assertEqual(calls,[([[0,0],[1,0]],[1.,2.,3.],[4.,5.,6.],1)])
        self.assertEqual(result['stage'],'line_built');self.assertFalse(result['movement_verified'])

    def test_partial_and_failed_corridors_never_produce_goal_line(self):
        instance=object.__new__(native.NavigationPipelineEmulator)
        def forbidden(*args):raise AssertionError('Must not construct a line to an unreachable target')
        instance.straight=forbidden
        for status,stage in [(0x40000040,'partial_corridor'),(0x80000008,'query_failed')]:
            instance.route_between_points=lambda *args:route(status)
            result=instance.navigate([1.,2.,3.],[4.,5.,6.],[25.,50.,25.])
            self.assertEqual(result['stage'],stage);self.assertIsNone(result['line'])

    def test_missing_projection_does_not_start_polygon_query(self):
        instance=object.__new__(native.NavigationPipelineEmulator)
        projections=iter([dict(polygon=None,point_nav=None),dict(polygon=[0,0],point_nav=[1.,2.,3.])])
        instance.project=lambda *args:next(projections)
        def forbidden(*args):raise AssertionError('Must not search without both projected refs')
        instance.search_prepared=forbidden;instance.straight=forbidden
        result=instance.navigate([0.,0.,0.],[1.,2.,3.],[25.,50.,25.])
        self.assertEqual(result['stage'],'projection_missing');self.assertIsNone(result['corridor_query']);self.assertIsNone(result['line'])

    def test_unreviewed_line_option_rejected_before_any_stage_runs(self):
        instance=object.__new__(native.NavigationPipelineEmulator)
        with self.assertRaises(ValueError):instance.navigate([0.,0.,0.],[1.,2.,3.],[25.,50.,25.],2)

if __name__=='__main__':unittest.main()
