"""Independent portal geometry and cross-tile corridor regression cases."""
import copy
import importlib.util
import struct
import unittest
from pathlib import Path
HERE=Path(__file__).parent/'resource-tools/vampir'
spec=importlib.util.spec_from_file_location('linked_path_audit_test',HERE/'audit-recast-linked-path.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

def square(left,neighbor=0):
    vertices=[[left,0.,0.],[left+2,0.,0.],[left+2,0.,2.],[left,0.,2.]]
    raw=bytearray(88+96+32);struct.pack_into('<HHHH',raw,0,7,0,1,4)
    for i,v in enumerate(vertices):struct.pack_into('<3d',raw,88+24*i,*v)
    struct.pack_into('<4H',raw,188,0,1,2,3);struct.pack_into('<HBB',raw,212,1,4,1)
    return bytes(raw),vertices

class LinkedPathTests(unittest.TestCase):
    def test_quantized_external_portal_clips_both_ends(self):
        a,av=square(0.);b,bv=square(2.);polys=[audit.polygons(a),audit.polygons(b)]
        link=dict(source=[0,0],target=[1,0],edge=1,metadata=0,low=64,high=192)
        low,high=audit.portal(link,polys,[av,bv],[link])
        self.assertAlmostEqual(low[2],128/255);self.assertAlmostEqual(high[2],384/255)
        self.assertEqual(low[0],2.);self.assertEqual(high[0],2.)

    def test_special_portal_selects_vertex_from_forward_or_reverse_edge(self):
        polys=[[dict(vertices=[0,1],kind=1)],[dict(vertices=[0,1,2],kind=0)]]
        vertices=[[[1.,2.,3.],[4.,5.,6.]],[[0.,0.,0.]]*3]
        outgoing=dict(source=[0,0],target=[1,0],edge=1,metadata=102,low=0,high=0)
        incoming=dict(source=[1,0],target=[0,0],edge=255,metadata=98,low=0,high=0)
        self.assertEqual(audit.portal(outgoing,polys,vertices,[incoming,outgoing]),[vertices[0][1]]*2)
        self.assertEqual(audit.portal(incoming,polys,vertices,[incoming,outgoing]),[vertices[0][1]]*2)

    def test_cross_tile_path_requires_connected_and_admitted_link(self):
        a,av=square(0.);b,bv=square(2.)
        link=dict(source=[0,0],target=[1,0],edge=1,metadata=0,low=0,high=255)
        case=dict(start=[0,0],end=[1,0],kind='external',name='fixture',
            options=dict(include=65535,exclude=0,travel=[1.]*64,entering=[0.]*64),
            state=dict(vertices=[av,bv],links=[link]),
            result=dict(status=0x40000000,corridor=[[0,0],[1,0]],segment_costs=[0.,2.],total_cost=2.))
        audit.check_corridor([a,b],case)
        for mode in ['missing','excluded','direction']:
            changed=copy.deepcopy(case)
            if mode=='missing':changed['state']['links']=[]
            elif mode=='excluded':changed['options']['exclude']=1
            else:changed['state']['links'][0]['metadata']=0x50
            with self.assertRaises(AssertionError):audit.check_corridor([a,b],changed)

    def test_external_interval_bytes_are_checked_against_matching_geometry(self):
        a,av=square(0.);b,bv=square(2.)
        raw=bytearray(a);struct.pack_into('<H',raw,200+2,0x8000)
        graph=[{'connections':[[0,1,1,0,.5,1.5]]},{'connections':[]}]
        result=audit.expected_external([bytes(raw),b],[0,1],0,graph)
        self.assertEqual(len(result),1);self.assertEqual((result[0]['low'],result[0]['high']),(63,191))

if __name__=='__main__':unittest.main()
