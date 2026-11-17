"""Retained actual r89 replay and adversarial pure graph controls; no QEMU."""
import copy,hashlib,importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
C=load('exact_file_chain',HERE/'chain.py');T=load('exact_file_transform',HERE/'transform.py')
class Controls(unittest.TestCase):
 def setUp(self):self.raw=(HERE/'actual-r89-chain.DATA.json').read_bytes();self.rows=json.loads(self.raw)
 def reject(self,edit):
  rows=copy.deepcopy(self.rows);edit(rows)
  with self.assertRaises((ValueError,TypeError)):C.chain(json.dumps(rows).encode(),125042688)
 def test_actual_retained_r89_positive(self):
  v=json.loads((HERE/'provenance.DATA.json').read_bytes());self.assertEqual(C.pin(self.raw),{k:v['actual_chain'][k]for k in('bytes','sha256')});self.assertEqual(len(self.raw),2047);self.assertEqual(C.chain(self.raw,125042688)['status'],'EXACT_TWO_NODE_CHAIN_METADATA_ONLY')
 def test_exact_transform_and_full_byte_inverse(self):
  old=(HERE/'predecessor-recovery.py').read_bytes(),(HERE/'predecessor-observe_initialized.py').read_bytes();new=T.apply(*old);self.assertEqual(T.inverse(*new),old);self.assertEqual(new[1].count(b"R.chain(raw,request['overlay']['pin']['bytes'])"),1)
 def test_predecessor_or_successor_corruption_refuses(self):
  a=(HERE/'predecessor-recovery.py').read_bytes();b=(HERE/'predecessor-observe_initialized.py').read_bytes();self.assertRaises(ValueError,T.apply,a+b' ',b);x,y=T.apply(a,b);self.assertRaises(ValueError,T.inverse,x+b' ',y)
 def test_file_wrapper_filename_and_protocol_refuse(self):
  for i in(0,1):
   for key,val in(('filename','/different'),('format','http'),('virtual-size',7),('dirty-flag',True),('actual-size',1)):
    with self.subTest(i=i,key=key):self.reject(lambda r:r[i]['children'][0]['info'].__setitem__(key,val))
 def test_extra_nested_missing_and_named_children_refuse(self):
  for i in(0,1):
   edits=[lambda r:r[i]['children'].append(copy.deepcopy(r[i]['children'][0])),lambda r:r[i].__setitem__('children',[]),lambda r:r[i]['children'][0].__setitem__('name','backing'),lambda r:r[i]['children'][0]['info'].__setitem__('children',[{}]),lambda r:r[i]['children'][0].__setitem__('extra',{}),lambda r:r[i]['children'][0]['info'].__setitem__('data-file','/other')]
   for edit in edits:self.reject(edit)
 def test_external_backing_encrypted_dirty_corrupt_refuse(self):
  for key,val in(('backing-filename','/other'),('full-backing-filename','/other'),('backing-filename-format','qcow2'),('encrypted',True),('dirty-flag',True),('data-file','/external'),('children',{})):
   self.reject(lambda r:r[0].__setitem__(key,val))
  self.reject(lambda r:r[0]['format-specific']['data'].__setitem__('corrupt',True));self.reject(lambda r:r[1].__setitem__('backing-filename','/extra'))
 def test_topology_formats_geometry_and_allocation_refuse(self):
  for i in(0,1):
   for key,val in(('filename','/other'),('format','file'),('virtual-size',1),('actual-size',True),('actual-size',C.RAW_BYTES+512)):
    self.reject(lambda r:r[i].__setitem__(key,val))
  self.reject(lambda r:r.append(r[-1]));self.reject(lambda r:r.reverse());self.reject(lambda r:r[0].__setitem__('cluster-size',4096))
 def test_unknown_protocol_fields_and_flags_refuse(self):
  self.reject(lambda r:r[0]['children'][0]['info']['format-specific']['data'].__setitem__('external',True));self.reject(lambda r:r[0]['format-specific']['data'].__setitem__('refcount-bits',32));self.reject(lambda r:r[0]['children'][0]['info'].__setitem__('extra',False));self.reject(lambda r:r[0]['format-specific']['data'].__setitem__('corrupt',0));self.reject(lambda r:r[0]['format-specific']['data'].__setitem__('refcount-bits',16.0))
 def test_bad_json_duplicate_nonfinite_and_frame_cap_refuse(self):
  for b in(b'{}',b'[',b'[NaN]',b' '*16385,self.raw.replace(b'"format": "qcow2"',b'"format": "qcow2", "format": "qcow2"')):
   with self.subTest(b=b[:20]),self.assertRaises(ValueError):C.chain(b,125042688)
 def test_root_overlay_pin_eof_is_required(self):
  for n in(None,True,0,125042689,4294967297):self.assertRaises(ValueError,C.chain,self.raw,n)
if __name__=='__main__':unittest.main(verbosity=2)
