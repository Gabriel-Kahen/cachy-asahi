"""Synthetic inode/directory metadata; never opens a guest or child inode."""
import copy,importlib.util,json,struct,unittest
from pathlib import Path
S=Path(__file__).parent
spec=importlib.util.spec_from_file_location('initialized_empty',S/'ssh_empty.py');E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
def block(entries):
 out=bytearray()
 for i,(inode,name,kind)in enumerate(entries):
  width=(8+len(name)+3)//4*4 if i<len(entries)-1 else 4096-len(out)
  out.extend(struct.pack('<IHBB',inode,width,len(name),kind)+name+b'\0'*(width-8-len(name)))
 return bytes(out)
class Reader:
 def __init__(self,extra=None):
  self.row=dict(inode=17,type='directory',mode=0o700,uid=0,gid=0,size=4096,links=2,mtime=123,mtime_ns=456);self.calls=[];self.data=block([(17,b'.',2),(4,b'..',2)]+(extra or []))
 def inode(self,n):
  if n!=17:raise AssertionError('private child inode must never be visited')
  self.calls.append(n);return dict(self.row),b'OPAQUE_INODE_METADATA'
 def chunks(self,row,raw):
  if row['inode']!=17:raise AssertionError('only selected directory metadata')
  yield self.data
class Controls(unittest.TestCase):
 def test_empty_complete_dot_entries_and_same_inode(self):
  r=Reader();v=E.aggregate(r,17,4);self.assertEqual(E.require_empty(v),r.row);self.assertEqual(r.calls,[17,17]);self.assertEqual(v['live_entries_seen'],2)
 def test_nonempty_file_directory_symlink_refuses_without_names_or_children(self):
  for kind in(1,2,7):
   r=Reader([(99,b'PRIVATE_FILENAME_DO_NOT_RETAIN',kind)]);v=E.aggregate(r,17,4);self.assertFalse(v['empty']);self.assertFalse(v['complete']);self.assertEqual(v['non_dot_entries_seen'],1);self.assertEqual(r.calls,[17]);self.assertNotIn('PRIVATE_FILENAME',json.dumps(v));self.assertFalse(v['names_retained']);self.assertEqual(v['child_inodes_visited'],0)
   with self.assertRaises(ValueError):E.require_empty(v)
 def test_wrong_kind_owner_mode_size_or_links_refuses(self):
  for field,value in(('type','symlink'),('mode',0o755),('uid',1000),('gid',1000),('size',0),('size',65540),('links',3)):
   r=Reader();r.row[field]=value
   with self.subTest(field=field,value=value),self.assertRaises(ValueError):E.aggregate(r,17,4)
 def test_bad_dot_parent_duplicate_or_malformed_header_refuses(self):
  entries=[[(18,b'.',2),(4,b'..',2)],[(17,b'.',2),(5,b'..',2)],[(17,b'.',2),(17,b'.',2)],[(17,b'.',2)]]
  for row in entries:
   r=Reader();r.data=block(row)
   with self.assertRaises(ValueError):E.aggregate(r,17,4)
  r=Reader();data=bytearray(r.data);struct.pack_into('<H',data,4,7);r.data=bytes(data)
  with self.assertRaises(ValueError):E.aggregate(r,17,4)
 def test_metadata_replacement_and_unknown_or_private_proof_fields_refuse(self):
  r=Reader();old=r.inode
  def changed(n):
   fields,raw=old(n)
   if len(r.calls)==2:fields['mtime_ns']+=1
   return fields,raw
  r.inode=changed
  with self.assertRaises(ValueError):E.aggregate(r,17,4)
  good=E.aggregate(Reader(),17,4)
  for key,value in(('names_retained',True),('child_inodes_visited',1),('file_payload_chunks_read',True),('complete',False),('unknown','MODEL_PRIVATE')):
   bad=copy.deepcopy(good);bad[key]=value
   with self.assertRaises(ValueError):E.require_empty(bad)
if __name__=='__main__':unittest.main(verbosity=2)
