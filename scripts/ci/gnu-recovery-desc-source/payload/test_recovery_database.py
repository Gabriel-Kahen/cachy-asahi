# SPDX-License-Identifier: MIT
"""Portable raw descriptor controls; source only, no checkpoint actor."""
import argparse,base64,copy,hashlib,sys,types,unittest
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,default=HERE.parents[2]if HERE.name=='gnu-immutable-source-native'else None);args,remaining=parser.parse_known_args();sys.argv=[sys.argv[0],*remaining]
if args.source is None:raise ValueError('development controls require explicit --source')
SOURCE=args.source.resolve();LANE=SOURCE/'scripts/ci/gnu-immutable-source-native';raw=(HERE/'recovery_database.py').read_bytes();M=types.ModuleType('_actual_emitted_recovery_database');M.__file__=str(HERE/'recovery_database.py');exec(compile(raw,M.__file__,'exec'),vars(M))
RAW=b'%NAME%\nglibc\n\n%VERSION%\n2.43-1\n\n%INSTALLDATE%\n1234567890\n\n%REASON%\n0\n\n%VALIDATION%\npgp\n\n'
def capture(raw):
 fields,date,normalized=M.parse(raw);return dict(raw_base64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),logical_node=dict(type='file',mode=420,uid=0,gid=0,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),install_date=date,non_date_sha256=M.sha(normalized),parse_error=None)
class Controls(unittest.TestCase):
 def test_numeric_install_date_only_raw_comparison(self):
  first=capture(RAW);after=capture(RAW.replace(b'1234567890',b'99'));value=M.compare(first,after);self.assertTrue(all(value[n]for n in('metadata_equal','field_order_equal','field_values_equal_except_install_date','normalized_bytes_equal')));self.assertEqual(M.parse(RAW)[1],1234567890)
 def test_other_field_order_and_separator_changes_refuse(self):
  for changed in(RAW.replace(b'pgp',b'none'),RAW.replace(b'%REASON%\n0',b'%REASON%\n1'),RAW.replace(b'%REASON%\n0\n\n',b'')+b'%REASON%\n0\n\n'):
   value=M.compare(capture(RAW),capture(changed));self.assertFalse(value['normalized_bytes_equal'])
  for bad in(RAW+b'\n',RAW.replace(b'%NAME%',b'%NAME%\n'),RAW.replace(b'1234567890',b'12\r3'),RAW.replace(b'1234567890',b'9'*20),RAW+b'%INSTALLDATE%\n1\n\n',RAW.replace(b'1234567890',b'-1'),RAW.replace(b'1234567890','１２'.encode()),b'x'*65537):
   with self.subTest(bad=bad[:20]),self.assertRaises((ValueError,UnicodeError)):M.parse(bad)
 def test_metadata_must_remain_exact(self):
  before=capture(RAW)
  for key,bad in(('mode',384),('uid',1),('gid',1),('type','symlink')):
   after=copy.deepcopy(before);after['logical_node'][key]=bad;self.assertFalse(M.compare(before,after)['metadata_equal'])
 def test_source_owned_derivation_wrapper_is_required(self):
  sys.path.insert(0,str(LANE))
  try:
   import fixed_case as F,interruption_case as I,extraction_case as X
   base=F.snapshot(SOURCE/'runtime');self.assertEqual(len(base),667)
   for case in I.CASES:
    self.assertEqual(X.render(base,case,F,'normal'),F.render(base,case))
    for op in('remove-interruption',X.OPERATION):
     out,_=X.render(base,case,F,op);worker=out['immutable/worker.py'];self.assertIn(b'def recovery_database_wrapper(',worker);self.assertIn(b'RECOVERY_DATABASE_BODY=',worker);self.assertIn(b"recovery_database_wrapper(private,module,'remove-interruption')",worker)
     if op==X.OPERATION:self.assertIn(b"recovery_database_wrapper(private,module,'candidate-extraction-interruption')",worker)
     profile=I.profile(case,F.profile(case))if op=='remove-interruption'else X.profile(case,F);self.assertEqual(profile['recovery_database_evidence'],'REQUIRED_BOUNDED_RAW_DESC_V1')
  finally:sys.path.remove(str(LANE))
if __name__=='__main__':unittest.main(verbosity=2)
