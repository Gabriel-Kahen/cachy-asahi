#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""No host NM modifications: state/failure tests plus genuine offline keyfile roundtrip."""
import configparser,copy,fcntl,hashlib,importlib.machinery,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).absolute().parent
loader=importlib.machinery.SourceFileLoader('dns',str(HERE/'cachy-asahi-dns'));spec=importlib.util.spec_from_loader(loader.name,loader);D=importlib.util.module_from_spec(spec);loader.exec_module(D)
UUID='11111111-2222-4333-8444-555555555555'

class MemoryNM:
 def __init__(self):self.values={'ipv4.dns':['192.0.2.53'],'ipv4.ignore-auto-dns':'no','ipv6.dns':['2001:db8::53'],'ipv6.ignore-auto-dns':'no','vpn.secret':'never-query-or-save','ipv4.dns-priority':-50};self.calls=[];self.failure=None
 def read(self,connection,fields):
  if connection!=UUID:raise D.Refusal('connection absent')
  return copy.deepcopy({f:self.values[f]for f in fields})
 def modify(self,connection,changes):
  self.calls.append((connection,copy.deepcopy(changes)))
  if self.failure=='before':raise D.Refusal('authorization failed')
  self.values.update(copy.deepcopy(changes))
  if self.failure=='after':raise D.Refusal('outcome unknown')

class WorkflowTests(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory(prefix='dns-tests-');self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'change';self.nm=MemoryNM();self.request={'ipv4.dns':['1.1.1.1','9.9.9.9'],'ipv4.ignore-auto-dns':'yes'}
 def plan(self,changes=None):return D.preview(self.path,UUID,changes or self.request,self.nm)
 def apply(self,plan):return D.change(self.path,plan['receipt_sha256'],confirm='APPLY_CONNECTION_DNS',nm=self.nm)
 def undo(self,applied):return D.change(self.path,applied['receipt_sha256'],True,'RESTORE_CONNECTION_DNS',self.nm)
 def test_preview_is_private_minimal_and_nonmutating(self):
  before=copy.deepcopy(self.nm.values);p=self.plan();self.assertEqual(self.nm.values,before);self.assertEqual(self.nm.calls,[]);self.assertEqual(self.path.stat().st_mode&0o777,0o700)
  raw=(self.path/'receipt.json').read_bytes();self.assertEqual((self.path/'receipt.json').stat().st_mode&0o777,0o600);self.assertNotIn(b'never-query',raw);self.assertNotIn(b'ipv6',raw);self.assertEqual(p['receipt_sha256'],D.sha(raw))
 def test_apply_undo_and_repeats_preserve_unowned_settings(self):
  old=copy.deepcopy(self.nm.values);p=self.plan();a=self.apply(p);self.assertEqual(self.nm.values['ipv4.dns'],self.request['ipv4.dns']);self.assertEqual(len(self.nm.calls),1)
  self.assertEqual(self.apply(a)['status'],'ALREADY_APPLIED');self.assertEqual(len(self.nm.calls),1)
  self.nm.values['ipv6.dns']=['2001:db8::99'];u=self.undo(a);self.assertEqual(self.nm.values['ipv4.dns'],old['ipv4.dns']);self.assertEqual(self.nm.values['ipv6.dns'],['2001:db8::99']);self.assertEqual(self.nm.values['vpn.secret'],old['vpn.secret']);self.assertEqual(self.nm.values['ipv4.dns-priority'],-50)
  self.assertEqual(self.undo(u)['status'],'ALREADY_UNDONE');self.assertEqual(len(self.nm.calls),2)
 def test_noop_needs_no_modification(self):
  a=self.apply(self.plan({'ipv4.dns':['192.0.2.53']}));self.undo(a);self.assertEqual(self.nm.calls,[])
 def test_single_ipv6_property_and_clear_are_exact(self):
  a=self.apply(self.plan({'ipv6.dns':[]}));self.assertEqual(self.nm.calls[-1][1],{'ipv6.dns':[]});self.undo(a);self.assertEqual(self.nm.values['ipv6.dns'],['2001:db8::53'])
 def test_drift_after_preview_refuses_before_mutation(self):
  p=self.plan();self.nm.values['ipv4.dns']=['8.8.8.8']
  with self.assertRaisesRegex(D.Refusal,'later edits preserved'):self.apply(p)
  self.assertEqual(self.nm.calls,[])
 def test_later_owned_edit_blocks_undo_without_overwrite(self):
  a=self.apply(self.plan());self.nm.values['ipv4.ignore-auto-dns']='no';before=copy.deepcopy(self.nm.values)
  with self.assertRaisesRegex(D.Refusal,'later edits preserved'):self.undo(a)
  self.assertEqual(self.nm.values,before);self.assertEqual(len(self.nm.calls),1)
 def test_failed_and_uncertain_modifications_never_auto_retry_or_rollback(self):
  for failure in('before','after'):
   with self.subTest(failure=failure):
    self.path=Path(self.temp.name)/failure;self.nm=MemoryNM();p=self.plan();self.nm.failure=failure
    with self.assertRaises(D.Refusal):self.apply(p)
    v=json.loads((self.path/'receipt.json').read_bytes());self.assertEqual(v['phase'],'APPLY_UNKNOWN');self.assertEqual(v['before']['ipv4.dns'],['192.0.2.53']);self.assertEqual(len(self.nm.calls),1)
    state=D.status(self.path,self.nm)
    with self.assertRaisesRegex(D.Refusal,'uncertain'):self.apply(state)
    with self.assertRaisesRegex(D.Refusal,'uncertain'):self.undo(state)
    self.assertEqual(len(self.nm.calls),1)
 def test_readback_mismatch_is_unknown_and_retains_original(self):
  p=self.plan()
  def wrong(connection,changes):self.nm.calls.append((connection,changes));self.nm.values['ipv4.dns']=['8.8.8.8']
  self.nm.modify=wrong
  with self.assertRaisesRegex(D.Refusal,'readback differs'):self.apply(p)
  self.assertEqual(json.loads((self.path/'receipt.json').read_bytes())['phase'],'APPLY_UNKNOWN')
 def test_undo_failure_is_retained_unknown(self):
  a=self.apply(self.plan());self.nm.failure='before'
  with self.assertRaises(D.Refusal):self.undo(a)
  self.assertEqual(json.loads((self.path/'receipt.json').read_bytes())['phase'],'UNDO_UNKNOWN')
 def test_confirmation_digest_and_existing_output_refuse(self):
  p=self.plan()
  for digest,confirm in(('0'*64,'APPLY_CONNECTION_DNS'),(p['receipt_sha256'],'YES')):
   with self.assertRaises(D.Refusal):D.change(self.path,digest,confirm=confirm,nm=self.nm)
  with self.assertRaises(FileExistsError):self.plan()
  self.assertEqual(self.nm.calls,[])
 def test_lock_permissions_alias_and_hardlinks_refuse(self):
  self.plan();a=Path(self.temp.name)/'alias';a.symlink_to(self.path)
  with self.assertRaises(D.Refusal):D.status(a,self.nm)
  os.chmod(self.path/'receipt.json',0o644)
  with self.assertRaises(D.Refusal):D.status(self.path,self.nm)
  os.chmod(self.path/'receipt.json',0o600);os.link(self.path/'receipt.json',self.path/'hardlink')
  with self.assertRaises(D.Refusal):D.status(self.path,self.nm)
  (self.path/'hardlink').unlink()
  with D.state(self.path):
   with self.assertRaises(BlockingIOError):D.status(self.path,self.nm)
 def test_unknown_or_duplicate_receipt_keys_refuse(self):
  self.plan();raw=(self.path/'receipt.json').read_bytes()
  for changed in(raw.replace(b'"schema_version": 1',b'"schema_version": 1, "schema_version": 1'),raw.replace(b'"schema_version": 1',b'"schema_version": 1, "secrets": {}')):
   with self.assertRaises(D.Refusal):D.decode(changed)
 def test_receipt_persist_failure_precedes_nm_mutation(self):
  p=self.plan()
  with patch.object(D.State,'save',side_effect=OSError('fsync failed')):
   with self.assertRaises(OSError):self.apply(p)
  self.assertEqual(self.nm.calls,[])
 def test_inconsistent_preview_observation_creates_no_receipt(self):
  calls=[]
  def drift(connection,fields):calls.append(1);return {'ipv4.dns':['1.1.1.1'if len(calls)==1 else'9.9.9.9']}
  self.nm.read=drift
  with self.assertRaisesRegex(D.Refusal,'between reads'):self.plan({'ipv4.dns':['8.8.8.8']})
  self.assertFalse(self.path.exists());self.assertEqual(self.nm.calls,[])
 def test_final_receipt_failure_retains_interrupted_prior_not_false_undo(self):
  p=self.plan();original=D.State.save
  def save(holder,record):
   if record['phase']=='APPLIED':raise OSError('final fsync failed')
   return original(holder,record)
  with patch.object(D.State,'save',save),self.assertRaises(OSError):self.apply(p)
  self.assertEqual(self.nm.values['ipv4.dns'],self.request['ipv4.dns']);v=D.status(self.path,self.nm);self.assertEqual(v['phase'],'APPLYING')
  with self.assertRaisesRegex(D.Refusal,'uncertain'):self.undo(v)
  self.assertEqual(len(self.nm.calls),1)
 def test_receipt_types_nonfinite_and_unowned_properties_refuse(self):
  self.plan();raw=(self.path/'receipt.json').read_bytes();v=json.loads(raw)
  for changed in(dict(v,before={'ipv4.dns':42},after={'ipv4.dns':[]}),dict(v,before={'vpn.secret':'secret'},after={'vpn.secret':'secret'})):
   with self.assertRaises(D.Refusal):D.decode(D.encoded(changed))
  with self.assertRaises(D.Refusal):D.decode(raw.replace(b'"schema_version": 1',b'"schema_version": NaN'))
 def test_invalid_values_and_missing_family_refuse_before_nm_or_state(self):
  for field,raw in(('ipv4.dns','::1'),('ipv6.dns','1.1.1.1'),('ipv4.dns','https://resolver.example'),('ipv6.dns','fe80::1%eth0'),('ipv4.dns','1.1.1.1,1.1.1.1'),('ipv4.ignore-auto-dns','true')):
   with self.subTest(field=field,raw=raw),self.assertRaises(D.Refusal):D.value(field,raw)
  with self.assertRaises(D.Refusal):D.preview(self.path,'--bad',self.request,self.nm)
  with self.assertRaises(D.Refusal):D.preview(self.path,UUID,{},self.nm)
  self.assertFalse(self.path.exists())

class NmcliTests(unittest.TestCase):
 def test_query_is_exact_allowlist_no_secret_or_full_profile(self):
  nm=D.Nmcli();seen=[]
  def invoke(args):seen.append(args);return UUID+'\n1.1.1.1, 9.9.9.9\nyes\n2001:db8::1\nno\n'
  nm.invoke=invoke;row=nm.read(UUID,D.FIELDS);self.assertEqual(row['ipv6.dns'],['2001:db8::1']);self.assertEqual(seen[0],['--escape','no','--get-values','connection.uuid,ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns','connection','show','uuid',UUID]);self.assertNotIn('--show-secrets',seen[0])
 def test_wrong_uuid_or_field_frame_refuses(self):
  nm=D.Nmcli()
  for text in(UUID+'\n',UUID+'\nno\nextra\n','00000000-0000-0000-0000-000000000000\nno\n'):
   nm.invoke=lambda _,t=text:t
   with self.assertRaises(D.Refusal):nm.read(UUID,['ipv4.ignore-auto-dns'])
 def test_bounded_child_errors_hide_raw_stderr_and_kill_overflow(self):
  real=subprocess.Popen
  for source,expected in(("import sys;sys.stderr.write('VPN_SECRET_SENTINEL');sys.exit(3)",'exit 3'),("import sys;sys.stdout.write('x'*1000000)",'output cap')):
   def child(argv,**kw):self.assertEqual(argv[0],'/usr/bin/nmcli');return real([sys.executable,'-I','-B','-c',source],**kw)
   with patch.object(D.subprocess,'Popen',side_effect=child),self.assertRaisesRegex(D.Refusal,expected)as error:D.Nmcli().invoke(['connection','show'])
   self.assertNotIn('VPN_SECRET_SENTINEL',str(error.exception))
 def test_real_offline_apply_and_restore_both_families(self):
  self.assertTrue(Path('/usr/bin/nmcli').is_file(),'genuine offline nmcli required; no skip')
  original=b'[connection]\nid=DNS test\nuuid=11111111-2222-4333-8444-555555555555\ntype=ethernet\nautoconnect=false\n\n[ethernet]\n\n[ipv4]\nmethod=auto\ndns=192.0.2.53;\ndns-search=example.invalid;\nignore-auto-dns=false\n\n[ipv6]\nmethod=auto\ndns=2001:db8::53;\nignore-auto-dns=false\n'
  def offline(raw,properties):
   args=D.modify_args(UUID,properties)[4:];row=subprocess.run(['/usr/bin/nmcli','--offline','connection','modify',*args],input=raw,capture_output=True,timeout=10);self.assertEqual(row.returncode,0,row.stderr);return row.stdout
  def parsed(raw):
   p=configparser.ConfigParser(interpolation=None);p.read_string(raw.decode());return {s:dict(p[s])for s in p.sections()}
  before=offline(original,{'ipv4.dns':['192.0.2.53']});wanted={'ipv4.dns':['1.1.1.1','9.9.9.9'],'ipv4.ignore-auto-dns':'yes','ipv6.dns':['2001:4860:4860::8888'],'ipv6.ignore-auto-dns':'yes'}
  after=offline(before,wanted);fields=parsed(after);self.assertEqual(fields['ipv4']['dns'],'1.1.1.1;9.9.9.9;');self.assertEqual(fields['ipv6']['ignore-auto-dns'],'true');self.assertEqual(fields['ipv4']['dns-search'],'example.invalid;')
  restored=offline(after,{'ipv4.dns':['192.0.2.53'],'ipv4.ignore-auto-dns':'no','ipv6.dns':['2001:db8::53'],'ipv6.ignore-auto-dns':'no'});self.assertEqual(parsed(restored),parsed(before));self.assertNotIn(b'dns+tls',after)

class DiscoveryTests(unittest.TestCase):
 def listing(self,name):return UUID+':802-3-ethernet:'+name+'\n'
 def test_genuine_terse_colon_backslash_and_unicode_names(self):
  for encoded,expected in [('ordinary profile','ordinary profile'),('colon\\:name','colon:name'),('back\\\\slash','back\\slash'),('Café 東京','Café 東京'),('tab\there','tab\there'),('escape\x1b[31m','escape\x1b[31m')]:
   nm=D.Nmcli()
   with patch.object(nm,'invoke',side_effect=[UUID+':802-3-ethernet\n',self.listing(encoded)])as query:
    self.assertEqual(nm.profiles(),[dict(uuid=UUID,type='802-3-ethernet',name=expected)])
   self.assertEqual(query.call_args_list[0].args[0],['--terse','--escape','yes','--fields','UUID,TYPE','connection','show'])
   self.assertEqual(query.call_args_list[1].args[0],['--terse','--escape','yes','--fields','UUID,TYPE,NAME','connection','show'])
 def test_multiline_ambiguous_malformed_and_incomplete_rows_refuse(self):
  for raw in (self.listing('line\nbreak'),self.listing('bad\\q'),self.listing('x')[:-1],self.listing('x')*2,'not-uuid:ethernet:name\n',self.listing('x'*1025),self.listing('x:extra')):
   with self.subTest(raw=raw[:60]),self.assertRaises(D.Refusal):D.terse_records(raw,3)
 def test_identity_change_and_oversized_profile_count_refuse(self):
  nm=D.Nmcli()
  with patch.object(nm,'invoke',side_effect=[UUID+':802-3-ethernet\n',UUID+':vpn:name\n']),self.assertRaisesRegex(D.Refusal,'identities changed'):nm.profiles()
  with self.assertRaisesRegex(D.Refusal,'at most64'):D.terse_records((UUID+':ethernet\n')*65,2)
  with self.assertRaisesRegex(D.Refusal,'bounded'):D.terse_records('x'*(D.CAP+1),2)
 def test_empty_profiles_read_only(self):
  nm=D.Nmcli()
  with patch.object(nm,'invoke',return_value='')as query,patch.object(nm,'modify',side_effect=AssertionError('discovery must not mutate')):self.assertEqual(nm.profiles(),[])
  self.assertEqual(query.call_count,2)
 def test_cli_profiles_json_and_terminal_safe_human_names(self):
  import io
  rows=[dict(uuid=UUID,type='ethernet',name='Café\t\x1b[31m\u202e')]
  for args in (['profiles'],['--json','profiles']):
   out=io.StringIO()
   with patch.object(D.Nmcli,'profiles',return_value=rows),patch.object(D,'preview',side_effect=AssertionError('no receipt/mutation')),patch('sys.stdout',out):self.assertEqual(D.main(args),0)
   raw=out.getvalue();self.assertNotIn('\x1b',raw);self.assertNotIn('\u202e',raw)
   if '--json'in args:self.assertEqual(json.loads(raw)['profiles'],rows)
   else:self.assertIn('Café',raw);self.assertIn('\\u001b',raw)
 def test_cli_profiles_failure_exposes_no_raw_profile_output(self):
  import io
  err=io.StringIO()
  with patch.object(D.Nmcli,'profiles',side_effect=D.Refusal('listing changed')),patch('sys.stderr',err):self.assertEqual(D.main(['profiles']),1)
  self.assertIn('listing changed',err.getvalue())

if __name__=='__main__':unittest.main(verbosity=2)
