# SPDX-License-Identifier: MIT
"""Finite parser and real disposable host-GPG controls; no native or system trust actor."""
import copy,datetime,hashlib,json,lzma,os,platform,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_auth as A
import signer_actor as S
HERE=Path(__file__).resolve().parent


def job(now):
 value=dict(source_sha='a'*40,run_id='123',run_attempt='1',proof_issued_epoch=now,consumer_token='')
 value['consumer_token']=hashlib.sha256(('mirrors-consumer:123:1:'+'a'*40).encode()).hexdigest()[:32];return value


def status(fpr,now):
 date=datetime.datetime.fromtimestamp(now,datetime.timezone.utc).date().isoformat()
 return ('[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG '+fpr[-16:]+' TEST ONLY\n[GNUPG:] VALIDSIG '+fpr+' '+date+' '+str(now)+' 0 4 0 22 8 00 '+fpr+'\n').encode()


def signing_fixture(job_value,archive_rows,*,architecture='aarch64'):
 """Pure synthetic control receipt; never actual key/signature or native evidence."""
 now=job_value['proof_issued_epoch']+10;main='A'*40;wrong='B'*40;empty=A.pin(b'')
 public=A.pin(b'SYNTHETIC TEST PUBLIC KEY CONTROL');wrong_public=A.pin(b'SYNTHETIC WRONG TEST PUBLIC KEY CONTROL')
 archives={side:dict(row,signature=A.pin(('SYNTHETIC SIGNATURE '+side).encode()),verification=A.verify_status(status(main,now),0,main,now,now+1)) for side,row in archive_rows.items()}
 negatives=dict(wrong_key=dict(exit=2,expected_rejection=True,status=A.pin(b'SYNTHETIC NO_PUBKEY')),tampered=dict(exit=1,expected_rejection=True,status=A.pin(b'SYNTHETIC BADSIG')))
 names=['MAIN_KEY_GENERATE','MAIN_PUBLIC_LIST','MAIN_PUBLIC_EXPORT','MAIN_ARCHIVE_SIGN','MAIN_ARCHIVE_SIGN','WRONG_KEY_GENERATE','WRONG_PUBLIC_LIST','WRONG_PUBLIC_EXPORT','WRONG_ARCHIVE_SIGN','MAIN_RETIRE','WRONG_RETIRE','PUBLIC_IMPORT','PUBLIC_NO_SECRET_KEYS','VERIFY_BUILD_A','VERIFY_BUILD_B','REFUSE_WRONG_KEY','REFUSE_TAMPERED_BYTES','PUBLIC_RETIRE']
 operations=[dict(operation=name,exit=2 if i==15 else 1 if i==16 else 0,stdout=empty,stderr=empty) for i,name in enumerate(names)]
 for i,value in ((2,public),(7,wrong_public),(13,archives['a']['verification']['status_pin']),(14,archives['b']['verification']['status_pin']),(15,negatives['wrong_key']['status']),(16,negatives['tampered']['status'])):operations[i]['stdout']=value
 return dict(schema_version=1,status='PASS_FRESH_TEST_SIGNATURES_PUBLIC_ONLY',job=dict(job_value),actor=dict(architecture=architecture,uid=1000,started_epoch=now,finished_epoch=now+1,seconds=1.0,limit=120),signer=main,wrong_signer=wrong,public_key=public,wrong_public_key=wrong_public,wrong_signature=A.pin(b'SYNTHETIC WRONG SIGNATURE'),archives=archives,key_lifetimes=dict(main=dict(fingerprint=main,created_epoch=now,expires_epoch=now+86400),wrong=dict(fingerprint=wrong,created_epoch=now,expires_epoch=now+86400)),negatives=negatives,cleanup=dict(private_keys_removed=True,agent_endpoints_absent=True,private_root_removed=True,verifier_home_removed=True),operations=operations)


class Parser(unittest.TestCase):
 def test_good_current_signature_and_exact_primary(self):
  now=int(time.time());fpr='A'*40;proof=A.verify_status(status(fpr,now),0,fpr,now-1,now+1)
  self.assertEqual(proof['created_epoch'],now);self.assertEqual(proof['primary_fingerprint'],fpr)
 def test_bad_expired_revoked_or_failure_status_even_exit0_refuses(self):
  now=int(time.time());fpr='A'*40
  for bad in A.BAD:
   with self.subTest(bad=bad),self.assertRaises(ValueError):A.verify_status(status(fpr,now)+('[GNUPG:] '+bad+' details\n').encode(),0,fpr,now-1,now+1)
 def test_wrong_primary_duplicate_exit_and_time_refuse(self):
  now=int(time.time());fpr='A'*40;raw=status(fpr,now)
  for body,code,start,end in ((raw,1,now-1,now+1),(raw+raw,0,now-1,now+1),(raw.replace(fpr.encode(),b'B'*40),0,now-1,now+1),(raw,0,now+1,now+2),(raw,0,now-2,now-1)):
   with self.subTest(code=code,start=start),self.assertRaises(ValueError):A.verify_status(body,code,fpr,start,end)
 def test_actual_job_token_and_typed_clock_refuse(self):
  value=job(int(time.time()));A.job_scope(value)
  for key,value2 in (('consumer_token','0'*32),('proof_issued_epoch',True),('run_attempt','2'),('run_id',123),('source_sha','branch')):
   bad=dict(value);bad[key]=value2
   with self.subTest(key=key),self.assertRaises(ValueError):A.job_scope(bad)
 def test_pure_fixture_without_gpg(self):
  now=int(time.time());scope=job(now);rows={side:dict(archive='/inputs/'+side+'/cachy-asahi-mirrors-0.2.0-2-any.pkg.tar.xz',bytes=1,sha256='1'*64) for side in ('a','b')}
  proof=signing_fixture(scope,rows);self.assertEqual(A.validate_signing(proof,scope,rows)['signatures'],2)
 def test_receipt_schema_empty_hash_and_negative_operation_grafts_refuse(self):
  now=int(time.time());scope=job(now);rows={side:dict(archive='/inputs/'+side+'/cachy-asahi-mirrors-0.2.0-2-any.pkg.tar.xz',bytes=1,sha256='1'*64) for side in ('a','b')}
  for mutation in ('schema','empty_hash','negative_exit','key_after_signature'):
   proof=signing_fixture(scope,rows)
   if mutation=='schema':proof['schema_version']=True
   elif mutation=='empty_hash':proof['operations'][0]['stdout']['sha256']='0'*64
   elif mutation=='negative_exit':proof['negatives']['wrong_key']['exit']=1
   else:proof['key_lifetimes']['main']['created_epoch']+=1
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):A.validate_signing(proof,scope,rows)
 def test_held_signer_bytes_and_no_fake_clock(self):
  self.assertEqual(hashlib.sha256((HERE/'held_test_signer.py').read_bytes()).hexdigest(),'67f3ea8e1415d5662ef9307772dbd452f778862905d48c6d5b51a69ec89c2f04')
  with tempfile.TemporaryDirectory() as temp:
   commands=S.Commands(time.monotonic()+1,Path(temp))
   with self.assertRaises(ValueError):commands.call(['/usr/bin/gpg','--faked-system-time=1'],'forbidden')


class RealHostGPG(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='mirror-signing-control-');cls.addClassCleanup(cls.tmp.cleanup);root=Path(cls.tmp.name);inputs=root/'inputs';inputs.mkdir(mode=0o700);out=root/'public';out.mkdir(mode=0o700)
  rows={};body=lzma.compress(b'CONTROL ONLY package-like bytes; no installation or native claim\n')
  for side in ('a','b'):
   directory=inputs/side;directory.mkdir(mode=0o700);archive=directory/'cachy-asahi-mirrors-0.2.0-2-any.pkg.tar.xz';archive.write_bytes(body);rows[side]=dict(archive=str(archive),**A.pin(body))
  cls.job=job(int(time.time())-1);cls.rows=rows;path=inputs/'signing-input.json';path.write_text(json.dumps(dict(job=cls.job,products=rows)))
  cls.value=S.sign(path,out,native=False);cls.public=out
 def test_real_fresh_signatures_unknown_key_and_tamper_refused(self):
  value=self.value;self.assertEqual(value['status'],'PASS_FRESH_TEST_SIGNATURES_PUBLIC_ONLY');self.assertEqual(value['actor']['architecture'],platform.machine())
  self.assertNotEqual(value['signer'],value['wrong_signer']);self.assertTrue(value['cleanup']['private_root_removed'])
  self.assertTrue(all(value['negatives'][name]['exit']!=0 for name in ('wrong_key','tampered')))
  self.assertEqual({p.name for p in self.public.iterdir()},{'TEST-public.asc','WRONG-TEST-public.asc','build-a.sig','build-b.sig','wrong-key.sig','signing.json'})
  self.assertNotIn('PRIVATE KEY',(self.public/'TEST-public.asc').read_text())
 def test_full_receipt_gate_rejects_every_critical_graft(self):
  A.validate_signing(self.value,self.job,self.rows,architecture=platform.machine())
  for change in ('clock','identity','key','cleanup','signer','archive','negative','native','operations','export','wall_delta','expiry','extra'):
   bad=copy.deepcopy(self.value)
   if change=='clock':bad['actor']['finished_epoch']=self.job['proof_issued_epoch']+6001
   elif change=='identity':bad['actor']['uid']=0
   elif change=='key':bad['key_lifetimes']['main']['created_epoch']=1
   elif change=='cleanup':bad['cleanup']['private_keys_removed']=False
   elif change=='signer':bad['archives']['a']['verification']['primary_fingerprint']=bad['wrong_signer']
   elif change=='archive':bad['archives']['a']['sha256']='0'*64
   elif change=='negative':bad['negatives']['wrong_key']['exit']=0
   elif change=='native':bad['actor']['architecture']='not-native'
   elif change=='operations':bad['operations'].reverse()
   elif change=='export':bad['public_key']['sha256']='0'*64
   elif change=='wall_delta':bad['actor']['finished_epoch']+=30
   elif change=='expiry':bad['archives']['a']['verification']['expires_epoch']=bad['actor']['finished_epoch']+1
   else:bad['private_extra']='forbidden'
   with self.subTest(change=change),self.assertRaises(ValueError):A.validate_signing(bad,self.job,self.rows,architecture=platform.machine())


if __name__=='__main__':unittest.main()
