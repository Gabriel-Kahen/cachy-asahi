# SPDX-License-Identifier: MIT
"""Finite signed gate controls only; no host ALPM/native actor."""
import ast,copy,json,sys,time,unittest,tempfile,types,uuid,os
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import signed_lifecycle as S
import test_signing as T

def fixture():
 job=T.job(int(time.time())-10);rows={side:dict(archive='/inputs/'+side+'/candidate.pkg.tar.xz',bytes=10,sha256='c'*64) for side in ('a','b')};signing=T.signing_fixture(job,rows);epoch=signing['actor']['finished_epoch'];empty=S.pin(b'');pos=signing['archives']
 expected=['import-main-public','list-only-main-public','list-no-secret-keys','trust-main-TEST-only','verify-build-a','verify-build-b']+[name for case in ('missing-signature','wrong-key','tampered') for name in ('reject-'+case+'-gpg','reject-'+case+'-ALPM')]+['public-verifier-retire']
 return dict(status='PASS_TEST_SIGNATURE_VERIFIED_BEFORE_CANDIDATE_OBSERVATION',signature_policy='SigLevel=Required;LocalFileSigLevel=Required',public_only=True,wrong_key_not_trusted=True,verified_before_candidate_observation=True,job=job,signer=signing['signer'],wrong_signer=signing['wrong_signer'],public_key=signing['public_key'],signing_receipt=S.pin((json.dumps(signing,indent=2,sort_keys=True)+'\n').encode()),signing_receipt_data=signing,verified_epoch=epoch,verification_limit_seconds=120,archives={side:dict(archive={k:pos[side][k] for k in ('bytes','sha256')},signature=pos[side]['signature'],verification=pos[side]['verification']) for side in ('a','b')},negatives=[dict(case=case,gpg_exit=2,pacman_exit=1,pacman_signature_diagnostic=True,signature_rejected=True,inventory_count=574,inventory_unchanged=True,inventory=S.pin(b'SYNTHETIC574')) for case in ('missing-signature','wrong-key','tampered')],observations=[dict(phase=phase,epoch=epoch,signature_gate_complete=True) for phase in ('staged-before-install','install','same-version-reinstall','reinstall-after-removal')],cleanup=dict(verifier_removed=True,agent_endpoints_absent=True,upstream_trust_preserved=True),commands=[dict(operation=name,exit=1 if name.startswith('reject-') else 0,started_epoch=epoch,finished_epoch=epoch,stdout=empty,stderr=empty) for name in expected])

class GateTests(unittest.TestCase):
 def test_complete_current_job_gate(self):self.assertEqual(S.validate_gate(fixture())['refused_cases'],3)
 def test_required_policy_positive_verification_trust_and_cleanup_mutations(self):
  for field,value in (('verified_before_candidate_observation',False),('wrong_key_not_trusted',False),('public_only',False),('signature_policy','Optional')):
   bad=fixture();bad[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):S.validate_gate(bad)
  for mutation in ('cleanup','negative','signer','signing','order'):
   bad=fixture()
   if mutation=='cleanup':bad['cleanup']['upstream_trust_preserved']=False
   elif mutation=='negative':bad['negatives'][0]['pacman_exit']=0
   elif mutation=='signer':bad['archives']['a']['verification']=dict(bad['archives']['a']['verification'],primary_fingerprint='0'*40)
   elif mutation=='signing':bad['signing_receipt_data']['cleanup']['private_keys_removed']=False
   else:bad['observations'].reverse()
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):S.validate_gate(bad)
 def test_installed_auth_precedes_stage_and_all_five_transitions_held(self):
  text=Path(__file__).with_name('installed.py').read_text();ast.parse(text)
  self.assertLess(text.index('gate=S.prepare('),text.index("stage=Path('/tmp/mirrors-staged-payload')"))
  for marker in ('gate.before_observation(label)','gate.close()',"for label in ('install','same-version-reinstall')","absent('remove')","installed('reinstall-after-removal')","absent('final-remove')","signature_verification=gate.receipt","trust='EPHEMERAL_TEST_SIGNED_LOCAL_CANDIDATE_ONLY'"):self.assertIn(marker,text)
 def test_unverified_or_closed_observation_refuses(self):
  gate=S.Gate.__new__(S.Gate);gate.verified=False;gate.closed=False
  with self.assertRaises(ValueError):gate.before_observation('staged-before-install')
  gate.verified=True;gate.closed=True
  with self.assertRaises(ValueError):gate.before_observation('install')

class MockExecution(unittest.TestCase):
 def exercise(self,root,mode='good'):
  inputs=root/'inputs';inputs.mkdir();(inputs/'build-b').mkdir();signed=inputs/'signed';signed.mkdir();name='cachy-asahi-mirrors-0.2.0-2-any.pkg.tar.xz';body=b'SYNTHETIC CONTROL ARCHIVE';job=T.job(int(time.time())-20)
  for path in (inputs/name,inputs/'build-b'/name):path.write_bytes(body)
  rows={side:dict(archive='/inputs/'+side+'/'+name,**S.pin(body)) for side in ('a','b')};signing=T.signing_fixture(job,rows)
  data={'TEST-public.asc':b'SYNTHETIC TEST PUBLIC KEY CONTROL','WRONG-TEST-public.asc':b'SYNTHETIC WRONG TEST PUBLIC KEY CONTROL','build-a.sig':b'SYNTHETIC SIGNATURE a','build-b.sig':b'SYNTHETIC SIGNATURE b','wrong-key.sig':b'SYNTHETIC WRONG SIGNATURE'}
  for filename,raw in data.items():(signed/filename).write_bytes(raw)
  (signed/'signing.json').write_text(json.dumps(signing,indent=2,sort_keys=True)+'\n');(inputs/'signing-job.json').write_text(json.dumps(job));(inputs/'signing-input.json').write_text(json.dumps(dict(job=job,products=rows)))
  base={str(i):'1' for i in range(574)};product=dict(archive=name,archive_b='build-b/'+name,sha256=S.pin(body)['sha256'],sha256_b=S.pin(body)['sha256']);work=Path('/tmp')/('mirrors-signed-gate-control-'+uuid.uuid4().hex);self.work=work;self.calls=[]
  def engine(argv,**kwargs):
   self.calls.append(argv);out=b'';err=b'';code=0
   if argv[0]=='/usr/bin/pacman':code=0 if mode=='bad-accepted' else 1;err=b'database locked' if mode=='unrelated-error' else b'corrupted package (PGP signature)'
   elif '--list-keys' in argv:out=(':'.join(['fpr']+['']*8+[signing['signer'],''])+'\n').encode()
   elif '--list-secret-keys' in argv:out=b'sec::forbidden' if mode=='secret' else b''
   elif '--verify' in argv:
    label=Path(argv[argv.index('--verify')+1]).parent.name
    if label in ('missing-signature','wrong-key','tampered'):code=2;out=('[GNUPG:] '+{'missing-signature':'FAILURE','wrong-key':'NO_PUBKEY','tampered':'BADSIG'}[label]+' fixture\n').encode()
    else:out=T.status(signing['signer'],signing['archives']['a']['verification']['created_epoch'])
   return types.SimpleNamespace(returncode=code,stdout=out,stderr=err)
  L=types.SimpleNamespace(inventory=lambda:dict(base));hooks=root/'hooks';hooks.mkdir();original_lexists=S.os.path.lexists
  def lexists(path):return False if str(path)=='/usr/bin/cachy-asahi-mirrors' else original_lexists(path)
  with patch.object(S.subprocess,'run',side_effect=engine),patch.object(S.Gate,'upstream_snapshot',return_value={'upstream':'unchanged'}),patch.object(S.os.path,'lexists',side_effect=lexists):
   gate=S.prepare(None,L,inputs,work,base,product,hooks,root/'pacman.conf')
   for phase in ('staged-before-install','install','same-version-reinstall','reinstall-after-removal'):gate.before_observation(phase)
   gate.close();S.validate_gate(gate.receipt)
  return gate
 def test_full_public_gate_plan_and_retirement_without_actual_commands(self):
  with tempfile.TemporaryDirectory() as temp:
   gate=self.exercise(Path(temp));self.assertFalse(self.work.exists());self.assertTrue(all(gate.receipt['cleanup'].values()));self.assertEqual(len(gate.receipt['commands']),13)
   self.assertEqual(sum(argv[0]=='/usr/bin/pacman' for argv in self.calls),3);self.assertTrue(all('WRONG-TEST-public.asc' not in ' '.join(argv) for argv in self.calls))
 def test_invalid_candidate_acceptance_or_unrelated_alpm_error_refuses(self):
  for mode in ('bad-accepted','unrelated-error','secret'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp:
    with self.assertRaises(ValueError):self.exercise(Path(temp),mode)
    self.assertFalse(self.work.exists())

if __name__=='__main__':unittest.main()
