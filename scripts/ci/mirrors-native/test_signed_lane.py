# SPDX-License-Identifier: MIT
"""Focused job-proof and signer integration controls; never native actors."""
import copy,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import job as J
import run as R
ROOT=Path(__file__).resolve().parents[3]
class SignedLane(unittest.TestCase):
 def proof(self):
  env=dict(SOURCE_SHA='1'*40,GITHUB_SHA='1'*40,GITHUB_WORKFLOW_SHA='1'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='12345',GITHUB_RUN_ATTEMPT='1')
  return env,J.prove(ROOT,json.loads((ROOT/'scripts/ci/mirrors-native/source-manifest.json').read_bytes()),env)
 def test_source_proof_clock_and_current_job_join(self):
  env,proof=self.proof()
  with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,env):
   path=Path(temp)/'proof.json';path.write_text(json.dumps(proof));path.chmod(0o600)
   self.assertEqual(R.signing_job(ROOT,proof['consumer_token'],path)['proof_issued_epoch'],proof['issued_epoch'])
 def test_foreign_stale_future_or_partial_proof_refuses(self):
  env,proof=self.proof()
  for key,val in (('issued_epoch',int(time.time())-6001),('issued_epoch',int(time.time())+60),('issued_epoch',True),('source_files',0),('job_token','0'*16),('workflow_sha','0'*40),('consumer_token','0'*32)):
   with self.subTest(key=key),tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,env):
    path=Path(temp)/'proof.json';bad=copy.deepcopy(proof);bad[key]=val;path.write_text(json.dumps(bad));path.chmod(0o600)
    with self.assertRaises(ValueError):R.signing_job(ROOT,proof['consumer_token'],path)
 def test_signature_gate_is_mandatory_for_complete_lifecycle(self):
  from test_native import receipt
  good=receipt();C.validate_lifecycle(good)
  for change in ('missing','unsigned','cleanup','sigbytes','observation'):
   bad=copy.deepcopy(good)
   if change=='missing':bad.pop('signature_verification')
   elif change=='unsigned':bad['trust']='UNSIGNED_LOCAL_CANDIDATE_ONLY'
   elif change=='cleanup':bad['signature_verification']['cleanup']['upstream_trust_preserved']=False
   elif change=='sigbytes':bad['signature_verification']['archives']['a']['signature']['sha256']='0'*64
   else:bad['signature_verification']['observations'].pop()
   with self.subTest(change=change),self.assertRaises((ValueError,KeyError,TypeError)):C.validate_lifecycle(bad)
 def test_budgets_and_original_authentication_held(self):
  text=(ROOT/'scripts/ci/mirrors-native/workflow.yml.in').read_text()
  for token in ('timeout-minutes: 100','2300s','2500s','330s','--proof "$RUNNER_TEMP/mirrors-native-source-proof.json"'):self.assertIn(token,text)
  self.assertEqual(C.digest(ROOT/'scripts/ci/maintained_desktop574.py'),'27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760')
if __name__=='__main__':unittest.main()
