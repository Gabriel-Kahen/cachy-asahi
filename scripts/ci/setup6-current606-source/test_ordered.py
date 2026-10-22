"""Exact676 mode, unchanged predecessors and real source-owned transport controls."""
import argparse,importlib.util,io,json,os,shutil,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
for n in('original-source','setup-source','expected','real-expected','apps-packet'):p.add_argument('--'+n,type=Path,required=True)
a,rest=p.parse_known_args();OLD,SETUP,EXPECTED,REAL_EXPECTED,APPS=map(lambda q:q.absolute(),(a.original_source,a.setup_source,a.expected,a.real_expected,a.apps_packet))
spec=importlib.util.spec_from_file_location('_maintained_coexist_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def cli(factory,out,auth,original=OLD,setup=SETUP):return subprocess.run([sys.executable,'-I','-B','-Werror',str(factory/'prepare.py'),'--original-source',str(original),'--setup-source',str(setup),'--mode','coexistence','--ordered-nonce','--output',str(out),'--authorization',str(auth)],cwd='/tmp',capture_output=True,timeout=60)
class Ordered(unittest.TestCase):
 def test_exact676_isolated_CLI_whole_guard_original_source_controls_and_self_emitter(self):
  before=F.files(OLD),F.files(SETUP),F.files(APPS)
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);out,auth=root/'source',root/'authorization.json';r=cli(HERE,out,auth);self.assertEqual(r.returncode,0,r.stderr);value=json.loads(auth.read_bytes());self.assertEqual(value['files'],F.files(EXPECTED));self.assertEqual(F.files(out),F.files(EXPECTED));self.assertEqual(len(value['files']),676);self.assertEqual(value['expected_source'],'f9471acd0414c2f6abc53ee81111011df735430c');self.assertIsNone(value['actual']);self.assertEqual(value['Apps7'],'NOT_RUN_BY_FACTORY_REQUIRES_FULL676_NATIVE_REPLAY')
   for entry,arg in(('run.py','--source-preflight'),('test_source.py',None)):
    cmd=[sys.executable,'-I','-B','-Werror',str(out/'coexist'/entry)]
    if arg:cmd.append(arg)
    r=subprocess.run(cmd,cwd='/tmp',capture_output=True,timeout=60,env=dict(os.environ,APPS7_PAIR_PACKET=str(APPS)));self.assertEqual(r.returncode,0,r.stderr)
   child=root/'self-emitted';r=subprocess.run([sys.executable,'-I','-B',str(out/'coexist/prepare.py'),'--output',str(child)],cwd='/tmp',capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(F.files(child),F.files(out))
  self.assertEqual((F.files(OLD),F.files(SETUP),F.files(APPS)),before)
 def test_new_profile_42_payload_namespace_and_both_inputs_refuse_before_output(self):
  for target in('ordered-coexistence-profile.json','ordered-coexistence/coexist/integration.py','ordered-coexistence/foreign.json','ORIGINAL','SETUP'):
   with self.subTest(target=target),tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);factory=root/'factory';shutil.copytree(HERE,factory);original,setup=OLD,SETUP
    if target in('ORIGINAL','SETUP'):
     source=OLD if target=='ORIGINAL'else SETUP;clone=root/'input';shutil.copytree(source,clone);leaf=next(p for p in clone.rglob('*')if p.is_file()and '.git'not in p.relative_to(clone).parts);leaf.write_bytes(leaf.read_bytes()+b'\nDRIFT\n')
     if target=='ORIGINAL':original=clone
     else:setup=clone
    else:
     leaf=factory/target;leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes((leaf.read_bytes()if leaf.exists()else b'')+b'\nDRIFT\n')
    out,auth=root/'never-source',root/'never-auth';r=cli(factory,out,auth,original,setup);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists());self.assertFalse(auth.exists())
 def test_actual_emitted_checksum_stanzas(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);source=root/'expanded604-code';F.emit(OLD,SETUP,source,'coexistence',True);workflow=(source/'.github/workflows/native-arm-build.yml').read_text();self.assertEqual(workflow,(source/'.github/workflows/native-arm-current606-doctor2-owned-copy.yml').read_text());lines=[line.strip()for line in workflow.split('      - name: Checkout exact accepted Apps7',1)[0].splitlines()if line.strip().startswith("printf '%s  %s")and line.strip().endswith('| sha256sum --check')];self.assertEqual(len(lines),2)
   for line in lines:
    r=subprocess.run(['/bin/bash','--noprofile','--norc','-euo','pipefail','-c',line],cwd=root,capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.count(b': OK\n'),2)
 def test_actual_nonce_policy_retainer_capture_zip_and_missing_nonce_refusals(self):
  saved,paths=dict(sys.modules),sys.path[:]
  try:
   with tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);root.chmod(0o700);source=root/'source';F.emit(OLD,SETUP,source,'coexistence',True);sys.path.insert(0,str(source/'coexist'))
    for name in('guard','integration','latest_plan','coexist_inputs','coexist_plan'):sys.modules.pop(name,None)
    import guard as G,integration as I
    anchor=G.anchor();context=anchor.source_context(G.ROOT);obj=I.Integration(G,anchor,context,Path('/inert-runtime'),Path('/inert-setup'));T=load(source/'scripts/ci/native-evidence-transport/transport.py','_source676_transport');policy=json.loads((source/'coexist/transport-policy.json').read_bytes());owned=root/'owner';owned.mkdir();obj.prepare_nonce(owned);self.assertFalse((owned/'plan').exists());report=dict(status='FAIL');obj.prepare_export(owned,report);self.assertEqual(report['status'],'FAIL');self.assertEqual(report['nonce_projection']['phase'],'FAILED_PREPARATION_EXPORT_ONLY');self.assertFalse(report['nonce_projection']['actual_authority']);names=obj.export_names(owned);self.assertEqual(set(names),{'setup6-selection.json','plan/bridge-selection.json'});self.assertEqual((owned/'setup6-selection.json').read_bytes(),(owned/'plan/bridge-selection.json').read_bytes());public=root/'public';public.mkdir()
    for n in names:dest=public/n;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((owned/n).read_bytes())
    wf=(source/'.github/workflows/native-arm-build.yml').read_text();name=wf.splitlines()[0].removeprefix('name: ');self.assertEqual(name,policy['workflow_name']);body=wf.split("          python3 -I -B - <<'PYRETAIN'\n",1)[1].split('          PYRETAIN\n',1)[0];body='\n'.join(line[10:]for line in body.splitlines())+'\n';line=next(line for line in body.splitlines()if line.startswith('source='));self.assertEqual(body.count(line),1);body=body.replace(line,'source=pathlib.Path('+repr(str(public))+')',1)
    with patch.dict(os.environ,dict(RUNNER_TEMP=str(root),GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')):exec(compile(body,'<entire-original-retainer-only-owned-fixture-root>','exec'),{})
    env=dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=policy['repository'],GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_JOB='native',GITHUB_WORKFLOW=name,RUNNER_ARCH='ARM64',GITHUB_SHA='a'*40,CAA_EVIDENCE_SOURCE_SHA='a'*40,CAA_EVIDENCE_WORKFLOW_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1');encoder=HERE.parents[2]/'scripts/ci/log_evidence.py';step,receipt=T.capture(root/'expanded604-public',root/'capture',encoder,policy,env);self.assertEqual(receipt['context']['nonce'],obj.nonce);self.assertEqual(receipt['acceptance'],'NOT_GRANTED');archive=root/'artifact.zip'
    with zipfile.ZipFile(archive,'w')as z:z.writestr('transport.json',T.encoded(receipt));z.writestr('retention-step.txt',step)
    raw=archive.read_bytes();run=dict(id=123,run_attempt=1,head_sha='a'*40,repository=dict(full_name=policy['repository']),path=policy['workflow_path'],name=name,event='workflow_dispatch',status='completed',conclusion='failure');jobs=dict(total_count=1,jobs=[dict(id=9,name='native',run_id=123,status='completed',head_sha='a'*40,run_attempt=1,steps=[dict(name=policy['step_name'],status='completed',conclusion='success',number=48)])]);artifact=dict(id=7,size_in_bytes=len(raw),digest='sha256:'+T.pin(raw)['sha256'],expired=False,name='native-framed-evidence-123-1-native',workflow_run=dict(id=123,head_sha='a'*40));proof,files=T.verify_zip(archive,receipt['context'],run,jobs,artifact,policy);self.assertEqual(proof['acceptance'],'NOT_GRANTED');self.assertEqual(proof['original_conclusion'],'failure');self.assertEqual(set(files),set(names))
    for drift in(dict(env,GITHUB_RUN_ATTEMPT='2'),dict(env,GITHUB_WORKFLOW='native-arm-current606-setup6-real-modules')):
     with self.assertRaises(ValueError):T.context(policy,drift)
    (public/'plan/bridge-selection.json').write_bytes(b'{}')
    with self.assertRaises(ValueError):obj.export_names(public)
    (public/'plan/bridge-selection.json').unlink()
    with self.assertRaises(FileNotFoundError):obj.export_names(public)
  finally:
   sys.path[:]=paths
   for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
   sys.modules.update(saved)
 def test_exact_corrected636_source_entry_and_invalid_copied_root_revision(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);out,auth=root/'source',root/'auth';cmd=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--original-source',str(OLD),'--setup-source',str(SETUP),'--mode','real-modules','--ordered-nonce','--output',str(out),'--authorization',str(auth)];r=subprocess.run(cmd,cwd='/tmp',capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(F.files(out),F.files(REAL_EXPECTED));value=json.loads(auth.read_bytes());self.assertEqual(value['source_revision'],'ordered-nonce');self.assertEqual(value['expected_source'],'d09f6b5cb122062af7b9868f54bc1fda69318d34')
   for entry,arg in(('run.py','--source-preflight'),('test_source.py',None)):
    cmd=[sys.executable,'-I','-B','-Werror',str(out/'real606'/entry)]
    if arg:cmd.append(arg)
    r=subprocess.run(cmd,cwd='/tmp',capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr)
   missing=root/'never'
   with self.assertRaises(ValueError):F.emit(OLD,SETUP,missing,'copied-root',True)
   self.assertFalse(missing.exists())
 def test_all_three_original_authorization_receipts_stay_byte_identical(self):
  before={'copied-root': {'bytes': 110692, 'sha256': 'a197a3019eda70f9584ee5812d185ebcab9aba3d3019bb156264739bc09dba87'}, 'real-modules': {'bytes': 114825, 'sha256': 'f3bb45f697247c22603ca1f36a3dc79846a04791d11e57df0ec744beaf778ed2'}, 'coexistence': {'bytes': 120887, 'sha256': 'f59b8ed0983455a9e514c48c3c179cae38c77d23fc6ee591854f12f064041a26'}}
  for mode,pinned in before.items():
   with self.subTest(mode=mode),tempfile.TemporaryDirectory()as tmp:
    value=F.emit(OLD,SETUP,Path(tmp)/'source',mode);self.assertEqual(F.pin(F.encoded(value)),pinned)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest])
