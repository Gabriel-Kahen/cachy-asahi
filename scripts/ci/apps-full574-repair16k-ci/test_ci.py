# SPDX-License-Identifier: MIT
"""Finite source/argv/retention controls; no kernel, Docker or VM execution."""
import argparse,hashlib,importlib.util,io,json,os,subprocess,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=Path(os.environ.get('CACHY_ASAHI_REPAIR16K_TEST_SOURCE',HERE.parents[2]))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
import sys
sys.path.insert(0,str(HERE));import support as S
P=load('repair16k_ci_prepare',HERE/'prepare.py');R=load('repair16k_ci_retain',HERE/'retain.py');K=load('repair16k_ci_kernel',HERE/'kernel.py');O=load('repair16k_ci_owner',HERE/'owner.py')
class Controls(unittest.TestCase):
 def test_real_bridge_unbound_refuses_before_Git_source_or_output(self):
  C=S.bridge(ROOT);read=C.read
  def unbound(path,*args):return C.encoded({'schema_version':1,'status':'UNBOUND_NEW_NATIVE_REPAIR_CASES_AND_ACCEPTED_KERNEL','binding':None}) if Path(path).name=='input-policy.json' else read(path,*args)
  with patch.object(S,'bridge',return_value=C),patch.object(C,'read',side_effect=unbound),patch.object(subprocess,'Popen',side_effect=AssertionError('no actors before authority')):
   for case in C.CASES:
    with self.assertRaisesRegex(ValueError,'UNBOUND16K'):S.authorize(ROOT,case)
 def test_full_closed_emission_preserves_all_bridge_bytes_and_original_phases(self):
  with tempfile.TemporaryDirectory() as td,patch.object(subprocess,'Popen',side_effect=AssertionError('source only')):
   out=Path(td)/'source';result=P.emit(ROOT,out);mf=json.loads((out/P.LANE/'source-manifest.json').read_bytes());self.assertLessEqual(len(mf['files']),512)
   for name,row in mf['files'].items():self.assertEqual(P.pin((out/name).read_bytes()),row)
   self.assertEqual({p.relative_to(out).as_posix() for p in out.rglob('*') if p.is_file()},set(mf['files'])|{P.LANE+'/source-manifest.json',P.WF})
   bridge=ROOT/P.BRIDGE;files=json.loads((bridge/'source-manifest.json').read_bytes())['files'];names=[n for n in files if n.startswith(P.BRIDGE+'/')]+[P.BRIDGE+'/source-manifest.json']
   for name in names:self.assertEqual((out/name).read_bytes(),(ROOT/name).read_bytes())
   original=(ROOT/P.NATIVE_WF).read_text();wf=(out/P.WF).read_text()
   for begin,end in [('      - name: Seed the six exact retained inputs using existing secrets only\n','      - name: Checkout exact retained public input source\n'),('      - name: Checkout exact retained public input source\n','      - name: Actual native574 Apps copied-root transactions\n')]:
    expected=P.section(original,begin,end)
    if begin.startswith('      - name: Checkout'):expected=expected.split('      - name: Actual')[0]
    self.assertIn(expected,wf)
   self.assertIn('timeout-minutes: 350',wf)
   group='native-arm-apps-full574-repair16k-${{ inputs.repair_case }}';self.assertEqual(wf.count('  group: '+group+'\n'),1);self.assertIn('  cancel-in-progress: false\n',wf)
   groups={case:group.replace('${{ inputs.repair_case }}',case) for case in ('repair-bytes','repair-missing')};self.assertEqual(len(set(groups.values())),2);self.assertEqual(groups['repair-bytes'],group.replace('${{ inputs.repair_case }}','repair-bytes'))
   for value in ('3550s','650s','3700s','timeout-minutes: 63','timeout-minutes: 40'):self.assertIn(value,wf)
   self.assertLess(wf.index('Verify actual native-case and prior kernel authorities'),wf.index('Seed the six exact retained inputs'))
   self.assertIn('retained-apps574-inputs/payload',wf);self.assertNotIn('expanded604-',wf);self.assertNotIn('apps6-inputs',wf);self.assertIn('--kernel-authority ',wf);self.assertIn('--kernel-receipt ',wf);self.assertIn('ci-retention', (out/P.LANE/'retain.py').read_text())
   self.assertEqual(result['bridge_manifest_unchanged'],P.pin((bridge/'source-manifest.json').read_bytes()))
 def test_separate_current_implementation_only_supplies_missing_closed_helpers(self):
  with tempfile.TemporaryDirectory() as d,patch.object(subprocess,'Popen',side_effect=AssertionError('source only')):
   root=Path(d);bridge=root/'bridge';bridge.mkdir();rows=json.loads((ROOT/P.BRIDGE/'source-manifest.json').read_bytes())['files']
   for name in (*rows,P.BRIDGE+'/source-manifest.json'):
    p=bridge/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
   out=root/'source';value=P.emit(bridge,out,ROOT);self.assertEqual(value['source_rows'],148)
   for name in rows:self.assertEqual((out/name).read_bytes(),(bridge/name).read_bytes())
   empty=root/'empty';empty.mkdir();bad=root/'bad'
   with self.assertRaises((ValueError,FileNotFoundError)):P.emit(bridge,bad,empty)
   self.assertFalse(bad.exists());alias=root/'alias';alias.symlink_to(ROOT,target_is_directory=True)
   with self.assertRaises(ValueError):P.emit(bridge,bad,alias)
   self.assertFalse(bad.exists())
 def test_source_drift_duplicate_seam_and_existing_output_refuse(self):
  with tempfile.TemporaryDirectory() as td:
   out=Path(td)/'occupied';out.mkdir()
   with self.assertRaisesRegex(ValueError,'fresh ordinary'):P.emit(ROOT,out)
  raw=(ROOT/P.NATIVE_WF).read_text();kernel=(ROOT/P.KERNEL_WF).read_text()
  with self.assertRaisesRegex(ValueError,'one finite'):P.workflow(raw+raw,kernel,'a'*64,'b'*64)
 def test_actual_owner_argv_keeps_original_handoff_and_all_kernel_operands(self):
  C=S.bridge(ROOT);args=argparse.Namespace(source=ROOT,case='repair-bytes',proof=Path('/inert/proof'),base=Path('/inert/base'),output=Path('/inert/output'),handoff=Path('/inert/handoff'),packet=Path('/inert/packet/payload'),native_decisions=Path('/inert/decisions'),kernel_work=Path('/inert/kernel'),kernel_receipt=Path('/inert/kernel/receipt'),kernel_authority=Path('/inert/authority'))
  recorded=[];original=types.SimpleNamespace(handoff=lambda argv,path,identity:(recorded.append(argv) or dict(cancellation_signal=None,exit_code=0)))
  with patch.object(C,'authorize',return_value=None),patch.object(C,'load',return_value=original),patch.object(O,'identity',return_value={'inert':'not authority'}),patch.object(sys,'stdout',io.StringIO()):self.assertEqual(O.run(args,C,None),0)
  argv=recorded[0];self.assertEqual(argv[:3],['/usr/bin/python3','-I','-B']);self.assertEqual(argv[3],str(ROOT/S.BRIDGE/'job.py'))
  for flag,value in [('--case',args.case),('--packet',str(args.packet)),('--kernel-work',str(args.kernel_work)),('--kernel-receipt',str(args.kernel_receipt)),('--kernel-authority',str(args.kernel_authority)),('--native-decisions',str(args.native_decisions))]:self.assertEqual(argv[argv.index(flag)+1],value)
 def test_partial_originals_retained_without_upgrading_or_overwriting(self):
  C=S.bridge(ROOT)
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);public=root/'public';public.mkdir();raw=b'original failed worker bytes';(public/'raw-worker').write_bytes(raw);base=C.encoded(dict(status='FAIL_OR_INCOMPLETE',files={'raw-worker':dict(bytes=len(raw),sha256=C.sha(raw))},errors=['inert failed control']))
   (public/'retention.json').write_bytes(base);own=root/'own';own.mkdir();(own/'source-manifest.json').write_bytes(b'inert source manifest');source=root/'source';source.mkdir();(source/'.github/workflows').mkdir(parents=True);(source/S.WF).write_bytes(b'inert workflow')
   a=argparse.Namespace(source=source,public=public,case='repair-bytes',source_sha='a'*40,metadata=root/'no-metadata',kernel_cleanup=root/'no-cleanup',proof=root/'no-proof',ordered=root/'no-ordered',handoff=root/'no-handoff',acquire=root/'no-acquire',seed=root/'no-seed')
   with patch.object(S,'source',return_value={}),patch.object(S,'HERE',own):value=R.retain(a,C)
   self.assertFalse(value['proof_complete']);self.assertEqual((public/'raw-worker').read_bytes(),raw);self.assertEqual((public/'retention.json').read_bytes(),base);self.assertTrue((public/'ci-retention.json').is_file());self.assertEqual(value['scope'],'GENERIC16K_VM_ONLY_NOT_NATIVE_HOST_OR_HARDWARE')
   # Retention never repairs bad evidence to make a complete set.
   (public/'raw-worker').write_bytes(b'tampered')
   with patch.object(S,'source',return_value={}),patch.object(S,'HERE',own):
    with self.assertRaisesRegex(ValueError,'original retained file hash'):R.retain(a,C)
 def test_kernel_unknown_or_wrong_owned_directory_is_not_removed(self):
  C=S.bridge(ROOT)
  with tempfile.TemporaryDirectory() as td:
   work=Path(td)/'managed-gui16k-kernel';work.mkdir(mode=0o700);(work/'ci-owner.json').write_bytes(C.encoded(dict(source='a'*40,case='repair-bytes',identity=[0,0])));a=argparse.Namespace(work=work,case='repair-bytes')
   with patch.dict(os.environ,SOURCE_SHA='a'*40),patch.object(S,'kernel',side_effect=AssertionError('identity first')):
    with self.assertRaisesRegex(ValueError,'exact owned kernel'):K.cleanup(a,C)
   self.assertTrue(work.is_dir());a.work=Path(td)/'not-created';a.work=a.work.with_name('managed-gui16k-kernel-missing')
   with self.assertRaisesRegex(ValueError,'dedicated ordinary'):K.cleanup(a,C)
 def test_incomplete_handoff_cannot_release_kernel_backing(self):
  C=S.bridge(ROOT)
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);work=root/'managed-gui16k-kernel';work.mkdir(mode=0o700);info=work.stat();(work/'ci-owner.json').write_bytes(C.encoded(dict(source='a'*40,case='repair-bytes',identity=[info.st_dev,info.st_ino])))
   built=work/'helper/built';built.mkdir(parents=True);config=built/'config';config.write_bytes(b'INERT_NOT_A_KERNEL');image=built/'Image';image.write_bytes(b'INERT_NO_BOOT'.ljust(64,b'!'));receipt=built/'build-receipt.json';receipt.write_bytes(C.encoded({'config':C.row(config)}))
   a=argparse.Namespace(work=work,source=ROOT,case='repair-bytes',receipt=root/'cleanup.json',proof=root/'proof',handoff=root/'handoff',job_outcome='failure',ordered=root/'ordered',output=root/'output')
   supervisor=types.SimpleNamespace(check=lambda *args:(_ for _ in ()).throw(ValueError('original direct group absence unknown')));owner=types.SimpleNamespace(identity=lambda *args:{'inert':'NO_AUTHORITY'})
   with patch.dict(os.environ,SOURCE_SHA='a'*40),patch.object(S,'kernel',return_value=({'scope':'INERT_NOT_A_KERNEL'},image,config)),patch.object(S,'bridge',return_value=C),patch.object(C,'load',side_effect=[supervisor,owner]):
    with self.assertRaisesRegex(ValueError,'group absence unknown'):K.cleanup(a,C)
   self.assertTrue(work.is_dir());self.assertTrue((root/'repair16k-kernel-metadata.json').is_file());self.assertTrue((root/'repair16k-kernel-attempt.json').is_file());self.assertFalse((root/'cleanup.json').exists());attempt=C.decode(C.read(root/'repair16k-kernel-attempt.json'));self.assertEqual(attempt['files']['receipt']['sha256'],C.row(receipt)['sha256']);self.assertIn('NOT_COMPLETED_BUILD_AUTHORITY',attempt['status'])
 def test_scope_and_original_checks_have_no_budget_or_retirement_substitution(self):
  text=(HERE/'owner.py').read_text();self.assertIn("original.check(a.handoff,who,a.job_outcome=='skipped')",text);self.assertIn('original.handoff(argv,args.handoff,who)',text);self.assertIn('C.authorize(args)',text)
  self.assertNotIn('docker run',text);self.assertNotIn('killpg(',text);kernel=(HERE/'kernel.py').read_text();self.assertLess(kernel.index('original.check('),kernel.index('shutil.rmtree(a.work)'));self.assertIn('PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',kernel)
  retained=(HERE/'retain.py').read_text();self.assertIn('192*1024**2',retained);self.assertIn("open('xb')",retained);self.assertIn('GENERIC16K_REPAIR_ORIGINALS_RETAINED_NOT_ROOT_ACCEPTED',retained)
if __name__=='__main__':unittest.main(verbosity=2)
