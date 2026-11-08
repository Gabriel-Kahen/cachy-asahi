# SPDX-License-Identifier: MIT
"""Source-shaped/partial-runner DATA controls; no Source emission or native actor."""
import argparse
import ast
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adapter as A
import test_source as S
parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('--root',type=Path,default=HERE.parents[2])
args,rest=parser.parse_known_args()
ROOT=args.root.resolve()
ACTIVE=False

def fence(event,arguments):
    if ACTIVE and (event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn')) or
                   event in ('os.system','pty.spawn','os.kill','os.killpg')):
        raise RuntimeError('entry DATA actor denied: '+event)
sys.addaudithook(fence)

def need(ok,why):
    if not ok: raise ValueError(why)

def write(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    path.write_bytes(value if isinstance(value,bytes) else (json.dumps(value,sort_keys=True)+'\n').encode())

class EntryFailures(unittest.TestCase):
    def setUp(self):
        global ACTIVE
        self.addCleanup(self.disable)
        ACTIVE=True
        self.temporary=tempfile.TemporaryDirectory(prefix='component-entry-DATA-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.here=self.root/'scripts/ci/client-v3-native'
        self.here.mkdir(mode=0o700,parents=True)

    def disable(self):
        global ACTIVE
        ACTIVE=False

    def shape(self,closed):
        # Deliberately only four DATA leaves; never a complete Source/emission.
        policy=dict(status='ROOT_BOUND_FINAL_PRODUCT_SOURCES' if closed else 'UNBOUND_CLIENT_V3_COMPONENT',
                    candidate_source='438acd83fa3bcb79abe29a007ae9e8d0f784d03f' if closed else None,
                    retained_input_carrier='3856733787d10820ab73f842e9f2bbf4fdb84181' if closed else None,
                    native_source=None,actual_run=None,native_authority=None,resource_authority=None)
        write(self.here/'input-policy.json',policy)
        template=b'# MODELED partial workflow DATA only\ngroup: native-arm-apps7-client\n@RETAINED_INPUT_SOURCE@ @JOB_SHA256@ @MANIFEST_SHA256@\n'
        # Explicit closed mode has no template file. This partial fixture is not a Source construction.
        if closed:
            write(self.here/'job.py',b'# MODELED JOB DATA\n')
            write(self.here/'source-manifest.json',dict(status='FROZEN_ROOT_FINAL_SOURCES',files={}))
            template=template.replace(b'@RETAINED_INPUT_SOURCE@',policy['retained_input_carrier'].encode())
            template=template.replace(b'@JOB_SHA256@',hashlib.sha256((self.here/'job.py').read_bytes()).hexdigest().encode())
            template=template.replace(b'@MANIFEST_SHA256@',hashlib.sha256((self.here/'source-manifest.json').read_bytes()).hexdigest().encode())
            write(self.root/'.github/workflows/native-arm-build.yml',template)
        else: write(self.here/'workflow.yml.in',template)
        return policy

    def test_explicit_maintained_shape_reads_template(self):
        self.shape(False)
        raw,markers=S.workflow_controls(self.here,self.root,False)
        self.assertEqual(markers,('@RETAINED_INPUT_SOURCE@','@JOB_SHA256@','@MANIFEST_SHA256@'))
        self.assertEqual(raw,(self.here/'workflow.yml.in').read_text())

    def test_explicit_closed_shape_checks_real_body_without_template(self):
        self.shape(True)
        self.assertFalse((self.here/'workflow.yml.in').exists())
        raw,markers=S.workflow_controls(self.here,self.root,True)
        self.assertTrue(all(marker in raw for marker in markers))

    def test_wrong_modes_do_not_fall_back(self):
        self.shape(True)
        with self.assertRaisesRegex(ValueError,'maintained UNBOUND'): S.workflow_controls(self.here,self.root,False)
        policy=self.shape(True);policy['status']='UNBOUND_CLIENT_V3_COMPONENT'
        write(self.here/'input-policy.json',policy)
        with self.assertRaisesRegex(ValueError,'closed component Source'): S.workflow_controls(self.here,self.root,True)

    def test_missing_closed_manifest_refuses_even_with_template(self):
        self.shape(True)
        (self.here/'source-manifest.json').unlink()
        write(self.here/'workflow.yml.in',b'# A template cannot replace deployed evidence\n')
        with self.assertRaises(FileNotFoundError): S.workflow_controls(self.here,self.root,True)

    def test_unexpanded_closed_placeholder_refused(self):
        self.shape(True)
        write(self.root/'.github/workflows/native-arm-build.yml',b'@JOB_SHA256@')
        with self.assertRaisesRegex(ValueError,'placeholders'): S.workflow_controls(self.here,self.root,True)

    def test_closed_shape_cannot_invent_actual_native_selection(self):
        policy=self.shape(True);policy['actual_run']=123
        write(self.here/'input-policy.json',policy)
        with self.assertRaisesRegex(ValueError,'selectors must remain NULL'): S.workflow_controls(self.here,self.root,True)

    def cleanup(self,proof=None):
        calls=[]
        runtime=self.root/'runtime'
        def retire(group,*arguments):
            calls.append(group.name)
            need(proof is not None,'owned proof required')
            return dict(status='PASS_NO_CONSUMER_ACTORS',containers=[])
        def producer_cleanup(source,manifest,ownership,base,group,output,command):
            calls.append('producer')
            write(output,dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP'))
            return dict(status='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP')
        old=SimpleNamespace(invoke=lambda *a:None,manifest_files=lambda *a:calls.append('manifest'),
                            retire_consumers=retire,cleanup=producer_cleanup)
        C=SimpleNamespace(HERE=self.here,read=lambda p:{},load=lambda *a:SimpleNamespace(),need=need,
                          safe=lambda p:p)
        source=A.text(ROOT,'job.py')
        node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='cleanup')
        namespace=dict(A=A,C=C,inherited=lambda source:old,save=write,shutil=shutil)
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-derived-cleanup-DATA>','exec'),namespace)
        result=namespace['cleanup'](ROOT,proof,self.root/'base',runtime,self.root/'cleanup.json')
        return result,calls,runtime

    def test_early_preflight_cleanup_creates_owned_report_parent_and_attempts_all(self):
        result,calls,runtime=self.cleanup(dict(job_token='MODELED',consumer_token='MODELED'))
        self.assertEqual(calls,['manifest','apps-consumers','base-consumers','producer'])
        self.assertEqual(stat.S_IMODE(runtime.stat().st_mode),0o700)
        self.assertTrue((runtime/'base-cleanup.json').is_file())
        self.assertEqual(result['status'],'PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY')

    def test_partial_runner_never_blocks_cleanup(self):
        write(self.root/'runtime/runtime-context/runner/partial.py',b'# actual partial DATA\n')
        (self.root/'runtime').chmod(0o700)
        result,calls,_=self.cleanup(dict(job_token='MODELED',consumer_token='MODELED'))
        self.assertEqual(calls[-1],'producer')
        self.assertEqual(result['authority'],'PASS_REMOVED_AFTER_ACTOR_RETIREMENT')

    def test_missing_owner_proof_preserves_attempt_and_retains_authority(self):
        result,calls,_=self.cleanup()
        self.assertEqual(calls,['manifest','apps-consumers'])
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['authority'],'RETAINED')

    def test_cleanup_parent_rejects_alias_and_borrowed_mode(self):
        target=self.root/'target'; target.mkdir()
        alias=self.root/'alias'; alias.symlink_to(target,target_is_directory=True)
        with self.assertRaises(ValueError): A.cleanup_parent(alias)
        with self.assertRaises(ValueError): A.cleanup_parent(target)

    def runners(self):
        for context in ('runtime-context','lifecycle-inputs'):
            directory=self.root/context
            rows={}
            for name in A.RUNNER_NAMES:
                body=('# actual MODEL runtime bytes '+name+'\n').encode()
                write(directory/'runner'/name,body)
                (directory/'runner'/name).chmod(0o644)
                rows[name]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),mode=0o644)
            write(directory/'runner-derivations.json',dict(schema=1,status='SOURCE_CLOSED_ACTUAL_RUNTIME_RUNNER_DATA',files=rows))

    def forward(self):
        copied={};result=dict(errors=[])
        C=SimpleNamespace(read=lambda p:json.loads(p.read_bytes()),need=need,
                          digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest())
        A.forward_runners(C,self.root,lambda p,n,cap:copied.setdefault(n,p.read_bytes()),result)
        return result,copied

    def test_missing_forwarding_proofs_produce_negative_data_without_synthesis(self):
        result,copied=self.forward()
        self.assertEqual(len(result['errors']),2)
        self.assertEqual(copied,{})

    def test_partial_runner_retains_available_bytes_and_reports_missing(self):
        self.runners();(self.root/'runtime-context/runner/contract.py').unlink()
        result,copied=self.forward()
        self.assertEqual(len(result['errors']),1)
        self.assertNotIn('emitted/runtime-dependency/runner/contract.py',copied)
        self.assertIn('emitted/lifecycle/runner/contract.py',copied)

    def test_conflicting_runner_fails_without_reconstructed_bytes(self):
        self.runners();write(self.root/'lifecycle-inputs/runner/contract.py',b'conflicting actual bytes')
        result,copied=self.forward()
        self.assertEqual(len(result['errors']),1)
        self.assertNotIn('emitted/lifecycle/runner/contract.py',copied)

    def test_complete_actual_both_contexts_forward_exact26_files(self):
        self.runners();result,copied=self.forward()
        self.assertEqual(result['errors'],[])
        self.assertEqual(len(copied),26)
        for role,context in [('runtime-dependency','runtime-context'),('lifecycle','lifecycle-inputs')]:
            for name in A.RUNNER_NAMES:
                self.assertEqual(copied['emitted/'+role+'/runner/'+name],(self.root/context/'runner'/name).read_bytes())

    def test_derived_cleanup_has_no_forwarding_prerequisite(self):
        raw=A.text(ROOT,'job.py');tree=ast.parse(raw)
        cleanup=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='cleanup')
        retain=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='retain')
        self.assertNotIn('forward_runners',ast.unparse(cleanup))
        self.assertIn('A.forward_runners(C, runtime, copy, result)',ast.unparse(retain))
        self.assertIn("save(output / 'retention.json', result)",ast.unparse(retain))

if __name__=='__main__': unittest.main(argv=[sys.argv[0],*rest])
