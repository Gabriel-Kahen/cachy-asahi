# SPDX-License-Identifier: MIT
"""Hosted source/ownership controls only; never launch Docker or a native actor."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ.get('EXPANDED604_SOURCE',Path.cwd())).resolve()
spec=importlib.util.spec_from_file_location('_604_owner_test_contract',HERE/'contract.py')
C=importlib.util.module_from_spec(spec);sys.modules[spec.name]=C;spec.loader.exec_module(C)
R=C.scoped_load('_604_owner_tests_run',HERE/'run.py',{'contract':C})
G=C.scoped_load('_604_owner_tests_gate',HERE/'gate.py',{'contract':C})
F=C.scoped_load('_604_owner_tests_freeze',HERE/'freeze.py',{'contract':C})


class Owner(unittest.TestCase):
    def test_verifier_home_or_dangling_link_refuses_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);private=root/'private';private.mkdir()
            R.require_verifier_absence(root)
            home=private/'expanded604-verifier';home.mkdir();(home/'public-state').write_bytes(b'retain')
            with patch.object(R.subprocess,'run') as actor:
                with self.assertRaisesRegex(ValueError,'absence uncertain'):R.require_verifier_absence(root)
            actor.assert_not_called();self.assertEqual((home/'public-state').read_bytes(),b'retain')
            (home/'public-state').unlink();home.rmdir();home.symlink_to(private/'absent-target')
            with self.assertRaisesRegex(ValueError,'absence uncertain'):R.require_verifier_absence(root)
            self.assertTrue(home.is_symlink())

    def test_unbound_first_run_gate_does_not_observe_daemon_or_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'never-created'
            argv=[]
            for name in (*R.PRODUCER_PATHS,*R.CARRIERS,'audio_inputs'):
                argv+=['--'+name.replace('_','-'),directory]
            argv+=['--code-revision','0'*40,'--output',str(output)]
            with patch.object(C,'policy',side_effect=ValueError('UNBOUND Welcome')) as policy,patch.object(R,'capture') as daemon,patch.object(C,'load') as load:
                with self.assertRaisesRegex(ValueError,'UNBOUND'):R.main(argv)
            policy.assert_called_once();daemon.assert_not_called();load.assert_not_called();self.assertFalse(output.exists())

    def test_preflight_refuses_unbound_before_github_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'outputs'
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(output)}),patch.object(C,'policy',side_effect=ValueError('UNBOUND')),patch.object(C,'revision') as revision:
                with self.assertRaisesRegex(ValueError,'UNBOUND'):G.main(['--code',directory,'--source','a'*40,'--workflow-sha','a'*40,'--preflight'])
            revision.assert_not_called();self.assertFalse(output.exists())

    def test_bound_preflight_exposes_only_fixed_carrier_revisions(self):
        policy=dict(legacy_source='1'*40,eight_pair_source='2'*40,retained_seven_source='3'*40,
            management={'packet_source':'4'*40},setup={'source':'5'*40},welcome={'source':'7'*40,'carrier_source':'6'*40})
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'outputs'
            with patch.dict(os.environ,{'GITHUB_OUTPUT':str(output)}),patch.object(C,'policy',return_value=policy),patch.object(C,'verify_source') as source,patch.object(C,'revision',return_value='a'*40),patch.object(C,'inputs') as inputs:
                self.assertEqual(G.main(['--code',directory,'--source','a'*40,'--workflow-sha','a'*40,'--preflight']),0)
            self.assertEqual(set(line.split('=')[0] for line in output.read_text().splitlines()),set(R.CARRIERS))
            self.assertIn('welcome_source='+'6'*40,output.read_text())
            inputs.assert_not_called();source.assert_called_once()

    def test_input_or_source_failure_precedes_actor_module_and_output(self):
        args=types.SimpleNamespace(code=SOURCE,code_revision='a'*40)
        for failed in ('verify_source','inputs'):
            with self.subTest(failed=failed),patch.object(C,'policy',return_value={}),patch.object(C,'revision',return_value='a'*40),patch.object(C,'verify_source'),patch.object(C,'inputs'),patch.object(C,'load') as load:
                with patch.object(C,failed,side_effect=ValueError('byte mismatch')):
                    with self.assertRaisesRegex(ValueError,'byte mismatch'):R.verify(args)
                load.assert_not_called()

    def test_scoped_owned_label_preserves_original_namespace_and_api(self):
        original=types.ModuleType('contract')
        with patch.dict(sys.modules,{'contract':original}):
            owner=C.scoped_load('_604_owned_test',SOURCE/'scripts/ci/expanded-development-composition/owned.py',{'contract':C})
            self.assertIs(sys.modules['contract'],original);self.assertIs(owner.C,C)
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'containers.json'
                owned=owner.Containers(path,'sha256:'+'1'*64)
                try:
                    with patch.object(owner,'capture',return_value=''):
                        argv=owned.launch(['docker','run','--name','cachy-asahi-expanded604-test','image'])
                    self.assertIn(C.LABEL+'='+owned.token,argv)
                    saved=json.loads(path.read_bytes());self.assertEqual(saved['containers'][0]['status'],'RESERVED')
                    self.assertIsNone(saved['containers'][0]['id']);self.assertTrue(path.with_suffix('.lease').exists())
                finally:owned.close()

    def test_foreign_identity_and_unknown_daemon_never_authorize_removal(self):
        owner=C.scoped_load('_604_owned_identity_test',SOURCE/'scripts/ci/expanded-development-composition/owned.py',{'contract':C})
        with tempfile.TemporaryDirectory() as directory:
            owned=owner.Containers(Path(directory)/'containers.json','sha256:'+'1'*64)
            try:
                owned.rows=[dict(name='cachy-asahi-expanded604-test',status='RESERVED',id=None)]
                for response in (types.SimpleNamespace(returncode=1,stdout='',stderr='daemon unavailable'),
                    types.SimpleNamespace(returncode=0,stderr='',stdout=json.dumps([dict(Id='2'*64,Name='/cachy-asahi-expanded604-test',Image='sha256:'+'3'*64,Config={'Labels':{C.LABEL:owned.token}})]))):
                    with self.subTest(response=response),patch.object(owner.subprocess,'run',return_value=response),patch.object(owner,'capture') as remove:
                        with self.assertRaisesRegex(ValueError,'cleanup failed'):owned.cleanup()
                    remove.assert_not_called();self.assertEqual(owned.rows[0]['status'],'FAIL')
            finally:owned.close()

    def test_export_closed_refs_and_drift_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'out';out.mkdir();carrier=root/'carrier';carrier.mkdir()
            raw=b'original pair archive';(carrier/'pair').write_bytes(raw)
            ref=dict(path='pair',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            summary=dict(retention=[dict(root='eight_source',ref=ref)])
            args=types.SimpleNamespace(eight_source=carrier)
            report={};R.export(out,report,args,summary)
            self.assertEqual((out/'public/inputs/eight_source/pair').read_bytes(),raw)
            self.assertEqual(report['retention']['cap'],64*1024**2)
            (carrier/'pair').write_bytes(b'drift')
            with self.assertRaisesRegex(ValueError,'identity'):R.export(out,{},args,summary)

    def test_plan_accepts_only_exact_preaccepted_audio_error_vectors(self):
        before,after=C.locks();incoming={n:v for n,v in after.items() if before.get(n)!=v}
        extras={'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}
        projects=set(sorted(set(before)-extras)[:10]);initial=projects|extras
        rows=[dict(name=n,version=v,archive=n+'.pkg',signature=n+'.pkg.sig',size=1,sha256='a'*64,
            signature_sha256='b'*64,signer='F'*40) for n,v in after.items()]
        original=dict(packages=[dict(name=n,version=v,archive=n+'.pkg') for n,v in before.items()],
            projects=[{'name':n} for n in projects],preparation={'signer_roles':{'ephemeral_TEST':'F'*40}})
        ownership={n:[] for n in initial}
        profile=types.SimpleNamespace(manifest=lambda _: (original,{},before),payload=lambda root,rows,code:
            dict(packages=before if len(rows)==587 else after,ownership=ownership,nodes={}))
        def report(path):
            name=path.name.removesuffix('.pkg')
            return dict(sha256='a'*64,members={},metadata={'.PKGINFO':{}},elf={},
                errors=['exact protected audio source boundary'] if name in C.AUDIO else [])
        audios={n:{'inspected':report(Path(n+'.pkg'))} for n in C.AUDIO}
        checker=types.SimpleNamespace(package=report)
        def load(name,path):return profile if path.name=='profile.py' else checker
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);ready=root/'ready';target=root/'target';ready.mkdir();target.mkdir()
            for parent in (ready,target):(parent/'manifest.json').write_text('{}')
            out=root/'good';out.mkdir()
            with patch.object(C,'load',side_effect=load),patch.object(C,'target_manifest',return_value=({'packages':rows},{},after)):
                planroot,plan=R.prepare_plan(ready,target,out,SOURCE,SOURCE,{'combined':{}},audios)
                self.assertEqual(len(plan['incoming']),19);self.assertTrue((planroot/'predecessor-payload.json').exists())
                wrong=root/'wrong';wrong.mkdir();audios['asahi-audio']['inspected']['errors']=[]
                with self.assertRaisesRegex(ValueError,'exact original inspected audio'):
                    R.prepare_plan(ready,target,wrong,SOURCE,SOURCE,{'combined':{}},audios)

    def test_source_freeze_is_canonical_and_requires_bound_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);here=root/'scripts/ci/expanded604-composition';here.mkdir(parents=True)
            (here/'run.py').write_text('# fixed owner\n');(here/'held-pins.json').write_text('{}')
            workflow=root/'.github/workflows/native-arm-expanded604.yml';workflow.parent.mkdir(parents=True)
            workflow.write_text('@OWNER_SHA256@ @MANIFEST_SHA256@\n')
            with patch.object(C,'HERE',here),patch.object(C,'policy',side_effect=ValueError('UNBOUND')),patch.object(C,'held_source') as held:
                with self.assertRaisesRegex(ValueError,'UNBOUND'):F.freeze(root)
            held.assert_not_called();self.assertFalse((here/'source-manifest.json').exists())
            with patch.object(C,'HERE',here),patch.object(C,'policy',return_value={}),patch.object(C,'held_source'),patch.object(C,'verify_source'):
                result=F.freeze(root)
            self.assertEqual(result['status'],'FROZEN_SOURCE_ONLY');value=json.loads((here/'source-manifest.json').read_bytes())
            self.assertNotIn('scripts/ci/expanded604-composition/source-manifest.json',value['files'])
            self.assertNotIn('@OWNER_SHA256@',workflow.read_text());self.assertEqual(value['status'],'FROZEN_ROOT_FINAL_SOURCE')

    def test_workflow_shells_and_embedded_python_parse_without_execution(self):
        path=HERE.parents[2]/'.github/workflows/native-arm-expanded604.yml'
        text=path.read_text();lines=text.splitlines();blocks=[]
        for i,line in enumerate(lines):
            if line=='        run: |':
                body=[]
                for following in lines[i+1:]:
                    if following and not following.startswith('          '):break
                    body.append(following[10:])
                blocks.append('\n'.join(body)+'\n')
        self.assertGreater(len(blocks),10)
        for body in blocks:
            result=subprocess.run(['bash','-n'],input=body,text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            bodylines=body.splitlines()
            for i,line in enumerate(bodylines):
                if "<<'PY" in line:
                    marker=line.rsplit("<<'",1)[1].split("'",1)[0];end=bodylines.index(marker,i+1)
                    ast.parse('\n'.join(bodylines[i+1:end]))
        self.assertLess(text.index('--preflight'),text.index('secrets.CACHY_'))
        self.assertLess(text.index('Verify every actual accepted pair'),text.index('secrets.CACHY_'))
        for filename,marker in (('run.py','@OWNER_SHA256@'),('source-manifest.json','@MANIFEST_SHA256@')):
            prefix='test "$(sha256sum expanded604-code/scripts/ci/expanded604-composition/'+filename+" | cut -d ' ' -f 1)\" = "
            rows=[line.strip()[len(prefix):] for line in text.splitlines() if line.strip().startswith(prefix)]
            self.assertEqual(len(rows),1)
            self.assertTrue(rows[0]==marker or re.fullmatch('[0-9a-f]{64}',rows[0]) and rows[0]==C.sha(HERE/filename))
        self.assertIn('packet_raw_cap=4*1024**2',text);self.assertNotIn('upload-artifact',text)

    def test_retention_packets_preserve_full_files_and_shared_encoder_caps(self):
        text=(HERE.parents[2]/'.github/workflows/native-arm-expanded604.yml').read_text()
        body=text.split("          python3 -I -B - <<'PYRETAIN'\n",1)[1].split('          PYRETAIN\n',1)[0]
        tree=ast.parse('\n'.join(line[10:] for line in body.splitlines()))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir();target=root/'packets'
            data=b'first-frame-and-original-pair\n'*(170000)
            (source/'full.bin').write_bytes(data);(source/'empty.log').write_bytes(b'')
            for node in tree.body:
                if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                    name=node.targets[0].id
                    if name in ('source','target'):
                        node.value=ast.parse('pathlib.Path('+repr(str(source if name=='source' else target))+')',mode='eval').body
            exec(compile(ast.fix_missing_locations(tree),'<inert-public-packet-control>','exec'),{})
            index=json.loads((target/'part-0000/retention.json').read_bytes())
            self.assertEqual(index['bytes'],len(data));self.assertGreater(index['packet_count'],1)
            for name,row in index['files'].items():
                raw=b''.join((target/p['packet']/p['path']).read_bytes() for p in row['chunks'])
                self.assertEqual(raw,(source/name).read_bytes());self.assertEqual(hashlib.sha256(raw).hexdigest(),row['sha256'])
            encoder=C.load('_604_unmodified_log_encoder',SOURCE/'scripts/ci/log_evidence.py')
            for packet in target.iterdir():
                self.assertLess(sum(p.stat().st_size for p in packet.iterdir()),8*1024**2)
                self.assertTrue(encoder.bundle(packet))


if __name__=='__main__':unittest.main()
