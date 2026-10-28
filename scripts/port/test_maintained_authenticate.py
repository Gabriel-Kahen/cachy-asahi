# SPDX-License-Identifier: MIT
"""Portable Source/data/temp-FS controls; authentication actors remain mocked."""
import ast
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import maintained_authenticate as m
ROOT = Path(os.environ.get('MAINTAINED_AUTH_SOURCE_ROOT', HERE.parents[1]))


class MaintainedBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.legacy = m.engine(ROOT)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.profile = json.loads((ROOT/'manifests/proposals/maintained-desktop-archives-v1.json').read_bytes()) if (ROOT/'manifests/proposals/maintained-desktop-archives-v1.json').exists() else json.loads((HERE.parents[1]/'manifests/proposals/maintained-desktop-archives-v1.json').read_bytes())
        proposal = json.loads((ROOT/'manifests/proposals/maintained-desktop-v1.json').read_bytes())
        builder = json.loads((ROOT/'scripts/ci/maintained-native/locks/inputs-successor.lock.json').read_bytes())
        archives = json.loads((ROOT/'scripts/port/refreshed-desktop/desktop-archives-proposal.json').read_bytes())
        seedraw = (ROOT/'scripts/ci/maintained-native/locks/builder-successor.lock').read_bytes()
        baseline = m.inventory(seedraw); final = baseline | {r['name']:r['version'] for r in archives['packages']}
        finalraw = ''.join(n+' '+v+'\n' for n,v in sorted(final.items())).encode()
        # Real canonical historical metadata, with only the maintained Vim pair
        # substituted. Terminal records below are explicit inert model facts.
        worker = json.loads((ROOT/'scripts/port/refreshed-desktop/receipt.json').read_bytes())
        inputs = {r['name']:r for r in builder['packages']}
        fields = {'name':'name','version':'version','arch':'arch','depends':'depends','provides':'provides','conflicts':'conflicts','replaces':'replaces','license':'license_metadata','source_url':'upstream_url','filename':'archive_filename','sha256':'archive_sha256'}
        for r in worker['full_candidate_inventory']:
            if r['name'][0] in ('vim','vim-runtime'):
                original = inputs[r['name'][0]]
                for key,target in fields.items(): r[target] = original[key] if type(original[key]) is list else [original[key]]
        for r in worker['dependency_relationships']:r['relation'] = r['relation'].replace('9.2.1164-2','9.2.1178-1')
        worker['changes'] = [dict(name=r['name'],version=r['version'],kind='add',download_bytes=r['size']) for r in sorted(archives['packages'],key=lambda r:r['name'])]
        worker.update(status='PASS-generic-maintained-metadata-resolution',phase='complete',builder_input_sha256=m.CURRENT['builder-input.json'],seed_inventory_sha256=m.CURRENT['seed341.lock'],unchanged233_archive_identity_sha256=m.CURRENT['archives233.json'],first_failure=None,cancelled=False)
        context='/fixture/artifacts/maintained-desktop-resolution-run-unit/private-context'
        prefix=['/usr/bin/pacman']
        for flag,name in [('--config','pacman.conf'),('--root','root'),('--dbpath','db'),('--cachedir','cache'),('--gpgdir','gpg'),('--hookdir','hooks'),('--logfile','pacman.log')]:prefix += [flag,context+'/'+name]
        prefix += ['--arch','aarch64','--color','never']
        targets=[r['name']+'='+r['version'] for r in proposal['roots']+proposal['provider_constraints']]
        deps=sorted({r['relation'] for r in worker['dependency_relationships']})
        commands=[prefix+['--sync','--print','--needed','--noconfirm','--print-format','%n\t%v\t%r\t%a\t%s\t%h']+targets]+[prefix+['--deptest']+deps[i:i+200] for i in range(0,len(deps),200)]
        worker['commands']=[dict(argv=a,state='RETURNED',exit=0,natural_exit=True,cleanup_verified=True) for a in commands]
        parent=dict(status=worker['status'],worker_exit=0,natural_exit=True,cleanup_verified=True,first_failure=None,cancelled=False,worker_receipt_sha256=m.sha(m.encoded(worker)))
        outer=dict(exit_code=0,natural_exit=True,within_envelope=True,first_failure=None,failure=None,cancelled=False,signals_sent=[],entered_monotonic=10.0,ended_monotonic=11.0,work_end=310.0,end=314.0)
        completion=dict(status='PASS_ACTUAL_HOST_PRIVATE_MAINTAINED_METADATA_RESOLUTION',final_inventory_sha256=m.sha(finalraw),initial_count=341,final_count=574,additions=233,changes_to_baseline=0,natural_parent_and_worker=True,new_source_signature_archive_installation_native_ARM_Asahi_hardware_release_admission=False,indexed_files={'artifacts/maintained-desktop-resolution-run-unit/final574.lock':{'sha256':m.sha(finalraw)}})
        self.data=dict(zip(['proposal.json','builder-input.json','archives233.json','worker.json','parent.json','outer.json','completion.json'],[proposal,builder,archives,worker,parent,outer,completion]))
        self.blobs={n:m.encoded(v) for n,v in self.data.items()}|{'seed341.lock':seedraw,'expected574.lock':finalraw}
        for name,path in [('proposal.json','manifests/proposals/maintained-desktop-v1.json'),('builder-input.json','scripts/ci/maintained-native/locks/inputs-successor.lock.json'),('archives233.json','scripts/port/refreshed-desktop/desktop-archives-proposal.json')]:self.blobs[name]=(ROOT/path).read_bytes()
        pins={n:m.sha(raw) for n,raw in self.blobs.items()};self.profile['files_sha256']=pins
        self.pins=patch.object(m,'CURRENT',pins);self.pins.start();self.addCleanup(self.pins.stop)
        self.seed,self.final=baseline,final

    def validate(self):m.validate_resolution(self.data,self.seed,self.final)

    def test_current_model_reaches_held_validation_with_only_three_derived_bindings(self):
        result=m.prepare(self.profile,self.blobs,self.legacy);old=self.data['archives233.json'];keys={'proposal_sha256','preview_receipt_sha256','builder_lock_sha256'}
        self.assertEqual({k:v for k,v in result.items() if k not in keys},{k:v for k,v in old.items() if k not in keys})
        self.assertEqual(result['packages'],old['packages']);self.assertEqual(result['builder_lock_sha256'],m.CURRENT['builder-input.json'])
        self.legacy.validate(result)
    def test_legacy_status_and_mixed_binding_profiles_refuse(self):
        for field,value in [('status','PASS-generic-metadata-preview'),('builder_input_sha256','0'*64),('seed_inventory_sha256','1'*64),('unchanged233_archive_identity_sha256','2'*64)]:
            data=copy.deepcopy(self.data);data['worker.json'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):m.validate_resolution(data,self.seed,self.final)
        original=self.blobs['worker.json'];self.blobs['worker.json']=m.encoded(self.data['archives233.json'])
        with self.assertRaisesRegex(ValueError,'profile-inputs'):m.prepare(self.profile,self.blobs,self.legacy)
        self.blobs['worker.json']=original
    def test_raw_hashes_duplicates_and_boolean_profile_values_refuse(self):
        for name in self.blobs:
            poisoned=self.blobs|{name:self.blobs[name]+b' '}
            with self.subTest(name=name),self.assertRaises(ValueError):m.prepare(self.profile,poisoned,self.legacy)
        for field in ('schema_version','package_count','expected_final_count'):
            with self.subTest(field=field),self.assertRaises(ValueError):m.prepare(self.profile|{field:True},self.blobs,self.legacy)
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ValueError):m.document(raw)
    def test_third_seed_change_and_addition_relation_disagreement_refuse(self):
        changed=self.seed.copy();name=next(n for n in changed if n not in ('vim','vim-runtime'));changed[name]='99-1'
        with self.assertRaises(ValueError):m.validate_resolution(self.data,changed,self.final)
        self.data['archives233.json']['packages'][0]['depends'].append('unreviewed')
        with self.assertRaises(ValueError):self.validate()
    def test_root_provider_snapshot_and_key_changes_refuse(self):
        for section,field in [('proposal.json','roots'),('proposal.json','provider_constraints'),('proposal.json','snapshots'),('builder-input.json','keyring_files')]:
            data=copy.deepcopy(self.data);data[section][field]=[]
            with self.subTest(field=field),self.assertRaises(ValueError):m.validate_resolution(data,self.seed,self.final)
    def test_partial_failure_cancelled_uncertain_or_boolean_terminals_refuse(self):
        variants=[('worker.json','phase','prepare'),('worker.json','first_failure',{}),('parent.json','cancelled',True),('parent.json','cleanup_verified',False),('parent.json','worker_exit',True),('outer.json','exit_code',True),('outer.json','natural_exit',False),('outer.json','within_envelope',False)]
        for name,field,value in variants:
            data=copy.deepcopy(self.data);data[name][field]=value
            with self.subTest(name=name,field=field),self.assertRaises(ValueError):m.validate_resolution(data,self.seed,self.final)
    def test_clock_renewal_nonfinite_and_partial_deptest_refuse(self):
        for value in (float('nan'),True,311.0):
            data=copy.deepcopy(self.data);data['outer.json']['work_end']=value
            with self.subTest(value=value),self.assertRaises(ValueError):m.validate_resolution(data,self.seed,self.final)
        self.data['worker.json']['commands'][-1]['argv'].pop()
        with self.assertRaises(ValueError):self.validate()
    def test_host_paths_install_flags_foreign_returns_and_unsafe_context_refuse(self):
        for transform in (lambda a:a+['--refresh'],lambda a:[*a[:a.index('--dbpath')+1],'/var/lib/pacman',*a[a.index('--dbpath')+2:]],lambda a:a[:-1]):
            data=copy.deepcopy(self.data);data['worker.json']['commands'][0]['argv']=transform(data['worker.json']['commands'][0]['argv'])
            with self.assertRaises(ValueError):m.validate_resolution(data,self.seed,self.final)
        self.data['worker.json']['commands'][1]['exit']=4
        with self.assertRaises(ValueError):self.validate()
    def test_symlink_hardlink_writable_and_replaced_pinned_inputs_refuse(self):
        p=self.root/'input';p.write_bytes(b'bound');pin=m.sha(b'bound');self.assertEqual(m.read(p,pin),b'bound')
        p.chmod(0o622)
        with self.assertRaises(ValueError):m.read(p,pin)
        p.chmod(0o600);q=self.root/'hard';os.link(p,q)
        with self.assertRaises(ValueError):m.read(p,pin)
        q.unlink();q.symlink_to(p)
        with self.assertRaises(ValueError):m.read(q,pin)
        p.write_bytes(b'other')
        with self.assertRaises(ValueError):m.read(p,pin)
    def test_helper_code_hash_is_required_before_raw_function_loading(self):
        fake=self.root/'source';fake.mkdir();p=fake/'scripts/port/authenticate.py';p.parent.mkdir(parents=True);p.write_bytes(b'raise AssertionError("never execute")\n')
        with self.assertRaises(ValueError):m.engine(fake)
    def test_partial_authentication_is_fail_and_keeps_receipt_and_233_input(self):
        keys=self.root/'keys';keys.mkdir();out=self.root/'result'
        with patch.object(self.legacy,'authenticate',return_value=dict(status='FAIL-incomplete-archive-authentication',verified_count=232,failures=[{'name':'fixture'}])) as actor:
            result=m.execute(self.profile,self.blobs,self.legacy,keys,out)
        self.assertEqual(result['status'],'FAIL');self.assertEqual(result['authenticated_count'],232);self.assertEqual(actor.call_args.args[0]['packages'],self.data['archives233.json']['packages']);self.assertTrue((out/'maintained-binding.json').is_file())
    def test_control_failure_survives_secondary_binding_receipt_failure(self):
        keys=self.root/'keys';keys.mkdir();control=KeyboardInterrupt('controlled')
        with patch.object(self.legacy,'authenticate',side_effect=control),patch.object(self.legacy.native,'save',side_effect=OSError('secondary')):
            with self.assertRaises(KeyboardInterrupt) as caught:m.execute(self.profile,self.blobs,self.legacy,keys,self.root/'out')
        self.assertIs(caught.exception,control)
        with patch.object(self.legacy,'authenticate',side_effect=control),patch.object(self.legacy.native,'save',side_effect=SystemExit('secondary')):
            with self.assertRaises(KeyboardInterrupt) as caught:m.execute(self.profile,self.blobs,self.legacy,keys,self.root/'out-secondary')
        self.assertIs(caught.exception,control)
    def test_exact_loaded_engine_signature_gate_and_233_iteration_with_stubbed_io(self):
        # Trust I/O is explicitly stubbed: this exercises the real held engine
        # and loaded helper closure, never actual key import or authentication.
        effective=m.prepare(self.profile,self.blobs,self.legacy);keys=self.root/'keys';keys.mkdir()
        key_pins={}
        for row in effective['keyring_files']:
            path=keys/row['filename'];path.write_bytes(b'x'*row['size']);key_pins[path]=row['sha256']
        original_sha=self.legacy.native.sha
        def digest(path):return key_pins[path] if path in key_pins else original_sha(path)
        good=f'[GNUPG:] VALIDSIG {self.legacy.SIGNER} 2026-08-05 1785933702 0 4 0 1 10 00 {self.legacy.SIGNER}\n'
        def run(argv,**kwargs):return m.subprocess.CompletedProcess(argv,0,'gpg fixture\n' if '--version' in argv else good,'')
        with patch.object(self.legacy,'CACHE',self.root/'cache'),patch.object(self.legacy.native,'sha',side_effect=digest),patch.object(self.legacy.subprocess,'run',side_effect=run) as command,patch.object(self.legacy,'fetch') as fetch,patch.object(self.legacy,'observe',return_value=dict(path_count=0,ELF=[],hooks_and_scriptlets=[])):
            result=m.execute(self.profile,self.blobs,self.legacy,keys,self.root/'out')
        self.assertEqual(result['status'],'PASS-233-maintained-authenticated-archives');self.assertEqual(fetch.call_count,466)
        self.assertEqual(sum('--verify' in c.args[0] for c in command.call_args_list),233)
        for text,code in [(good.replace(self.legacy.SIGNER,'A'*40),0),(good+good,0),(good+'[GNUPG:] NODATA 1\n',0),(good,1)]:
            with self.subTest(code=code),self.assertRaises(ValueError):self.legacy.status(m.subprocess.CompletedProcess([],code,text,''))

    def test_preview_does_not_authenticate_and_existing_output_refuses(self):
        keys=self.root/'keys';keys.mkdir()
        with patch.object(self.legacy,'authenticate',side_effect=AssertionError('actor reached')):
            m.prepare(self.profile,self.blobs,self.legacy)
            with self.assertRaises(ValueError):m.execute(self.profile,self.blobs,self.legacy,keys,self.root)


if __name__ == '__main__': unittest.main()
