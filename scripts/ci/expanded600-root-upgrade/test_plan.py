"""Real held exporter plus inert tempfile protocol inputs; no native/signing actors."""
import hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
CANONICAL=ROOT/'scripts/ci/expanded600-root-upgrade'
sys.path.insert(0,str(CANONICAL))
import contract as C

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
owner=load('_plan_fixed_owner',HERE/'run.py')
producer_path=ROOT/'scripts/ci/full-composition-installer-vm/producer.py'
assert hashlib.sha256(producer_path.read_bytes()).hexdigest()=='98d61944888485870b31b5457bcad9edfd8e51cb367414833f8d54611d7b0eaf'

class PlanProtocol(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='root600-real-export-data-');self.root=Path(self.temp.name)
        self.addCleanup(self.cleanup)
        self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
        self.p=load('_plan_actual_producer_'+str(id(self)),producer_path);self.calls=[]
        outer=self
        class Verifier:
            def __init__(self,*a):pass
            def __call__(self,archive,signature,signer):outer.calls.append((archive.name,signer))
            def close(self):pass
        self.verifier=Verifier
        self.args=NS(output=self.root/'producer')
    def cleanup(self):
        for p in self.root.rglob('*'):
            if p.is_dir():p.chmod(0o700)
        self.temp.cleanup()
    def prepared(self,args,badkey=False):
        raw=args.output/'private';inputs=raw/'inputs';inputs.mkdir(parents=True);deps=raw/'desktop574/context/deps';deps.mkdir(parents=True)
        base=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
        lock=(ROOT/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_bytes()
        baseline={r['name'] for r in base['packages'] if r['name']!='libfdk-aac'}
        additions=[dict(name=n,version=v) for n,v in (l.split() for l in lock.decode().splitlines()) if n not in baseline]
        for row in base['packages']+additions:
            data=b'inert-archive';sig=b'inert-signature';row.update(filename=row['name']+'.pkg.tar.xz',sha256=hashlib.sha256(data).hexdigest(),size=len(data),signature_sha256=hashlib.sha256(sig).hexdigest(),signature_size=len(sig))
            home=inputs if row in additions else deps;(home/row['filename']).write_bytes(data);(home/(row['filename']+'.sig')).write_bytes(sig)
        (inputs/'expected-installed.lock').write_bytes(lock);(raw/'desktop574/installed-packages.lock').write_bytes(self.p.inventory(base['packages']))
        alarm=b'inert-upstream-public';(inputs/'archlinuxarm.gpg').write_bytes(alarm);(inputs/'TEST-public.asc').write_bytes(b'inert-TEST-public')
        base['keyring_files']=[dict(filename='archlinuxarm.gpg',sha256='0'*64 if badkey else hashlib.sha256(alarm).hexdigest(),size=len(alarm))]
        projects=[dict(name=r['name'],payload=[]) for r in additions if r['name'].startswith('cachy-asahi-')]
        helpers={}
        for name in ('core-lifecycle.py','provider-helpers.py'):
            raw_helper=('inert-original-'+name).encode();(inputs/name).write_bytes(raw_helper);helpers[name]=dict(size=len(raw_helper),sha256=hashlib.sha256(raw_helper).hexdigest())
        (inputs/'expectedbase.lock').write_bytes(self.p.inventory(base['packages']))
        self.plan=dict(packages=additions,projects=projects,hooks=['original-hook-fixture'],signer_fingerprint=base['signer_fingerprint'],test_signer_fingerprint='A'*40,setup4=dict(helpers=helpers))
        held=dict(inputs=inputs,checkpoint_sha=self.p.EXPECTED,plan=self.plan)
        # Real exporter API. The producer's pre-volume contract never writes plan.json.
        return self.p.export_ready(raw,raw/'ready',held,base,{'scope':'inert API fixture only'},verifier_factory=self.verifier)
    def test_real587_export_returns_exact_plan_without_plan_file_and_restores_api(self):
        original=self.p.export_ready;self.p.prepare=self.prepared
        ready,plan=owner.prepare_with_plan(self.p,self.args)
        self.assertEqual(plan,self.plan);self.assertIsNot(plan,self.plan);self.assertIs(self.p.export_ready,original)
        self.assertFalse((self.args.output/'private/inputs/plan.json').exists())
        self.assertEqual(json.loads((ready/'manifest.json').read_bytes())['status'],'READY_SIGNED_INITIAL587')
        self.assertEqual(len(self.calls),587);self.assertEqual(sum(s=='A'*40 for _,s in self.calls),10)
    def flat_fixture(self):
        self.p.prepare=self.prepared;_,plan=owner.prepare_with_plan(self.p,self.args)
        ready=self.root/'expanded600';(ready/'packages').mkdir(parents=True)
        before,_=C.locks();rows=[];projects=[dict(name=n) for n in before if n.startswith('cachy-asahi-')]
        selected={r['name'] for r in projects}|owner.adapter.AUDIO|{'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}
        for n,v in before.items():
            raw=('inert-'+n).encode();sig=b'inert-signature';archive='packages/'+n+'.pkg.tar.xz'
            rows.append(dict(name=n,version=v,archive=archive,signature=archive+'.sig',size=len(raw),sha256=hashlib.sha256(raw).hexdigest(),signature_size=len(sig),signature_sha256=hashlib.sha256(sig).hexdigest()))
            if n in selected:(ready/archive).write_bytes(raw);(ready/(archive+'.sig')).write_bytes(sig)
        (ready/'expected-installed.lock').write_bytes((C.HERE/'before600.lock').read_bytes());(ready/'manifest.json').write_bytes(C.encoded(dict(status='READY_SIGNED_EXPANDED600',packages=rows,projects=projects)))
        return ready,plan,rows
    def test_real_flat600_stage_uses_captured_hooks_signers_helpers_and_exact27_files(self):
        ready,plan,_=self.flat_fixture()
        target=owner.flat_inputs(ready,self.args.output/'private',self.root/'flat',plan);result=json.loads((target/'plan.json').read_bytes())
        self.assertEqual(len(result['packages']),27);self.assertEqual(len(result['projects']),17)
        for key in ('hooks','signer_fingerprint','test_signer_fingerprint'):self.assertEqual(result[key],plan[key])
        self.assertEqual(result['setup4'],dict(helpers=plan['setup4']['helpers']));self.assertTrue(result['full_root_upgrade'])
        self.assertEqual((target/'expected-installed.lock').read_bytes(),(C.HERE/'before600.lock').read_bytes())
        self.assertFalse((self.args.output/'private/inputs/plan.json').exists())
    def large_lsp(self):
        ready,plan,rows=self.flat_fixture();row=next(r for r in rows if r['name']=='lsp-plugins-lv2')
        pinned=next(r for r in json.loads((ROOT/'scripts/ci/full-development-composition/audio-inputs.json').read_bytes()) if r['name']==row['name'])
        self.assertEqual(pinned['size'],5587560)
        path=ready/row['archive'];path.write_bytes(b'L'*pinned['size']);row.update(size=path.stat().st_size,sha256=C.sha(path))
        manifest=C.read(ready/'manifest.json');manifest['packages']=rows;(ready/'manifest.json').write_bytes(C.encoded(manifest))
        return ready,plan,row,path
    def test_exact_lsp_size_stages_all27_while_default_reference_and_json_refuse(self):
        ready,plan,row,path=self.large_lsp();ref=dict(path=row['archive'],bytes=row['size'],sha256=row['sha256'])
        with self.assertRaisesRegex(ValueError,'closed byte reference'):C.checked(ready,ref)
        with self.assertRaisesRegex(ValueError,'bounded ordinary JSON'):C.read(path)
        target=owner.flat_inputs(ready,self.args.output/'private',self.root/'flat-large',plan)
        staged=C.read(target/'plan.json');self.assertEqual(len(staged['packages']),27)
        self.assertEqual(len(staged['projects']),17);self.assertEqual(C.sha(target/path.name),row['sha256'])
        self.assertEqual((target/path.name).stat().st_size,5587560)
    def test_archive_cap_keeps_digest_hardlink_and_finite_size_refusals(self):
        ready,_,row,path=self.large_lsp();ref=dict(path=row['archive'],bytes=row['size'],sha256=row['sha256'])
        with self.assertRaisesRegex(ValueError,'identity differs'):C.checked(ready,ref|{'sha256':'0'*64},cap=8*1024**2)
        alias=ready/'alias';os.link(path,alias)
        with self.assertRaisesRegex(ValueError,'identity differs'):C.checked(ready,ref,cap=8*1024**2)
        alias.unlink()
        path.write_bytes(b'X'*(8*1024**2+1));ref.update(bytes=path.stat().st_size,sha256=C.sha(path))
        with self.assertRaisesRegex(ValueError,'closed byte reference'):C.checked(ready,ref,cap=8*1024**2)
    def test_flat_stage_does_not_raise_detached_signature_limit(self):
        ready,plan,row,_=self.large_lsp();signature=ready/row['signature'];signature.write_bytes(b'S'*(4*1024**2+1))
        manifest=C.read(ready/'manifest.json');held=next(r for r in manifest['packages'] if r['name']==row['name'])
        held.update(signature_size=signature.stat().st_size,signature_sha256=C.sha(signature))
        (ready/'manifest.json').write_bytes(C.encoded(manifest))
        with self.assertRaisesRegex(ValueError,'closed byte reference'):
            owner.flat_inputs(ready,self.args.output/'private',self.root/'flat-large-signature',plan)
    def test_real_export_refusal_restores_original_api_and_exposes_no_plan(self):
        original=self.p.export_ready;self.p.prepare=lambda args:self.prepared(args,badkey=True)
        with self.assertRaisesRegex(ValueError,'ALARM keyring pin differs'):owner.prepare_with_plan(self.p,self.args)
        self.assertIs(self.p.export_ready,original);self.assertFalse((self.args.output/'private/inputs/plan.json').exists())
    def test_ready_path_without_original_export_cannot_supply_a_plan(self):
        original=self.p.export_ready;self.p.prepare=lambda args:args.output/'private/ready'
        with self.assertRaisesRegex(ValueError,'successful original export'):owner.prepare_with_plan(self.p,self.args)
        self.assertIs(self.p.export_ready,original)

if __name__=='__main__':
    inherited=load('_plan_held_result_controls',CANONICAL/'test_lane.py');inherited.owner=owner
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(PlanProtocol),unittest.defaultTestLoader.loadTestsFromTestCase(inherited.ResultControls)])
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
