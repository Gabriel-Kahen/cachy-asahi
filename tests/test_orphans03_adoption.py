#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure opt-in adoption/export controls; no build, installation or ALPM actors."""
import contextlib,hashlib,importlib.util,io,json,os,runpy,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
PRODUCT=ROOT/'packages/tools/cachy-asahi-orphans03'
ORIGINAL=ROOT/'packages/tools/cachy-asahi-orphans'
NAME='cachy-asahi-orphans';VERSION='0.3.0-2'
REVISION='4c64ddbb5cf7c018365287583df3d0efb8cfe686'
PINS={'PKGBUILD':'a023ae04c6ad73ef592df339aebc240860cfdd532a6977be695a05ba6b6f21d2',
      '.SRCINFO':'f2af13015b6d3679992ebf819d9039188f4caa366880f0e3c721fce45589fe01'}
ACTIVE=[False]
def guard(event,args):
    if not ACTIVE[0]:return
    if event=='ctypes.dlopen' and args[0] is not None:raise AssertionError('ALPM/library execution forbidden')
    if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.fork','os.exec','os.posix_spawn'):
        raise AssertionError('process/network actors forbidden')
sys.addaudithook(guard)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module

class Adoption(unittest.TestCase):
    def setUp(self):
        ACTIVE[0]=True;self.addCleanup(lambda:ACTIVE.__setitem__(0,False))
        temporary=tempfile.TemporaryDirectory(prefix='orphans03-',dir=ROOT/'tests');self.addCleanup(temporary.cleanup)
        self.work=Path(temporary.name);self.d=load('adoption_export_v2',ROOT/'scripts/release/recipe_source_delivery_v2.py')
        self.old=load('adoption_export_original',ROOT/'scripts/release/recipe_source_delivery.py')
    def source(self,path=PRODUCT):return self.d.source_set(NAME,lambda name:self.d.s.local_read(path,name,self.d.MAX_FILE))
    def pack(self,path=PRODUCT,label='pack',exporter=None):
        output=self.work/label;result=(exporter or self.d).pack(path,NAME,REVISION,output);return output,result
    def cli(self,path,*args):
        stdout,stderr=io.StringIO(),io.StringIO();code=0
        with patch.object(sys,'argv',[str(path),*args]),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            try:runpy.run_path(str(path),run_name='__main__')
            except SystemExit as error:code=error.code
        return code,stdout.getvalue(),stderr.getvalue()
    def staged(self,bodies):
        root=self.work/'installed';root.mkdir(mode=0o700)
        for name,(source,mode) in self.d.payload(NAME,VERSION).items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(bodies[source]);path.chmod(mode)
        return root
    def builder(self,version='build_v2'):return load('adoption_'+version,ROOT/'scripts/build'/(version+'.py'))
    def build_args(self,reviewed,output='future-build'):
        lock=self.work/'base.lock';lock.write_text('fixture-base 1-1\n')
        return ['build_v2.py',str(PRODUCT),'--image','sha256:'+'0'*64,'--output',str(self.work/output),
                '--mode','native','--source-date-epoch','1','--expected-packages',str(lock),
                '--reviewed-inputs',str(reviewed)]

    def test_exact_admitted_recipe_pair_and_all_eighteen_local_inputs(self):
        bodies,info=self.source();self.assertEqual(len(bodies),20);self.assertEqual(len(info['source']),18)
        self.assertEqual({p.name for p in PRODUCT.iterdir()if p.is_file()},set(bodies))
        self.assertEqual(info['pkgver'],['0.3.0']);self.assertEqual(info['pkgrel'],['2'])
        for name,pin in PINS.items():self.assertEqual(hashlib.sha256(bodies[name]).hexdigest(),pin)
        for name,pin in zip(info['source'],info['sha256sums']):self.assertEqual(hashlib.sha256(bodies[name]).hexdigest(),pin)

    def test_explicit_version_selects_twelve_actual_successor_payload_files(self):
        selected=self.d.payload(NAME,VERSION);self.assertEqual(len(selected),12)
        self.assertEqual(selected['usr/bin/'+NAME],('orphans3',0o755))
        for name in ('remove.py','live.py','live_policy.py','readonly.py','protection-floor.json'):
            self.assertIn('usr/lib/cachy-asahi-orphans3/'+name,selected)
        self.assertEqual(self.d.payload(NAME),self.old.payload(NAME));self.assertNotEqual(self.d.payload(NAME),selected)

    def test_original_defaults_and_every_original_exact_profile_are_held(self):
        self.assertEqual(self.d.PROFILES,self.old.PROFILES)
        for key,value in self.old.LEGACY_PROFILES.items():self.assertEqual(self.d.LEGACY_PROFILES[key],value)
        self.assertEqual(self.d.profile(NAME)['version'],'0.1.0-2')
        self.assertEqual(self.d.profile(NAME,VERSION)['version'],VERSION)
        for invalid in ('0.3.0','0.3.0-3','latest'):
            with self.subTest(version=invalid),self.assertRaises(ValueError):self.d.profile(NAME,invalid)

    def test_original_bundle_bytes_remain_identical_through_both_entrypoints(self):
        a,old=self.pack(ORIGINAL,'old',self.old);b,new=self.pack(ORIGINAL,'old-v2')
        self.assertEqual((a/'source.tar').read_bytes(),(b/'source.tar').read_bytes());self.assertEqual(old,new)
        self.assertEqual(old['package']['version'],'0.1.0-2')

    def test_new_recipe_requires_the_explicit_versioned_exporter(self):
        with self.assertRaises(ValueError):self.old.source_set(NAME,lambda key:(PRODUCT/key).read_bytes())
        self.assertEqual(self.d.source_profile(NAME,self.source()[0])['version'],VERSION)

    def test_new_export_is_deterministic_and_never_claims_an_archive_or_native_run(self):
        a,first=self.pack(label='first');b,second=self.pack(label='second')
        self.assertEqual(first,second);self.assertEqual((a/'source.tar').read_bytes(),(b/'source.tar').read_bytes())
        saved=json.loads((a/'bundle.json').read_bytes());self.assertEqual(saved['package']['version'],VERSION)
        self.assertEqual(saved['archive_status'],'UNBOUND_NO_ARCHIVE_SUPPLIED');self.assertIsNone(saved['archive_binding'])
        self.assertEqual(saved['native_build'],'NOT_RUN');self.assertEqual(saved['alpm_installation'],'NOT_RUN')
        self.assertEqual(saved['release'],'NOT_ADMITTED')

    def test_export_roundtrip_preserves_complete_recipe_and_relocates(self):
        output,result=self.pack();saved,bodies=self.d.unpacked((output/'source.tar').read_bytes(),result['bundle_sha256'])
        self.assertEqual(bodies,self.source()[0]);self.assertEqual(saved['package']['version'],VERSION)
        relocated=self.work/'relocated';self.d.write_fresh(relocated,bodies)
        self.assertEqual(self.source(relocated)[0],bodies)
        self.assertEqual(self.cli(relocated/'orphans3','--version'),(0,'cachy-asahi-orphans 0.3.0\n',''))

    def test_source_and_installed_layout_cli_help_resolve_actual_backends(self):
        bodies,_=self.source();staged=self.staged(bodies)
        for path in (PRODUCT/'orphans3',staged/'usr/bin'/NAME):
            for args in (('--version',),('--help',),('remove','--help'),('live','--help'),('live','assess','--help'),('live','plan','--help'),('live','remove','--help')):
                with self.subTest(path=str(path),args=args):
                    code,stdout,stderr=self.cli(path,*args);self.assertEqual(code,0,stderr);self.assertTrue(stdout)
            self.assertIn('0.3.0',self.cli(path,'--version')[1]);self.assertIn('--authorize-live-removal',self.cli(path,'live','remove','--help')[1])

    def test_staged_payload_exact_bytes_modes_and_namespace(self):
        bodies,_=self.source();root=self.staged(bodies);payload=self.d.payload(NAME,VERSION)
        self.assertEqual({p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()},set(payload))
        for name,(source,mode)in payload.items():
            path=root/name;self.assertEqual(path.read_bytes(),bodies[source]);self.assertEqual(path.stat().st_mode&0o777,mode)

    def test_live_commands_cannot_fall_back_to_an_implicit_host_target(self):
        for command in ('assess','plan','remove'):
            code,_,stderr=self.cli(PRODUCT/'orphans3','live',command)
            self.assertEqual(code,2);self.assertIn('--target-root',stderr)

    def test_original_cli_remains_read_only_version(self):
        code,stdout,stderr=self.cli(ORIGINAL/NAME,'--version')
        self.assertEqual(code,0,stderr);self.assertIn('0.1.0',stdout)
        self.assertNotIn('explicit live backend',self.cli(ORIGINAL/NAME,'--help')[1].lower())

    def test_changed_product_bytes_and_changed_recipe_pair_are_refused(self):
        original,_=self.source()
        for name in ('live.py','remove.py','PKGBUILD','.SRCINFO'):
            bodies=dict(original);bodies[name]+=b'\n'
            with self.subTest(name=name),self.assertRaises(ValueError):self.d.source_set(NAME,bodies.__getitem__)

    def test_wrong_bundle_checksum_and_tampered_self_consistent_tar_are_refused(self):
        output,result=self.pack();raw=(output/'source.tar').read_bytes()
        with self.assertRaises(ValueError):self.d.unpacked(raw,'0'*64)
        saved,bodies=self.d.unpacked(raw,result['bundle_sha256']);bodies['live.py']+=b'\n'
        tampered=self.d.tar_bytes(dict(bodies,**{'bundle.json':self.d.encoded(saved)}))
        with self.assertRaises(ValueError):self.d.unpacked(tampered,self.d.s.digest(tampered))

    def test_export_refuses_existing_output_and_source_aliases(self):
        self.pack()
        with self.assertRaises(FileExistsError):self.pack()
        recipe=self.work/'aliased';shutil.copytree(PRODUCT,recipe);target=recipe/'live.py';target.unlink();target.symlink_to(PRODUCT/'live.py')
        with self.assertRaises((OSError,ValueError)):self.source(recipe)

    def test_both_builders_accept_exact_inputs_until_the_explicit_docker_boundary(self):
        for version in ('build','build_v2'):
            build=self.builder(version);report=build.recipe(PRODUCT/'PKGBUILD');self.assertEqual(report['errors'],[])
            self.assertEqual(len(report['input_sha256']),20);self.assertEqual(report['input_sha256']['PKGBUILD'],PINS['PKGBUILD'])
            self.assertEqual(report['input_sha256'],json.loads((ROOT/'scripts/build/orphans03-inputs.json').read_bytes()))
            self.assertIsNone(build.bind_generated(report['metadata'],report['metadata']))
            reviewed=self.work/'reviewed.json';reviewed.write_text(json.dumps(report['input_sha256']))
            class StopBeforeActor(RuntimeError):pass
            with self.subTest(builder=version),patch.object(sys,'argv',self.build_args(reviewed)),patch.object(build,'capture',side_effect=StopBeforeActor('source checks reached Docker boundary'))as capture:
                with self.assertRaisesRegex(StopBeforeActor,'Docker boundary'):build.main()
            capture.assert_called_once_with(['docker','image','inspect','sha256:'+'0'*64]);self.assertFalse((self.work/'future-build').exists())

    def test_build_v2_rejects_wrong_independently_reviewed_inputs_before_docker(self):
        build=self.builder();report=build.recipe(PRODUCT/'PKGBUILD');inputs=dict(report['input_sha256'],PKGBUILD='0'*64)
        reviewed=self.work/'wrong-reviewed.json';reviewed.write_text(json.dumps(inputs));stderr=io.StringIO()
        with patch.object(sys,'argv',self.build_args(reviewed)),patch.object(build,'capture',side_effect=AssertionError('Docker forbidden'))as capture,contextlib.redirect_stderr(stderr):
            self.assertEqual(build.main(),1)
        self.assertIn('independently reviewed digest set',stderr.getvalue());capture.assert_not_called()

if __name__=='__main__':unittest.main()
