# SPDX-License-Identifier: MIT
"""Real adapter cleanup/compare seams with mocked Docker; no native credit."""
import importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from test_batch_v2_fixture import Fixture,NAMES
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('v2_builder_seams',HERE.parent/'scripts/maintenance/build_batch_v2.py');V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)

class BuilderControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.f=Fixture(V,self.root);self.a=self.f.admit();self.t=self.a['tasks'][NAMES[0]];self.b=V.Builder(self.a)
        self.out=self.root/'build';self.out.mkdir(mode=0o700);s=V.SM.stage(V.prepare_task(self.t),self.out/'source-material')
        (self.out/'artifacts').mkdir();(self.out/'artifacts/packages.lock').write_bytes(V.B.read(self.t['expected_packages']));(self.out/'validation.json').write_bytes(V.encoded({'errors':[]}))
        self.r=dict(recipe_metadata=self.f.reports[NAMES[0]]['metadata'],image=self.t['image'],image_id=self.t['image'],mode=self.t['mode'],source_date_epoch=self.t['source_date_epoch'],recipe_inputs=self.t['recipe_inputs'],expected_packages_sha256=self.t['expected_packages_sha256'],entry_script_sha256=V.B.digest(V.ROOT/'scripts/build/container-entry-v2.sh'),network='none',source_material=s,files={'source-material/'+p:h for p,h in self.t['source_material_files'].items()},artifacts={'fake.pkg.tar.xz':'a'*64})
        self.save()
    def save(self):(self.out/'provenance.json').write_bytes(V.encoded(self.r))
    def test_verify_source_provenance_is_type_exact(self):
        real=V.B.module
        class Compare:
            def verify(inner,path):return self.r,{'fake.pkg.tar.xz':{}}
        def module(name,path):return Compare()if Path(path).name=='compare_v2.py'else real(name,path)
        with patch.object(V.B,'module',side_effect=module):
            self.assertEqual(self.b.verify(self.t,self.out),'a'*64)
            self.r['source_material']['legal_acceptance']=0;self.save()
            with self.assertRaisesRegex(ValueError,'source-material provenance'):self.b.verify(self.t,self.out)
    def owned(self):
        name='cachy-asahi-'+'b'*16;self.r['clean_environment_id']=name
        mounts=[(self.out/'inputs','/inputs',False),(self.out/'artifacts','/out',True),(V.ROOT/'scripts/build/container-entry-v2.sh','/builder-entry.sh',False),(self.out/'expected-packages.lock','/expected-packages.lock',False),(self.out/'source-material/srcdest','/offline-sources',False)]
        command=['docker','run','--rm','--name',name]
        for s,d,rw in mounts:command+=['--mount','type=bind,src='+str(s)+',dst='+d+(''if rw else',readonly')]
        self.r['command']=command+['--entrypoint','/bin/bash',self.t['image'],'/builder-entry.sh'];self.save()
        return dict(Name='/'+name,Image=self.r['image_id'],Config=dict(Image=self.t['image']),Mounts=[dict(Type='bind',Source=str(s),Destination=d,RW=rw)for s,d,rw in mounts])
    def test_cleanup_exact_owned_source_mount(self):
        row=self.owned();calls=[]
        def run(argv,**kw):calls.append(argv);return subprocess.CompletedProcess(argv,0,json.dumps([row])if argv[1]=='container'else'','')
        with patch.object(V.subprocess,'run',side_effect=run):self.b.cleanup(self.t,self.out)
        self.assertEqual([c[1]for c in calls],['container','rm','ps'])
    def test_post_build_cache_permissions_are_revalidated(self):
        obj=next((self.f.cache/'objects').iterdir());obj.chmod(0o644)
        try:
            with self.assertRaisesRegex(ValueError,'private owned cache'):
                self.b.verify(self.t,self.out)
        finally:obj.chmod(0o600)
    def test_prepared_cache_object_cannot_change_before_dependency_pin(self):
        prepared=V.prepare_task(self.t);obj=next((self.f.cache/'objects').iterdir());obj.chmod(0o600);obj.write_bytes(b'changed after prepare')
        with self.assertRaisesRegex(ValueError,'changed after preparation'):
            V.source_dependencies(self.t['offline_sources'],prepared)
    def test_cleanup_foreign_mount_or_daemon_error_never_removes(self):
        row=self.owned();row['Mounts'][-1]['RW']=True
        with patch.object(V.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps([row]),''))as run:
            with self.assertRaisesRegex(ValueError,'ownership differs'):self.b.cleanup(self.t,self.out)
        self.assertEqual(run.call_count,1)
        with patch.object(V.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','daemon down'))as run:
            with self.assertRaisesRegex(ValueError,'absence not established'):self.b.cleanup(self.t,self.out)
        self.assertTrue(all(c.args[0][1]!='rm'for c in run.call_args_list))

if __name__=='__main__':unittest.main()
