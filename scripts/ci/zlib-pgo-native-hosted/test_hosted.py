# SPDX-License-Identifier: MIT
"""New hosted composition controls; all daemon/Git observations are synthetic."""
import ast,copy,hashlib,importlib.util,json,os,shutil,socket,stat,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];PACKET=ROOT.parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
O=module('_new_pgo_owner',HERE/'owner.py');D=module('_new_pgo_driver',HERE/'execute_builder.py')

def env():
    return dict(GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='123',GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-zlib-pgo.yml@refs/heads/control')

class HostedControls(unittest.TestCase):
    def setUp(self):
        temp=PACKET/'evidence/tmp';temp.mkdir(parents=True,exist_ok=True);self.temp=tempfile.TemporaryDirectory(dir=temp);self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
        self.enterContext(patch.object(subprocess,'Popen',side_effect=AssertionError('native/process forbidden')))
        self.enterContext(patch.object(subprocess,'run',side_effect=AssertionError('native/process forbidden')))
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))

    def source_fixture(self):
        root=self.work/'source';root.mkdir();lane=root/O.LANE;lane.mkdir(parents=True)
        selected=set(O.load(HERE/'reviewed11.json'))|{'scripts/ci/inputs.lock.json'}
        for name in selected:
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
        shutil.copytree(ROOT/'pgo-source',root/'pgo-source')
        for name in('owner.py','reviewed11.json','expected-packages.lock','pgo-source-pins.json'):shutil.copy2(HERE/name,lane/name)
        (lane/'workflow.yml.in').write_text('name: control\n# @OWNER_SHA@ @MAP_SHA@\n')
        files={p.relative_to(root).as_posix():dict(**O.pin(p.read_bytes()),mode=stat.S_IMODE(p.stat().st_mode))for p in root.rglob('*')if p.is_file()}
        raw=(json.dumps(dict(schema=1,actual=None,files=files),sort_keys=True)+'\n').encode();(root/O.MAP).write_bytes(raw);checksum=O.sha(raw)
        for name in O.ALIASES:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text((lane/'workflow.yml.in').read_text().replace('@OWNER_SHA@',files[O.LANE+'/owner.py']['sha256']).replace('@MAP_SHA@',checksum))
        return root,checksum

    def test_whole_held_pgo39_and_source_alias_mutation_refuse(self):
        root,checksum=self.source_fixture();self.assertIsNone(O.source(root,checksum)['actual'])
        path=root/'pgo-source/packages/experiments/cachy-asahi-zlib-pgo-v1/training.bin';path.write_bytes(b'wrong')
        with self.assertRaises(ValueError):O.source(root,checksum)

    def test_source_namespace_and_unselected_feature_carrier_refuse(self):
        root,checksum=self.source_fixture();path=root/'source-feature-code';path.mkdir()
        with self.assertRaises(ValueError):O.source(root,checksum,allow_carriers=True)
        path.rmdir();(root/O.ALIASES[1]).write_bytes(b'wrong')
        with self.assertRaises(ValueError):O.source(root,checksum)

    def test_complete_git_blob_mode_and_workflow_join_refuses_wrong_blob(self):
        root,checksum=self.source_fixture();mapping=O.source(root,checksum);rows=[]
        for name in sorted(set(mapping['files'])|{O.MAP,*O.ALIASES}):
            path=root/name;body=path.read_bytes();mode='100755'if path.stat().st_mode&0o111 else'100644';blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest();rows.append((mode+' blob '+blob+'\t'+name+'\0').encode())
        raw=b''.join(rows)
        with patch.object(subprocess,'check_output',side_effect=['a'*40+'\n',raw]):self.assertEqual(len(O.git_source(root,mapping,'a'*40)),len(rows))
        with patch.object(subprocess,'check_output',side_effect=['a'*40+'\n',raw.replace(b' blob ',b' tree ',1)]),self.assertRaises(ValueError):O.git_source(root,mapping,'a'*40)
        with patch.object(subprocess,'check_output',return_value='b'*40+'\n'),self.assertRaises(ValueError):O.git_source(root,mapping,'a'*40)

    def test_same_first_attempt_source_workflow_identity_without_feature_sha(self):
        own=O.identity('a'*40,env());self.assertNotIn('feature_code_sha',own);self.assertTrue(own['tag'].startswith('cachy-asahi-pgo-hosted:'))
        for key,value in [('GITHUB_RUN_ATTEMPT','2'),('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_WORKFLOW_REF','foreign')]:
            wrong=env()|{key:value}
            with self.subTest(key=key),self.assertRaises(ValueError):O.identity('a'*40,wrong)

    def producer(self):
        own=O.identity('a'*40,env());work=self.work/'pgo-hosted-work';(work/'bootstrap').mkdir(parents=True)
        image='sha256:'+'b'*64;args=SimpleNamespace(work=work,manifest_sha256='c'*64)
        O.save(work/'bootstrap-owner.json',dict(status='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP',identity=own,manifest_sha256=args.manifest_sha256,package_count=341,image=image))
        shutil.copyfile(HERE/'expected-packages.lock',work/'bootstrap/packages.lock');(work/'bootstrap/image-id').write_text(image+'\n');O.save(work/'bootstrap/bootstrap.json',dict(status='image-provisioned'))
        row=dict(Id=image,Architecture='arm64',Os='linux',RepoTags=[own['tag']],Config=dict(Labels={O.LABEL:own['token'],O.LABEL+'.source':own['source_sha'],O.LABEL+'.run':own['run_id']}))
        actor=SimpleNamespace(docker=lambda *a:json.dumps([row]));return args,own,row,actor

    def test_fresh_producer_emits_live_image_and_full341_lock_binding(self):
        args,own,row,actor=self.producer();report=O.producer_binding(args,actor,own)
        self.assertEqual(report['package_count'],341);self.assertEqual(report['packages'],O.pin((args.work/'bootstrap/packages.lock').read_bytes()));self.assertEqual(report['image'],row['Id'])
        row['Config']['Labels'][O.LABEL]='foreign'
        with self.assertRaises(ValueError):O.producer_binding(args,actor,own,'-1')

    def test_synthetic_three_package_or_retired_producer_refuses_before_plan(self):
        args,own,row,actor=self.producer();(args.work/'bootstrap/packages.lock').write_text('gcc 1\nglibc 1\nmake 1\n')
        with self.assertRaises(ValueError):O.producer_binding(args,actor,own)
        shutil.copyfile(HERE/'expected-packages.lock',args.work/'bootstrap/packages.lock');(args.work/'bootstrap/image-id').write_text('sha256:'+'d'*64)
        with self.assertRaises(ValueError):O.producer_binding(args,actor,own)

    def inspection(self):
        output=self.work/'attempt-1/native-build';feature=ROOT/'pgo-source';ob=dict(name='cachy-asahi-'+'a'*16,image='sha256:'+'b'*64,output=str(output),feature_root=str(feature),source_sha='c'*40,user='1001:1001')
        mounts=[dict(Destination=d,Source=s,RW=w,Type='bind')for d,s,w in[('/inputs',str(output/'inputs'),False),('/out',str(output/'artifacts'),True),('/builder-entry.sh',str(feature/'scripts/build/container-entry-v2.sh'),False),('/expected-packages.lock',str(output/'expected-packages.lock'),False),('/offline-sources',str(output/'source-material/srcdest'),False)]]
        host=dict(NetworkMode='none',ReadonlyRootfs=True,AutoRemove=True,Privileged=False,PidsLimit=512,Memory=4*1024**3,NanoCpus=4_000_000_000,CapDrop=['ALL'],CapAdd=None,SecurityOpt=['no-new-privileges'],Devices=None,DeviceRequests=None,VolumesFrom=None,Tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'})
        return dict(Name='/'+ob['name'],Image=ob['image'],Config=dict(User=ob['user'],Env=['CACHY_ASAHI_OFFLINE_SOURCES=1']),HostConfig=host,Mounts=mounts),ob

    def test_actual_readonly_offline_mount_predicate_rejects_extra_cache_or_rw(self):
        row,ob=self.inspection();D.check_inspection(row,ob);row['Mounts'].reverse();D.check_inspection(row,ob)
        duplicate=copy.deepcopy(row);duplicate['Mounts'].append(copy.deepcopy(duplicate['Mounts'][0]))
        with self.assertRaises(ValueError):D.check_inspection(duplicate,ob)
        row['Mounts'][0]['RW']=True
        with self.assertRaises(ValueError):D.check_inspection(row,ob)
        row,ob=self.inspection();row['Mounts'].append(dict(Type='bind',Destination='/source-cache',Source='/private',RW=False))
        with self.assertRaises(ValueError):D.check_inspection(row,ob)

    def test_source_order_binds_runtime_producer_before_native_plan_and_intent_before_run(self):
        source=(HERE/'execute_builder.py').read_text();self.assertLess(source.index("producer=json.loads"),source.index('prepared=planner.prepare('));self.assertIn("args.lock,root=args.feature_root",source)
        self.assertLess(source.index('save(args.observation, observation)'),source.index('completed = original_run(forwarded'))
        self.assertIn("*prepared['command'][3:]",source)
        tree=ast.parse((HERE/'owner.py').read_text());function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='pairs');text=ast.get_source_segment((HERE/'owner.py').read_text(),function)
        self.assertIn("for number in(1,2)",text);self.assertLess(text.index("producer_binding(args,actor,own,'-'"),text.index('actor.run(command'));self.assertIn("timeout=1870",text)
        self.assertNotIn('require-bytes',text)

    def test_consumer_retirement_precedes_every_producer_image_operation(self):
        source=(HERE/'owner.py').read_text();tree=ast.parse(source);cleanup=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='cleanup');text=ast.get_source_segment(source,cleanup)
        self.assertLess(text.index('pair_cleanup(args, own)'),text.index("actor.docker('image', 'rm'"))
        pair=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='pair_cleanup');text=ast.get_source_segment(source,pair)
        self.assertIn("name=^/",text);self.assertIn("consumer absent before producer",text);self.assertNotIn("docker('image'",text)

if __name__=='__main__':unittest.main()
