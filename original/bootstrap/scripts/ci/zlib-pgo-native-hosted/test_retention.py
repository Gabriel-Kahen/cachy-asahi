# SPDX-License-Identifier: MIT
"""Passive synthetic retention joins; no fixture establishes native/GitHub origin."""
import copy,importlib.util,json,os,shutil,socket,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('_pgo_host_retention',HERE/'retention.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
SOURCE=ROOT/'pgo-source'/R.RECIPE


def raw(value):return(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def write(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value if type(value)is bytes else raw(value))


def fixture(directory):
    """Honest synthetic profiles/commands/payloads with real source pins only."""
    directory.mkdir();policy=R.j(SOURCE/'recipe-policy.json')
    for part in('profiles','decoded-profiles','instrumented','commands','optimized-1','optimized-2'):(directory/part).mkdir()
    for name in R.PROFILE_NAMES:
        for part in('profiles','decoded-profiles'):write(directory/part/name,b'adcgB62*'+b'\0'*16)
    for name in('libz.a','example','minigzip','gun','gun.o','Makefile','configure.log'):write(directory/'instrumented'/name,('synthetic instrumented '+name).encode())
    for name in('train.decoded','gun.decoded'):write(directory/name,R.read(SOURCE/'training.bin'))
    for name in('train.gz','example.gz'):write(directory/name,('synthetic opaque '+name).encode())
    labels=R.labels();rows=[]
    for index,label in enumerate(labels):
        stdout=R.read(directory/{'train-encode':'train.gz','train-decode':'train.decoded','train-gun':'gun.decoded'}[label])if label in('train-encode','train-decode','train-gun')else b''
        log=f'{index:04d}-'+label+'.log';body=b''
        if label=='build-training-profile-decode':body=''.join('reading file: ./'+name+'\n'for _ in range(2)for name in R.PROFILE_NAMES).encode()
        write(directory/'commands'/log,body)
        rows.append(dict(label=label,argv=['synthetic-source-bound-command'],log=log,status='PASS',exit=2 if '-reject-'in label else 0,group_absent=True,leader_held_until_group_inspection=True,cleanup_member_uids=[],elapsed_seconds=.001,stdout_bytes=len(stdout),stdout_sha256=R.sha(stdout),exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED',natural_exit=True,forced_cleanup=False))
    write(directory/'commands/commands.json',rows)
    plan=[dict(label='train-encode',argv=['/tmp/build/minigzip','-6'],input='training.bin',output='train.gz'),dict(label='train-decode',argv=['/tmp/build/minigzip','-d'],input='train.gz',output='train.decoded'),dict(label='train-example',argv=['/tmp/build/example','/tmp/work/src/pgo-result/example.gz'],input=None,output=None),dict(label='train-gun',argv=['/tmp/build/gun'],input='train.gz',output='gun.decoded')]
    cases=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]+[bytes((i*13+i//257)&255 for i in range(n))for n in(16383,16384,16385)]+[R.read(SOURCE/'validation.bin')]
    by_label={r['label']:r for r in rows};resultdir=Path('/tmp/work/src/pgo-result')
    for row in plan:by_label[row['label']]['argv']=row['argv']
    def observation(label,argv,stdout):
        by_label[label]['argv']=argv
        if stdout is not None:by_label[label].update(stdout_bytes=len(stdout),stdout_sha256=R.sha(stdout))
    probe=dict(status='PASS',variant='pgo-v1',prefix='/usr/lib/cachy-asahi/experiments/zlib-pgo-v1',zlib='1.3.2',source_sha256=R.SOURCE_SHA,roundtrips=21,negative_checks=42)
    for number in(0,1):
        root=resultdir/('optimized-'+str(number+1));observation('validate-probe-'+str(number),[str(root/'probe'),'--build-check'],(json.dumps(probe,separators=(',',':'))+'\n').encode())
        for index,plain in enumerate(cases):
            for level in(1,6,9):
                prefix=f'validate-{number}-{index}-{level}';observation(prefix+'-encode',[str(root/'minigzip'),'-'+str(level)],None)
                for consumer in(0,1):observation(prefix+'-decode-'+str(consumer),[str(resultdir/('optimized-'+str(consumer+1))/'strict-gzip')],plain)
        for index in range(3):observation(f'validate-{number}-reject-{index}',[str(root/'strict-gzip')],cases[2])
    write(directory/'commands/commands.json',rows)
    training=dict(plan=plan,results=[dict(label=n,stdout=dict(bytes=next(r for r in rows if r['label']==n)['stdout_bytes'],sha256=next(r for r in rows if r['label']==n)['stdout_sha256']))for n in('train-encode','train-decode','train-example','train-gun')],profiles=[dict(name=n,**v)for n,v in sorted(R.tree(directory/'profiles').items())],instrumented={p.name:R.pin(R.read(p))for p in(directory/'instrumented').iterdir()})
    write(directory/'training-results.json',training)
    tools={n:dict(path='/usr/bin/'+n,resolved_path='/usr/bin/'+n,bytes=1,sha256='a'*64,version='SYNTHETIC HOST CONTROL ONLY')for n in('gcc','gcc-ar','gcc-ranlib','ld','gcov-tool','make','as','cc1','collect2','libgcov.a')}
    binding=dict(source_sha256=R.SOURCE_SHA,source_files={**R.upstream(ROOT),**{'local/'+n:v for n,v in policy['local_files'].items()}},toolchain=dict(target='aarch64-unknown-linux-gnu',tools=tools),isa='armv8-a/generic',build_path='/tmp/build',profile_path='/tmp/profile',prefix='/usr/lib/cachy-asahi/experiments/zlib-pgo-v1',training=dict(corpus=policy['training'],heldout=policy['validation'],command_plan_sha256=R.sha(raw(plan)),results_sha256=R.sha(R.read(directory/'training-results.json'))))
    spec=importlib.util.spec_from_file_location('_fixture_profile_seal',SOURCE/'profile_seal.py');seal=importlib.util.module_from_spec(spec);spec.loader.exec_module(seal);sealed=seal.seal(directory/'profiles',binding,directory/'profile-seal.json')
    base=R.constant(SOURCE/'pipeline.py','BASE');link=R.constant(SOURCE/'pipeline.py','LINK');use=R.constant(SOURCE/'pipeline.py','USE')
    for number in(1,2):
        dest=directory/f'optimized-{number}'
        for name in R.PAYLOAD:write(dest/name,('synthetic optimized '+name).encode())
        for name,cflags,ldflags in [('Makefile.txt',base+use+' -fPIC -DHAVE_HIDDEN',link+use),('configure.log.txt',base+' -fPIC -DHAVE_HIDDEN',link)]:write(dest/name,('CC=gcc\nAR=gcc-ar\nRANLIB=gcc-ranlib\nCFLAGS='+cflags+'\nLDFLAGS='+ldflags+'\n').encode())
    payload={n:R.pin(R.read(directory/'optimized-1'/n))for n in R.PAYLOAD}
    cases=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]+[bytes((i*13+i//257)&255 for i in range(n))for n in(16383,16384,16385)]+[R.read(SOURCE/'validation.bin')]
    report=dict(status='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY',source_sha256=R.SOURCE_SHA,training_attempts=1,optimized_clean_builds=2,profile_use='SAME_SEALED_PROFILE_BOTH_BUILDS_NO_FALLBACK',profile_decode='GCC_NATIVE_DECODER_TRANSCRIPT_MATCHED',hardware='NOT RUN',physical16k='NOT RUN',performance='NOT MEASURED',release='NOT_ADMITTED',optimization_acceptance='NOT RUN',recipe_policy=R.pin(R.read(SOURCE/'recipe-policy.json')),binding=binding,profile_seal_sha256=sealed['seal_sha256'],outputs=[payload,payload],effective_flags=[R.configured(directory/f'optimized-{n}',SOURCE)for n in(1,2)],correctness=dict(encodes=48,cross_decodes=96,strict_rejections=6,probes=2,includes_page_boundaries=[16383,16384,16385],physical16k='NOT RUN',input_pins=[R.pin(d)for d in cases]))
    write(directory/'result.json',report);reseal(directory);return report


def reseal(directory):
    leaves=R.tree(directory);leaves.pop('receipt.json',None)
    write(directory/'receipt.json',dict(schema=1,status='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY',files=leaves,acceptance=False,performance='NOT MEASURED',hardware='NOT RUN'))


class RetentionControls(unittest.TestCase):
    def setUp(self):
        path=HERE.parents[3]/'evidence/tmp';path.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='retention-',dir=path);self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))
        self.enterContext(patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')))

    def test_complete_synthetic_nested_data_matches_only_source_bound_data(self):
        directory=self.root/'nested';fixture(directory);result=R.inner(directory,ROOT)
        self.assertEqual(result['profiles'],17);self.assertEqual(result['commands'],234)
        self.assertEqual(result['inner_clean_builds'],2);self.assertEqual(result['performance'],'NOT GRANTED')

    def test_missing_nested_receipt_extra_leaf_and_tampered_profile_refuse(self):
        directory=self.root/'nested';fixture(directory)
        receipt=R.read(directory/'receipt.json');(directory/'receipt.json').unlink()
        with self.assertRaises(FileNotFoundError):R.inner(directory,ROOT)
        write(directory/'receipt.json',receipt);write(directory/'unselected',b'no')
        with self.assertRaises(ValueError):R.inner(directory,ROOT)
        (directory/'unselected').unlink();write(directory/'profiles'/R.PROFILE_NAMES[0],b'adcgB62*'+b'changed profile');reseal(directory)
        with self.assertRaises(ValueError):R.inner(directory,ROOT)

    def test_source_toolchain_binding_fatal_flags_and_payload_mutation_refuse(self):
        directory=self.root/'nested';fixture(directory)
        path=directory/'optimized-2/Makefile.txt';original=R.read(path);write(path,original.replace(b'-Werror=missing-profile',b'-Wno-error=missing-profile'));reseal(directory)
        with self.assertRaises(ValueError):R.inner(directory,ROOT)
        write(path,original);write(directory/'optimized-2/minigzip',b'changed payload');reseal(directory)
        with self.assertRaises(ValueError):R.inner(directory,ROOT)
        # Rewriting a seal binding cannot hide a different toolchain/source identity.
        report=R.j(directory/'result.json');report['binding']['toolchain']['target']='x86_64-linux-gnu';write(directory/'result.json',report);reseal(directory)
        with self.assertRaises(ValueError):R.inner(directory,ROOT)

    def test_command_completeness_native_decoder_and_held_leader_refuse(self):
        directory=self.root/'nested';fixture(directory);path=directory/'commands/commands.json';original=R.j(path)
        for change in('missing','unheld','decoder'):
            rows=copy.deepcopy(original)
            if change=='missing':rows.pop()
            elif change=='unheld':rows[0]['leader_held_until_group_inspection']=False
            else:
                row=next(r for r in rows if r['label']=='build-training-profile-decode');write(directory/'commands'/row['log'],b'warning: profile mismatch\n')
            write(path,rows)
            with self.subTest(change=change),self.assertRaises(ValueError):R.commands(directory/'commands')

    def test_exit2_without_complete_refusal_plaintext_observation_refuses(self):
        directory=self.root/'nested';fixture(directory);path=directory/'commands/commands.json';rows=R.j(path)
        row=next(r for r in rows if r['label']=='validate-0-reject-0');row.update(stdout_bytes=0,stdout_sha256=R.sha(b''));write(path,rows);reseal(directory)
        with self.assertRaises(ValueError):R.inner(directory,ROOT)

    def test_safe_recursive_retention_rejects_aliases_special_and_unknown_names(self):
        directory=self.root/'tree';directory.mkdir();write(directory/'libz.a',b'data')
        self.assertEqual(R.tree(directory),{'libz.a':R.pin(b'data')});self.assertEqual(R.cap('libz.a'),64*1024**2)
        (directory/'alias').symlink_to(directory/'libz.a')
        with self.assertRaises(ValueError):R.tree(directory)
        (directory/'alias').unlink();os.link(directory/'libz.a',directory/'hardlink')
        with self.assertRaises(ValueError):R.tree(directory)
        (directory/'hardlink').unlink();os.mkfifo(directory/'fifo')
        with self.assertRaises(ValueError):R.tree(directory)
        self.assertFalse(R.attempt_leaf('native-build/artifacts/pgo-v1-evidence/unselected',set()))
        self.assertFalse(R.attempt_leaf('source-material/notices/credentials',set()))

    def test_runtime_producer_requires_same_genuine_image_and_full341_lock(self):
        work=self.root/'work';work.mkdir();lock=R.read(HERE/'expected-packages.lock');write(work/'bootstrap/packages.lock',lock)
        own={'source_sha':'b'*40};base=dict(status='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP',identity=own,image='sha256:'+'c'*64,package_count=341);write(work/'bootstrap-owner.json',base)
        def require_image(row,identity):
            R.need(row['owner']==identity,'owned image');return row['Id']
        owner=SimpleNamespace(LANE='scripts/ci/zlib-pgo-native-hosted',require_image=require_image)
        for suffix in('','-1','-2'):
            path=work/('producer-inspect'+suffix+'.json');write(path,dict(owner=own,Id=base['image']))
            write(work/('producer-binding'+suffix+'.json'),dict(schema=1,status='PASS_FRESH_OWNED_RUNTIME_IMAGE_AND_FULL341_LOCK',identity=own,image=base['image'],packages=R.pin(lock),package_count=341,bootstrap_owner=R.pin(R.read(work/'bootstrap-owner.json')),inspection=R.pin(R.read(path))))
        self.assertEqual(R.producer(work,ROOT,own,owner)[1],lock)
        write(work/'bootstrap/packages.lock',b'gcc 16\nglibc 2\nmake 4\n')
        with self.assertRaises(ValueError):R.producer(work,ROOT,own,owner)
        write(work/'bootstrap/packages.lock',lock);row=R.j(work/'producer-binding-2.json');row['image']='sha256:'+'d'*64;write(work/'producer-binding-2.json',row)
        with self.assertRaises(ValueError):R.producer(work,ROOT,own,owner)

    def test_missing_or_wrong_ordered_cleanup_never_qualifies_and_partial_retains_nested(self):
        work=self.root/'work';work.mkdir();own={'source_sha':'b'*40};base={'image':'sha256:'+'c'*64}
        pair=dict(identity=own,status='PASS_TWO_INDEPENDENT_NATIVE_PGO_BUILDS_PENDING_CLEANUP',image=base['image'],source_cache_unchanged=True,clean_environment_ids=['one','two'])
        write(work/'pairs-owner.json',pair);write(work/'pair-cleanup-owner.json',dict(identity=own,status='FAIL',observed_absent=[]));write(work/'cleanup-owner.json',dict(identity=own,status='PASS_ORDERED_OWNED_CONSUMER_THEN_IMAGE_ABSENCE',consumer_absence_verified=True,image_absence_verified=True,removed_images=[base['image']]))
        with patch.object(R,'producer',return_value=(base,b'full341')):
            with self.assertRaises(ValueError):R.qualify(work,ROOT,own,SimpleNamespace())
        source=self.root/'source';source.mkdir();write(source/'only-source',b'held source');proof=self.root/'proof.json';write(proof,b'proof')
        nested=work/'attempt-1/native-build/artifacts/pgo-v1-evidence';nested.mkdir(parents=True);write(nested/'result.json',dict(status='FAIL'));write(nested/'failed-profiles/partial.gcda',b'incomplete data')
        public=self.root/'public'
        def fresh(path):Path(path).mkdir();return Path(path)
        owner=SimpleNamespace(ROOT=source,MAP='map',ALIASES=('alias1','alias2'),LANE='lane',fresh=fresh,save=lambda p,v:write(p,v),binding=lambda *a,**k:({'files':{'only-source':{}}},own))
        for name in('map','alias1','alias2'):write(source/name,b'data')
        (source/'pgo-source'/R.RECIPE).mkdir(parents=True)
        args=SimpleNamespace(work=work,public=public,proof=proof,manifest_sha256='a'*64)
        with patch.object(R,'qualify',side_effect=ValueError('incomplete runtime')):self.assertEqual(R.retain(args,owner),1)
        receipt=R.j(public/'receipt.json');self.assertFalse(receipt['acceptance']);self.assertEqual(receipt['cleanup_credit'],'NONE')
        self.assertEqual(R.read(public/'attempt-1/native-build/artifacts/pgo-v1-evidence/failed-profiles/partial.gcda'),b'incomplete data')


if __name__=='__main__':unittest.main()
