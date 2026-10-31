# SPDX-License-Identifier: MIT
"""Pure contract, real temporary metadata, AST and mocked actor controls; no native actors."""
import ast
import copy
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import policy as P
import host
import gate
import lifecycle as T

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'AGENTS.md').is_file())


def functions(raw):return {n.name:ast.dump(n) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}


def descriptor(date=1,dependency='python>=3.11'):
    return ('%NAME%\n'+P.SETUP+'\n\n%VERSION%\n0.1.0-3\n\n%INSTALLDATE%\n'+str(date)+'\n\n%DEPENDS%\n'+dependency+'\n\n').encode()


class Contracts(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
        self.lock=dict(line.split() for line in (ROOT/'scripts/ci/expanded600-installer-vm/expected600.lock').read_text().splitlines())

    def test_pending_root600_acceptance_refuses_before_any_actor_or_git(self):
        (self.work/'input-policy.json').write_bytes(P.encoded(dict(schema_version=1,status='AWAITING_ROOT_NATIVE600_ACCEPTANCE')))
        with patch.object(P,'HERE',self.work),\
             patch.object(P.subprocess,'Popen',side_effect=AssertionError('actor forbidden')),\
             patch.object(P,'revision',side_effect=AssertionError('Git forbidden')):
            with self.assertRaisesRegex(ValueError,'Root accepted original600'):
                gate.verify(ROOT,'a'*40,'a'*40,ROOT,ROOT,ROOT,ROOT,ROOT)

    def bound(self):
        value=copy.deepcopy(P.read(P.HERE/'input-policy.json'));proof=P.read(P.HERE/'root-setup5-acceptance.json')
        baseline=dict(fixture_only=True,status='ROOT_ACCEPTED_NATIVE_EXPANDED600_COMPOSITION',source_sha=value['baseline_source'],run_id='999000001',
            package_count=600,expected600_sha256=P.AFTER,bang_version='0.1.0-2',bang_pair_bytes_buildinfo='PASS',installed_lifecycle='PASS',installed_six_modules='PASS',cleanup='PASS',hardware='NOT_RUN')
        for name,v in [('native.json',baseline),('setup5.json',proof)]:
            (self.work/name).write_bytes(P.encoded(v))
        value.update(status='ROOT_BOUND_SETUP5_EXPANDED600_AFTER_NATIVE600_ACCEPTANCE',
            baseline_acceptance=P.ref(self.work/'native.json'),setup5_acceptance=P.ref(self.work/'setup5.json'))
        (self.work/'input-policy.json').write_bytes(P.encoded(value));return value,baseline

    def test_real_setup5_prerequisite_and_native600_receipt_schema_are_separate(self):
        self.bound()
        with patch.object(P,'HERE',self.work):self.assertEqual(P.policy()['setup5_source'],P.PAIR)

    def test_failed_wrong_source_or_incomplete600_receipt_refuses(self):
        for key,bad in [('status','FAIL'),('package_count',599),('source_sha','0'*40),('cleanup','FAIL'),('installed_six_modules','NOT_RUN')]:
            value,baseline=self.bound();baseline[key]=bad;(self.work/'native.json').write_bytes(P.encoded(baseline))
            value['baseline_acceptance']=P.ref(self.work/'native.json');(self.work/'input-policy.json').write_bytes(P.encoded(value))
            with self.subTest(key=key),patch.object(P,'HERE',self.work),self.assertRaises(ValueError):P.policy()

    def test_only_setup3_to5_changes_while_all600_names_and_other599_versions_hold(self):
        after=P.expected(self.lock,'0.1.0-5');self.assertEqual(len(after),600)
        self.assertEqual({n:v for n,v in after.items() if n!=P.SETUP},{n:v for n,v in self.lock.items() if n!=P.SETUP})
        self.assertEqual(P.expected(self.lock,'0.1.0-3'),self.lock)
        with self.assertRaises(ValueError):P.expected(self.lock,'0.1.0-4')
        changed=dict(self.lock);changed['fish']='999'
        with self.assertRaises(ValueError):P.expected(changed,'0.1.0-5')

    def test_other599_database_and_records_detect_tamper(self):
        before={n:dict(version=v) for n,v in self.lock.items()};records={n:dict(desc=n.encode().hex()) for n in before}
        after=copy.deepcopy(before);after[P.SETUP]['version']='0.1.0-5';changed=copy.deepcopy(records);changed[P.SETUP]['desc']='new'
        T.other599(before,records,after,changed)
        changed['fish']['desc']='changed'
        with self.assertRaisesRegex(ValueError,'other599'):T.other599(before,records,after,changed)
        changed=copy.deepcopy(records);after['fish']['version']='999'
        with self.assertRaises(ValueError):T.other599(before,records,after,changed)

    def test_setup3_normal_alpm_date_delta_only(self):
        T.restored_desc(descriptor(1),descriptor(2),2,2)
        for after in [descriptor(2,'changed'),descriptor(3),descriptor(2).replace(b'0.1.0-3',b'0.1.0-4')]:
            with self.assertRaises(ValueError):T.restored_desc(descriptor(1),after,2,2)
        with self.assertRaises(ValueError):T.desc_fields(descriptor()+b'%NAME%\nduplicate\n\n')

    def test_borrowed_packet_metadata_and_bytes_change_is_visible(self):
        path=self.work/'index.json';path.write_bytes(b'original');before=host.packet_snapshot(self.work)
        path.write_bytes(b'changed');self.assertNotEqual(host.packet_snapshot(self.work),before)
        path.unlink();path.symlink_to('/unowned')
        with self.assertRaises(ValueError):host.packet_snapshot(self.work)


class PayloadTransition(unittest.TestCase):
    def setUp(self):
        self.old={'usr/bin/cachy-asahi-setup','usr/share/doc/cachy-asahi-setup/README.md',
                  'usr/share/licenses/cachy-asahi-setup/LICENSE','usr/share/licenses/cachy-asahi-setup/NOTICE'}
        self.added={'usr/bin/cachy-asahi-repository','usr/share/doc/cachy-asahi-setup/repository-enrollment.md'}
        self.full=dict(ownership={P.SETUP:sorted(self.old|{'usr/bin'})},
                       nodes={p:dict(type='file') for p in self.old}|{'usr/bin':dict(type='directory')})
        self.product=dict(payload={p:dict(type='0') for p in self.old|self.added})

    def test_signed_setup3_four_to_accepted_setup5_six_paths(self):
        self.assertNotEqual(set(self.product['payload']),self.old)  # Actual failed equality is reproduced.
        before,added=T.payload_transition(self.full,self.product)
        self.assertEqual(before,self.old);self.assertEqual(set(added),self.added)
        self.assertEqual(len(self.product['payload']),6)

    def test_missing_held_path_or_unexpected_setup5_path_refuses(self):
        for remove,extra in [('usr/bin/cachy-asahi-setup',None),(None,'usr/bin/unaccepted-tool')]:
            product=copy.deepcopy(self.product)
            if remove:del product['payload'][remove]
            if extra:product['payload'][extra]=dict(type='0')
            with self.subTest(remove=remove,extra=extra),self.assertRaises(ValueError):T.payload_transition(self.full,product)

    def test_missing_new_path_or_wrong_old_shape_refuses(self):
        product=copy.deepcopy(self.product);del product['payload']['usr/bin/cachy-asahi-repository']
        with self.assertRaises(ValueError):T.payload_transition(self.full,product)
        full=copy.deepcopy(self.full);full['ownership'][P.SETUP].append('usr/bin/old-extra');full['nodes']['usr/bin/old-extra']=dict(type='file')
        with self.assertRaises(ValueError):T.payload_transition(full,self.product)

    def test_new_paths_cannot_replace_any_other_signed600_payload(self):
        for path in self.added:
            full=copy.deepcopy(self.full);full['nodes'][path]=dict(type='file');full['ownership']['other599-package']=[path]
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'collide with signed full600'):
                T.payload_transition(full,self.product)

    def test_real_unowned_collision_or_leftover_after_rollback_refuses(self):
        for phase in ('before upgrade','after Setup3 rollback'):
            with patch.object(T,'L',SimpleNamespace(node=lambda path:dict(type='file'))):
                with self.subTest(phase=phase),self.assertRaisesRegex(ValueError,'must be absent'):
                    T.added_absent(self.added,phase)
        with patch.object(T,'L',SimpleNamespace(node=lambda path:dict(type='absent'))):
            T.added_absent(self.added,'before upgrade');T.added_absent(self.added,'after Setup3 rollback')


class Other599Payload(unittest.TestCase):
    def setUp(self):
        source=(ROOT/'scripts/ci/expanded-development-composition/lifecycle.py').read_text()
        method=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='expected_node')
        namespace={};exec(compile(ast.Module(body=[method],type_ignores=[]),'<unchanged native600 node projection>','exec'),namespace)
        self.project=namespace['expected_node']
        self.binding=patch.object(T,'L',SimpleNamespace(expected_node=self.project));self.binding.start();self.addCleanup(self.binding.stop)
        raw=lambda size,digest:dict(type='file',mode=0o644,uid=0,gid=0,bytes=size,sha256=digest*64)
        self.full=dict(packages={P.SETUP:'0.1.0-3','pacman':'held','kept':'1','addon':'2'},
            ownership={P.SETUP:['usr/bin/setup'],'pacman':['etc/pacman.conf'],'kept':['usr/bin/kept'],'addon':['usr/lib/libaddon.so']},
            nodes={'usr/bin/setup':raw(1,'a'),'etc/pacman.conf':raw(2693,'b'),'usr/bin/kept':raw(5,'c'),
                   'usr/lib/libaddon.so':dict(type='symlink',mode=0o777,uid=0,gid=0,target='libaddon.so.2')})
        self.baseline={p:self.project(n) for p,n in self.full['nodes'].items() if p!='usr/lib/libaddon.so'}
        self.baseline['etc/pacman.conf'].update(size=116,sha256='d'*64)
        self.incoming=[dict(name='addon',version='2',payload={'usr/lib/libaddon.so':self.full['nodes']['usr/lib/libaddon.so']})]

    def expected(self):return T.expected_other599(self.full,self.baseline,self.incoming)

    def test_configured_native600_baseline_plus_signed_incoming_without_raw_archive_waiver(self):
        expected=self.expected()
        self.assertNotEqual(expected['etc/pacman.conf'],self.project(self.full['nodes']['etc/pacman.conf']))
        self.assertEqual(expected['etc/pacman.conf'],self.baseline['etc/pacman.conf'])
        self.assertEqual(set(expected),{'etc/pacman.conf','usr/bin/kept','usr/lib/libaddon.so'})
        self.assertEqual(expected['usr/lib/libaddon.so'],self.project(self.full['nodes']['usr/lib/libaddon.so']))
        T.same_payload(expected,copy.deepcopy(expected),'actual other599 signed payload differs')

    def test_every_actual_byte_mode_uid_gid_type_and_link_drift_refuses_with_operands(self):
        expected=self.expected()
        for path,key,value in [('etc/pacman.conf','sha256','e'*64),('usr/bin/kept','size',6),
            ('usr/bin/kept','mode',0o755),('usr/bin/kept','uid',1),('usr/bin/kept','gid',1),
            ('usr/lib/libaddon.so','link','foreign.so'),('usr/lib/libaddon.so','type','file')]:
            actual=copy.deepcopy(expected);actual[path][key]=value
            with self.subTest(path=path,key=key),self.assertRaisesRegex(ValueError,'actual other599 signed payload differs') as caught:
                T.same_payload(expected,actual,'actual other599 signed payload differs')
            detail=json.loads(str(caught.exception).split(': ',1)[1])
            self.assertEqual(detail['path'],path);self.assertEqual(detail['expected'],expected[path]);self.assertEqual(detail['actual'],actual[path])

    def test_missing_baseline_incoming_signed_drift_and_overlap_refuse(self):
        baseline=copy.deepcopy(self.baseline);incoming=copy.deepcopy(self.incoming)
        del self.baseline['usr/bin/kept']
        with self.assertRaisesRegex(ValueError,'complete exact other599'):self.expected()
        self.baseline=copy.deepcopy(baseline);self.incoming=copy.deepcopy(incoming)
        self.incoming[0]['payload']['usr/lib/libaddon.so']=dict(self.full['nodes']['usr/lib/libaddon.so'],target='wrong.so')
        with self.assertRaisesRegex(ValueError,'signed payload'):self.expected()
        self.incoming=copy.deepcopy(incoming)
        self.baseline['usr/lib/libaddon.so']=self.project(self.full['nodes']['usr/lib/libaddon.so'])
        with self.assertRaisesRegex(ValueError,'overlap'):self.expected()

    def test_missing_extra_or_wrong_version_incoming_cannot_shrink_other599_scope(self):
        for field,value in [('payload',{}),('payload',{'usr/lib/extra.so':dict(type='0')}),('version','wrong')]:
            original=copy.deepcopy(self.incoming[0]);self.incoming[0][field]=value
            try:
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):self.expected()
            finally:self.incoming[0]=original
        expected=self.expected();actual=copy.deepcopy(expected);del actual['usr/bin/kept']
        with self.assertRaisesRegex(ValueError,'other599 installed payload changed'):
            T.same_payload(expected,actual,'other599 installed payload changed')

    def test_bounded_failure_operands_retain_full_path_and_link_hashes(self):
        path='x'*4096;expected={path:dict(type='symlink',link='a'*4096)};actual={path:dict(type='symlink',link='b'*4096)}
        with self.assertRaises(ValueError) as caught:T.same_payload(expected,actual,'actual other599 signed payload differs')
        raw=str(caught.exception);self.assertLess(len(raw.encode()),2048)
        detail=json.loads(raw.split(': ',1)[1]);self.assertEqual(detail['path_sha256'],hashlib.sha256(path.encode()).hexdigest())
        self.assertEqual(detail['actual']['link']['sha256'],hashlib.sha256(('b'*4096).encode()).hexdigest())
        path='😀'*1024
        with self.assertRaises(ValueError) as caught:
            T.same_payload({path:dict(type='symlink',link='😀'*1024)},{path:dict(type='symlink',link='😃'*1024)},'other599 installed payload changed')
        self.assertLess(len(str(caught.exception).encode()),2048)
        json.loads(str(caught.exception).split(': ',1)[1])


class PacketSources(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.path=self.root/'empty.log';self.path.write_bytes(b'')
        self.ref=dict(path='empty.log',bytes=0,sha256=hashlib.sha256(b'').hexdigest())

    def test_genuine_empty_raw_record_retained_without_positive_contract_change(self):
        self.assertEqual(gate.packet_source(self.root,self.ref),self.path)
        self.assertEqual(self.path.read_bytes(),b'')
        with self.assertRaisesRegex(ValueError,'exact bounded byte reference'):P.checked(self.root,self.ref)

    def test_empty_hash_type_shape_and_path_forgery_refuses(self):
        for change in (dict(sha256='0'*64),dict(bytes=False),dict(bytes=0.0),dict(path='../empty.log'),dict(path='/empty.log'),dict(extra='field')):
            with self.subTest(change=change),self.assertRaises(ValueError):gate.packet_source(self.root,self.ref|change)

    def test_declared_empty_nonempty_source_refuses(self):
        self.path.write_bytes(b'changed original data')
        with self.assertRaisesRegex(ValueError,'ordinary single-link empty'):gate.packet_source(self.root,self.ref)

    def test_empty_missing_symlink_and_ancestor_alias_refuse(self):
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):gate.packet_source(self.root,self.ref)
        target=self.root/'target';target.write_bytes(b'');self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError,'ordinary absolute'):gate.packet_source(self.root,self.ref)
        directory=self.root/'directory';directory.mkdir();(directory/'empty.log').write_bytes(b'')
        (self.root/'alias').symlink_to(directory,target_is_directory=True)
        with self.assertRaises(ValueError):gate.packet_source(self.root,self.ref|dict(path='alias/empty.log'))

    def test_empty_hardlink_and_special_node_refuse_before_read(self):
        os.link(self.path,self.root/'alias.log')
        with self.assertRaisesRegex(ValueError,'single-link'):gate.packet_source(self.root,self.ref)
        self.path.unlink();os.mkfifo(self.path)
        with self.assertRaisesRegex(ValueError,'ordinary single-link'):gate.packet_source(self.root,self.ref)

    def test_positive_records_delegate_to_unmodified_checked(self):
        self.path.write_bytes(b'original positive bytes');ref=P.ref(self.path)
        with patch.object(P,'checked',wraps=P.checked) as checked:
            self.assertEqual(gate.packet_source(self.root,ref),self.path)
        checked.assert_called_once_with(self.root,ref)
        with self.assertRaises(ValueError):gate.packet_source(self.root,ref|dict(sha256='0'*64))

    def test_stage_rejects_existing_output_before_packet_read_or_overwrite(self):
        out=self.root/'already-exists';out.mkdir();sentinel=out/'sentinel';sentinel.write_bytes(b'preserve')
        with patch.object(P,'checked',side_effect=AssertionError('read must not occur')):
            with self.assertRaisesRegex(ValueError,'fresh metadata-free'):gate.stage_packet(self.root,out,ROOT)
        self.assertEqual(sentinel.read_bytes(),b'preserve')


class Source(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(P.subprocess,'Popen',side_effect=AssertionError('actor forbidden')):
            cls.namespace,cls.host_source=host.original_namespace(ROOT)
        cls.original=(ROOT/'scripts/ci/expanded-development-composition/run.py').read_text()
        cls.life=(ROOT/'scripts/ci/expanded-development-composition/lifecycle.py').read_text()

    def test_unchanged_host_helpers_and_original_finally_cleanup(self):
        a,b=functions(self.original),functions(self.host_source)
        self.assertEqual({n for n in a if a[n]!=b[n]},{'main','export'})
        def final(raw):
            main=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='main')
            return [ast.dump(n.finalbody[0])+'|'+','.join(ast.dump(x) for x in n.finalbody[1:]) for n in main.body if isinstance(n,ast.Try)]
        self.assertEqual(final(self.original),final(self.host_source))
        self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',self.host_source)
        self.assertIn('C.validate_result(life)',self.host_source)

    def test_separate_consumer_runs_before_unchanged_original_and_is_owned(self):
        self.assertLess(self.host_source.index('setup5_host.consume('),self.host_source.index("resultdir=out/'container'"))
        self.assertIn('len(owned.rows)==4',self.host_source)
        self.assertEqual(self.host_source.count("execute(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner/lifecycle.py']"),1)
        self.assertIn("'setup5/'+n for n in setup5_host.P.PUBLIC",self.host_source)

    def test_bootstrap_adapter_inserts_only_its_explicit_result_before_original_continuation(self):
        raw=T.adapted_source(self.life)
        extra="        report.update(_setup5_trial(locals()),ldconfig=ld_receipts)\n        return 0\n"
        self.assertEqual(raw.replace(extra,''),self.life)
        self.assertEqual({n for n,v in functions(self.life).items() if functions(raw)[n]!=v},{'main'})
        self.assertNotIn("'--noscriptlet','-U','--print'",raw)
        self.assertIn("['--noconfirm','-U','--print'",raw)
        self.assertIn("restore('final587')",self.host_source if "restore('final587')" in self.host_source else self.life)

    def test_anchor_drift_refuses_instead_of_applying_broad_replacements(self):
        with self.assertRaises(ValueError):T.adapted_source(self.life.replace("install();checkpoint('install600',after,rows)",'missing'))
        with self.assertRaises(ValueError):host.replace('x x','x','y')

    def test_no_setup5_build_or_new_signing_authority_in_extension(self):
        raw=Path(host.__file__).read_text()
        self.assertIn('sign.append(dest)',raw);self.assertIn('verifier(path,signature,signer)',raw)
        self.assertNotIn('quick-generate-key',raw);self.assertNotIn('makepkg',raw)
        self.assertIn("STAGED['signer']==plan['test_signer']",raw)
        self.assertIn("snapshot.C=native",Path(T.__file__).read_text())
        self.assertIn('timeout=240',Path(T.__file__).read_text())
        self.assertIn("['--noconfirm','--noscriptlet','-U',rollback]",Path(T.__file__).read_text())

    def test_manual_workflow_presecret_gate_and_fixed_input_sources(self):
        root=Path(P.HERE).parents[2]  # proposed checkout root
        file=root/'.github/workflows/native-arm-setup5-expanded600.yml';text=file.read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('schedule:',text)
        self.assertLess(text.index('setup5-expanded600/gate.py'),text.index('secrets.'))
        self.assertIn('ref: '+P.PAIR,text);self.assertIn('ref: '+P.PROBE,text)
        self.assertIn('setup5-expanded600/run.py',text);self.assertIn('--code-revision "$EXPANDED_SOURCE"',text)
        self.assertIn('7200s',text);self.assertIn('timeout-minutes: 220',text)


class Results(unittest.TestCase):
    def setUp(self):
        flags=dict(signatures=True,dependencies=True,payload=True,ownership=True,originals_preserved=True,user_config_preserved=True)
        preserved=dict(other599_versions=True,other599_database=True,other599_payload=True,configuration_preserved=True,database_check=True)
        self.value=dict(status='PASS_SETUP5_EXPANDED600_INTEGRATION',scope='SEPARATE_OWNED_FULL600_SETUP5_CONSUMER',package_count=600,
            restored_count=600,baseline600_sha256=P.AFTER,setup5_archive_sha256=P.ARCHIVE,setup3_version='0.1.0-3',setup5_version='0.1.0-5',
            original_consumer_modified=False,hardware='NOT_RUN',release='NOT_ADMITTED',
            setup5_events=[dict(phase=n,count=600,status='PASS',inventory_sha256=P.AFTER if n==P.PHASES[-1] else P.TRIAL,**preserved) for n in P.PHASES],
            events=[dict(phase=n,count=count,status='PASS',**flags) for n,count in [('baseline587',587),('install600',600)]],
            ldconfig=[dict(phase=n,helper_exit='NOT_OBSERVED',state_sha256='a'*64,aux_sha256='b'*64,
                transition=dict(kind='RAW_EQUAL' if i else 'BASELINE')) for i,n in enumerate(P.LD_PHASES)],
            real_modules=dict(fixture_only=True),complete_user_workspace_preserved=True,ordinary_user_processes_absent=True,
            setup3_payload_restored=True,setup3_database_semantics_restored=True,other_setup3_db_files_identical=True)
        self.called=[];self.native=SimpleNamespace(validate_real=lambda value:self.called.append(value))

    def test_separate_result_requires_native_probe_validator(self):
        P.validate(self.value,self.native);self.assertEqual(self.called,[dict(fixture_only=True)])

    def test_partial_wrong_version_or_original_consumer_modification_refuses(self):
        for key,bad in [('package_count',599),('setup5_version','0.1.0-4'),('original_consumer_modified',True),
                        ('complete_user_workspace_preserved',False),('ordinary_user_processes_absent',False)]:
            value=copy.deepcopy(self.value);value[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):P.validate(value,self.native)
        value=copy.deepcopy(self.value);value['setup5_events'].pop()
        with self.assertRaises(ValueError):P.validate(value,self.native)

    def test_every_other599_gate_and_untouched_bootstrap_gate_is_required(self):
        for section,key in [('setup5_events','other599_database'),('setup5_events','other599_payload'),('setup5_events','configuration_preserved'),
                            ('events','payload'),('events','signatures')]:
            value=copy.deepcopy(self.value);value[section][0][key]=False
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):P.validate(value,self.native)

    def test_ldconfig_reset_or_raw_join_hash_omission_refuses(self):
        for key,bad in [('phase','new-baseline'),('state_sha256','missing'),('transition',dict(kind='BASELINE'))]:
            value=copy.deepcopy(self.value);value['ldconfig'][1][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):P.validate(value,self.native)

    def test_native_real_probe_failure_cannot_be_hidden_by_600_preservation(self):
        def failed(_):raise ValueError('real native probe failed')
        with self.assertRaisesRegex(ValueError,'real native probe failed'):
            P.validate(self.value,SimpleNamespace(validate_real=failed))


class Workspace(unittest.TestCase):
    def test_all_seven_home_trees_are_preserved_beyond_the_old128_node_cap(self):
        native=ROOT/'scripts/ci/setup5-native-real-modules/lifecycle.py'
        N=P.load('setup5_test_workspace_native',native);N.C=P
        io=P.load('setup5_test_legacy_entries',ROOT/'scripts/ci/welcome-native/lifecycle.py')
        H=P.load('setup5_test_per_home_bounds',ROOT/'scripts/ci/setup5-real-modules/run.py')
        with tempfile.TemporaryDirectory() as folder:
            parent=Path(folder);work=parent/'work';work.mkdir();(work/'receipt.json').write_text('{}\n')
            real=dict(lifecycle={name:{} for name in ('fish-a','fish-b','zsh-a','zsh-b','fish-noninteractive','zsh-noninteractive')})
            for name in [*real['lifecycle'],'edited-conflict-user']:
                home=work/name;home.mkdir()
                for n in range(30):(home/str(n)).write_bytes(b'preserved user state\n')
            before=N.workspace_snapshot(parent,real,io,H);self.assertGreater(len(before),210)
            changed=work/'edited-conflict-user/29';changed.write_bytes(b'changed edit\n')
            self.assertNotEqual(N.workspace_snapshot(parent,real,io,H),before)


if __name__=='__main__':unittest.main(verbosity=2)
