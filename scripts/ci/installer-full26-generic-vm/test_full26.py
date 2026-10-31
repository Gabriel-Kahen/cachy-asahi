#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert source/method/owner controls; no real original test or actor executes."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

import adapter as A
import job

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())


def call(pattern):
    positive=pattern in ('PAIR','ADD','REMOVE','UPGRADE','PROTECTED_ADD')
    phase='complete' if positive else dict(REFUSED='NOT_REPORTED',DECLARED='declaration-after',CONFLICT='commit',
        SNAPSHOT='snapshot',PREPARE='prepare').get(pattern,'isolated')
    return dict(returncode=0 if positive else 1,worker_status='PASS-disposable-payload-transaction' if positive else
        'REFUSED' if pattern in ('REFUSED','DECLARED') else 'FAIL',phase=phase,commit_started=positive or pattern=='CONFLICT',committed=positive)


def barrier(common):
    return dict(status='PASS-barrier-only',worker_sha256=common.TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256'],
        outside_errno=30,uid=0,namespace_changed=True,denied_service_syscalls={str(n):1 for n in (203,206,211,269,425,426,427)},
        capabilities=dict(CapEff=0x400cb,CapPrm=0x400cb,CapBnd=0x400cb,CapInh=0,CapAmb=0),no_new_privileges=1,
        libalpm_initialized=False,package_commit=False,host_namespace_unchanged=True,outside_bytes_unchanged=True,
        guest_file_absent_on_host=True,evidence_marker_persisted=True)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='INERT-full26-controls-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.engine=self.root/'engine';self.receipt=A.prepare(ROOT,self.engine)
        blocker=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden in inert controls'))
        blocker.start();self.addCleanup(blocker.stop)

    def fixture(self,fail=None,interrupt=False):
        module=ModuleType('synthetic_full26');module.__file__=str(self.engine/'scripts/install/test_local_transaction.py')
        module.FIXTURE_SELECTION_SHA256=None;module.GENERIC_VM_CONTRACT=Path('/SYNTHETIC-contract');module.GENERIC_VM_CONTRACT_SHA256='b'*64
        events=[];cleanups=[];executed=[]
        with job.modules(self.engine/'scripts/virtual',('common','guest','image_decode_report')):
            import common,guest
            for cls,names in A.selection().items():
                attrs={'__module__':module.__name__}
                def setup_class(c):c.addClassCleanup(cleanups.append,'class:'+c.__name__)
                attrs['setUpClass']=classmethod(setup_class)
                for name in names:
                    def method(case,cls=cls,name=name):
                        executed.append((cls,name));case.addCleanup(cleanups.append,'case:'+name)
                        if cls=='BarrierTests':
                            self.assertEqual(module.FIXTURE_SELECTION_SHA256,'b'*64)
                            self.assertIsNone(module.GENERIC_VM_CONTRACT)
                            type(case).last_report=barrier(common)
                        else:self.assertIsNone(module.FIXTURE_SELECTION_SHA256)
                        if name==fail:
                            if interrupt:raise KeyboardInterrupt()
                            raise AssertionError('synthetic original duty failure')
                        if cls=='ActualTransactionTests':
                            index=common.TRANSACTION_TESTS.index(name)
                            type(case).execution_history.extend(call(p) for p in common.TRANSACTION_CASES[index][2])
                    attrs[name]=method
                setattr(module,cls,type(cls,(unittest.TestCase,),attrs))
            with patch.object(guest,'emit',side_effect=lambda event,**row:events.append(dict(event=event,**row))), \
                 patch.object(guest,'transaction_execution',side_effect=lambda record,index,hop:record), \
                 patch.object(guest.os,'geteuid',return_value=23001),patch.object(guest.os,'getegid',return_value=23001):
                try:result=guest.transaction_test(module,{},'a'*32,'b'*64,'c'*40)
                except (ValueError,KeyboardInterrupt):result=events[-1] if events else None
            return result,events,cleanups,executed,module

    def test_real_suite_all26_order22_calls_and_all_class_cleanups(self):
        row,events,cleanups,executed,module=self.fixture()
        self.assertEqual(row['status'],A.PASS);self.assertEqual(row['tests'],26)
        self.assertEqual(executed,[(c,n) for c,names in A.selection().items() for n in names])
        self.assertEqual(sum(len(r['calls']) for r in row['methods']),22)
        self.assertEqual(len([r for r in cleanups if r.startswith('class:')]),4)
        self.assertEqual(len([r for r in cleanups if r.startswith('case:')]),26)
        self.assertTrue(row['class_cleanups_returned']);self.assertIsNone(module.FIXTURE_SELECTION_SHA256)
        self.assertEqual(len(events),1)
        self.assertLessEqual(len(json.dumps(row)),8192)

    def test_loader_failure_cannot_be_reported_as_full26(self):
        fail=A.selection()['SourceLoaderTests'][2]
        row,events,cleanups,executed,module=self.fixture(fail)
        self.assertEqual(row['status'],'FAIL');self.assertLess(row['tests'],26)
        self.assertEqual(row['duties'][-1]['status'],'FAIL');self.assertTrue(row['class_cleanups_returned'])
        self.assertIsNone(module.FIXTURE_SELECTION_SHA256)

    def test_interrupt_drains_registered_class_and_instance_duties(self):
        fail=A.selection()['SourceLoaderTests'][0]
        row,events,cleanups,executed,module=self.fixture(fail,True)
        self.assertIsNotNone(row);self.assertEqual(row['status'],'FAIL');self.assertTrue(row['cancelled'])
        self.assertIn('class:SourceLoaderTests',cleanups);self.assertIn('case:'+fail,cleanups)
        self.assertIsNone(module.FIXTURE_SELECTION_SHA256)

    def test_original_tests_runtime_profile_and_deadlines_are_unchanged(self):
        for name in ('scripts/install/test_local_transaction.py','scripts/port/kernel-native-job/runtime.py'):
            self.assertEqual((self.engine/name).read_bytes(),(ROOT/name).read_bytes())
        def constants(file,names):
            return {x.id:ast.literal_eval(n.value) for n in ast.parse(file.read_bytes()).body if isinstance(n,ast.Assign)
                    for x in n.targets if isinstance(x,ast.Name) and x.id in names}
        names={'TRANSACTION_PROFILE_BYTES','TRANSACTION_PROFILE','TRANSACTION_LAUNCHER','TRANSACTION_CASES'}
        self.assertEqual(constants(ROOT/'scripts/virtual/common.py',names),constants(self.engine/'scripts/virtual/common.py',names))
        for name in ('prepare.py','run.py'):
            # Only purpose/PASS literals change; no timeout or capacity integer.
            old=[n.value for n in ast.walk(ast.parse((ROOT/'scripts/virtual'/name).read_bytes())) if isinstance(n,ast.Constant) and type(n.value) in (int,float)]
            new=[n.value for n in ast.walk(ast.parse((self.engine/'scripts/virtual'/name).read_bytes())) if isinstance(n,ast.Constant) and type(n.value) in (int,float)]
            self.assertEqual(old,new)

    def test_protocol_rejects_missing_loader_supervision_and_barrier_duties(self):
        row,*_=self.fixture()
        with job.modules(self.engine/'scripts/virtual',('common',)):
            import common
            for index in (17,24,25):
                bad=copy.deepcopy(row);bad['duties'].pop(index)
                with self.subTest(index=index),self.assertRaises(ValueError):common.transaction_event(bad,'a'*32,'b'*64,'c'*40)
            bad=copy.deepcopy(row);bad['barrier_report']['outside_errno']=0
            with self.assertRaises(ValueError):common.transaction_event(bad,'a'*32,'b'*64,'c'*40)

    def test_protocol_rejects_duplicate_or_reordered_original_method(self):
        row,*_=self.fixture()
        with job.modules(self.engine/'scripts/virtual',('common',)):
            import common
            row['duties'][18]=row['duties'][17]
            with self.assertRaises(ValueError):common.transaction_event(row,'a'*32,'b'*64,'c'*40)

    def test_source_drift_refuses_before_materialization(self):
        pins=json.loads((A.HERE/'held-files.json').read_bytes())
        def changed(path,cap=8*1024**2):
            raw=original(path,cap)
            return raw+b'changed' if path==ROOT/'scripts/install/test_local_transaction.py' else raw
        original=A.read
        with patch.object(A,'read',side_effect=changed),self.assertRaises(ValueError):A.prepare(ROOT,self.root/'bad')
        self.assertFalse((self.root/'bad').exists())

    def test_unbound_policy_before_git_output_or_secret_actor(self):
        with patch.object(job,'read',return_value=dict(schema_version=1,status='UNBOUND_DO_NOT_EXECUTE')), \
             self.assertRaisesRegex(ValueError,'UNBOUND'):job.proof(ROOT,self.root/'proof.json')
        self.assertFalse((self.root/'proof.json').exists())

    def test_missing_unknown_or_failed_vm_retirement_is_not_safe(self):
        self.assertFalse(job.vm_retired(self.root/'missing'))
        out=self.root/'vm/owner-public';out.mkdir(parents=True)
        value=dict(private_workspace_cleanup='PASS',guest=dict(owned_group_retirement='PASS',cleanup_uncertain=False),cleanup=[dict(status='PASS')])
        (out/'result.json').write_bytes(A.encoded(value));self.assertTrue(job.vm_retired(self.root/'vm'))
        value['guest']['cleanup_uncertain']=True;(out/'result.json').write_bytes(A.encoded(value))
        self.assertFalse(job.vm_retired(self.root/'vm'))

    def test_producer_cannot_retire_before_vm_or_without_ownership(self):
        out=self.root/'owned';(out/'native').mkdir(parents=True)
        (out/'native/image-id').write_text('sha256:'+'d'*64)
        (out/'producer-owner.json').write_bytes(A.encoded(dict(token='e'*32,before_images=[])))
        class Native:
            def run(self,*a,**kw):raise AssertionError('must refuse before Docker')
        with self.assertRaises(ValueError):job.cleanup_image(Native(),out,'e'*32,False)
        with self.assertRaises(ValueError):job.cleanup_image(Native(),out,'f'*32,True)

    def test_missing_build_acknowledgement_is_unknown_not_absence(self):
        out=self.root/'unknown-build';out.mkdir();(out/'producer-build.json').write_bytes(b'{}\n')
        value=job.cleanup_image(None,out,'e'*32,True)
        self.assertEqual(value['status'],'RETAINED_CREATION_UNKNOWN');self.assertFalse(value['absence_verified'])

    def test_export_closure_does_not_copy_private_tree_or_accept_failure(self):
        source=self.root/'owned';source.mkdir();(source/'private-key').write_text('secret')
        (source/'result.json').write_bytes(A.encoded(dict(status='FAIL')))
        report=job.retain(source,self.root/'public')
        self.assertEqual(report['status'],'FAIL_OR_INCOMPLETE_FULL26_EVIDENCE')
        self.assertEqual(set(report['files']),{'result.json'});self.assertFalse((self.root/'public/private-key').exists())

    def test_adapter_refuses_existing_output_and_source_alias(self):
        with self.assertRaises(ValueError):A.prepare(ROOT,self.engine)
        link=self.root/'source';link.symlink_to(ROOT,target_is_directory=True)
        with self.assertRaises(ValueError):A.prepare(link,self.root/'new')

    def test_private_controller_core_and_worker_source_refs_are_rebound(self):
        def assignment(path,name):
            return next(ast.literal_eval(n.value) for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.Assign)
                        and any(getattr(t,'id',None)==name for t in n.targets))
        core=assignment(self.engine/'scripts/virtual/controller.py','CORE')
        self.assertEqual(set(core),{'common.py','guest.py','prepare.py','run.py','gbm_probe.c','image_decode_probe.c','image_decode_report.py'})
        for name,pin in core.items():self.assertEqual(A.digest((self.engine/'scripts/virtual'/name).read_bytes())['sha256'],pin)
        refs=assignment(self.engine/'scripts/virtual/common.py','TRANSACTION_FILES')
        for name,row in refs.items():self.assertEqual(A.digest((self.engine/name).read_bytes()),row)
        original=ast.parse((ROOT/'scripts/install/local_transaction.py').read_bytes())
        changed=ast.parse((self.engine/'scripts/install/local_transaction.py').read_bytes())
        class Purpose(ast.NodeTransformer):
            def visit_Constant(self,node):
                if node.value=='installer-transaction-only':node.value=A.PURPOSE
                return node
        self.assertEqual(ast.dump(Purpose().visit(original),include_attributes=False),ast.dump(changed,include_attributes=False))

    def test_export_cannot_promote_a_bare_pass_without_actual_receipts(self):
        source=self.root/'bare';source.mkdir();(source/'result.json').write_bytes(A.encoded(dict(status='PASS')))
        value=job.retain(source,self.root/'bare-public')
        self.assertEqual(value['status'],'FAIL_OR_INCOMPLETE_FULL26_EVIDENCE');self.assertTrue(value['errors'])

    def test_export_retains_all14_pinned_sources_despite_filter_assertion_literals(self):
        source=self.root/'source-export';source.mkdir();A.prepare(ROOT,source/'engine')
        (source/'result.json').write_bytes(A.encoded(dict(status='FAIL')))
        value=job.retain(source,self.root/'source-public')
        self.assertEqual(value['errors'],[])
        self.assertEqual(sum(n.startswith('engine/scripts/') for n in value['files']),14)
        self.assertEqual((self.root/'source-public/engine/scripts/install/test_local_transaction.py').read_bytes(),
                         (ROOT/'scripts/install/test_local_transaction.py').read_bytes())

    def test_source_literal_exception_still_refuses_runtime_private_marker_and_source_armor(self):
        source=self.root/'privacy';(source/'engine/scripts/virtual').mkdir(parents=True)
        name='scripts/virtual/controller.py';raw=b'# -----BEGIN PGP PRIVATE KEY BLOCK-----\n'
        (source/'engine'/name).write_bytes(raw)
        (source/'engine/adapter.json').write_bytes(A.encoded(dict(files={name:dict(after=A.digest(raw))})))
        (source/'result.json').write_bytes(A.encoded(dict(status='FAIL')))
        (source/'native').mkdir();(source/'native/result.json').write_bytes(b'{"error":"PRIVATE KEY"}')
        value=job.retain(source,self.root/'privacy-public')
        self.assertTrue(any(n.startswith('engine/'+name+':') for n in value['errors']))
        self.assertTrue(any(n.startswith('native/result.json:') for n in value['errors']))
        self.assertNotIn('engine/'+name,value['files']);self.assertNotIn('native/result.json',value['files'])

    def tooling_fixture(self):
        source=self.root/'packet';source.mkdir()
        path=self.engine/'scripts/virtual/tooling.lock.json';lock=json.loads(path.read_bytes())
        files={}
        for row in lock['keyring_files']+lock['packages']:
            raw=('inert:'+row['filename']).encode();(source/row['filename']).write_bytes(raw)
            pin=A.digest(raw);row.update(size=pin['bytes'],sha256=pin['sha256']);files[row['filename']]=pin
            if 'signature_size' in row:
                raw=('inert-signature:'+row['filename']).encode();name=row['filename']+'.sig'
                (source/name).write_bytes(raw);pin=A.digest(raw)
                row.update(signature_size=pin['bytes'],signature_sha256=pin['sha256']);files[name]=pin
        path.write_bytes(A.encoded(lock))
        index=dict(schema_version=1,purpose='installer-full26-generic-vm-tooling-inputs',
                   tooling_lock_sha256=job.sha(path),files=files)
        (source/'index.json').write_bytes(A.encoded(index))
        return source,index

    def test_closed_retained_tooling_copies_all45_without_network_or_input_mutation(self):
        source,index=self.tooling_fixture();before={p.name:p.read_bytes() for p in source.iterdir()}
        out=self.root/'tooling-cache';receipt=job.tooling_packet(source,self.engine,out)
        self.assertEqual(receipt['count'],45);self.assertEqual(receipt['network'],'NOT_USED')
        self.assertEqual(receipt['files'],index['files']);self.assertEqual(receipt['bytes'],sum(r['bytes'] for r in index['files'].values()))
        self.assertEqual({p.name:p.read_bytes() for p in source.iterdir()},before)
        self.assertEqual({p.name:p.read_bytes() for p in out.iterdir()},{n:v for n,v in before.items() if n!='index.json'})

    def test_tooling_missing_extra_hash_alias_and_index_drift_refuse_before_cache(self):
        source,index=self.tooling_fixture();name=next(iter(index['files']));raw=(source/name).read_bytes()
        for variant in ('missing','extra','hash','alias','index'):
            with self.subTest(variant=variant):
                if variant=='missing':(source/name).unlink()
                elif variant=='extra':(source/'unexpected').write_bytes(b'extra')
                elif variant=='hash':(source/name).write_bytes(raw+b'x')
                elif variant=='alias':(source/name).unlink();(source/name).symlink_to(source/'index.json')
                else:
                    bad=copy.deepcopy(index);bad['files'][name]['sha256']='0'*64
                    (source/'index.json').write_bytes(A.encoded(bad))
                out=self.root/('bad-cache-'+variant)
                with self.assertRaises((ValueError,OSError)):job.tooling_packet(source,self.engine,out)
                self.assertFalse(out.exists())
                (source/'unexpected').unlink(missing_ok=True)
                if (source/name).is_symlink() or (source/name).exists():(source/name).unlink()
                (source/name).write_bytes(raw);(source/'index.json').write_bytes(A.encoded(index))

    def test_tooling_all_validates_before_materialization_and_changed_copy_refuses(self):
        source,index=self.tooling_fixture();name=next(iter(index['files']));origin=job.A.read;seen=0
        def changed(path,*args):
            nonlocal seen
            raw=origin(path,*args)
            if path==source/name:
                seen+=1
                if seen==2:return raw+b'changed'
            return raw
        with patch.object(job.A,'read',side_effect=changed),self.assertRaises(ValueError):
            job.tooling_packet(source,self.engine,self.root/'racy-cache')
        self.assertFalse((self.root/'racy-cache'/name).exists())

    def test_producer_safe_distinguishes_constructor_from_started_consumers(self):
        from types import SimpleNamespace
        owner=SimpleNamespace(installed=None,installed_owned=None,report=dict(stages={}))
        self.assertTrue(job.producer_safe(None,False,False,self.root/'vm'))
        self.assertTrue(job.producer_safe(owner,False,False,self.root/'vm'))
        self.assertFalse(job.producer_safe(None,True,False,self.root/'vm'))
        self.assertFalse(job.producer_safe(owner,True,False,self.root/'vm'))
        self.assertFalse(job.producer_safe(owner,False,True,self.root/'vm'))
        owner.installed_owned={'image_id':'sha256:'+'a'*64}
        self.assertFalse(job.producer_safe(owner,False,False,self.root/'vm'))
        owner.installed_owned=None;owner.report['stages']={'fixtures':dict(status='FAIL')}
        self.assertFalse(job.producer_safe(owner,False,False,self.root/'vm'))
        owner.report['owned_image_cleanup']=dict(status='PASS')
        self.assertTrue(job.producer_safe(owner,True,False,self.root/'vm'))
        self.assertFalse(job.producer_safe(owner,True,True,self.root/'vm'))

    def test_tooling_validation_precedes_native_actors_and_consumer_start_has_exact_anchor(self):
        node=next(n for n in ast.parse(Path(job.__file__).read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='run')
        calls={}
        for n in ast.walk(node):
            if isinstance(n,ast.Call):
                name=ast.unparse(n.func)
                if name in ('tooling_packet','native.probe','native.main','controller.run'):calls[name]=n.lineno
        self.assertLess(calls['tooling_packet'],calls['native.probe']);self.assertLess(calls['native.probe'],calls['native.main'])
        self.assertLess(calls['native.main'],calls['controller.run'])
        self.assertNotIn('ThreadPoolExecutor',Path(job.__file__).read_text())
        self.assertNotIn('audit_tooling.fetch',Path(job.__file__).read_text())

    def producer_graph(self,tagged=True,borrowed_parent=False):
        token='d'*32;image='sha256:'+'e'*64;borrowed='sha256:'+'f'*64;child='sha256:'+'a'*64
        tag=job.producer_tag(token)
        out=self.root/'producer-graph';(out/'native').mkdir(parents=True)
        (out/'native/image-id').write_text(image)
        job.save(out/'producer-owner.json',dict(token=token,before_images=[borrowed],tag=tag,tag_absent_before=True))
        class Graph:
            def __init__(self):
                self.calls=[]
                self.images={borrowed:dict(tags=[],labels={},parent=None),
                             image:dict(tags=[tag] if tagged else [],labels={job.LABEL:token},parent=borrowed if borrowed_parent else None),
                             child:dict(tags=['cachy-asahi-private-installed:'+'b'*32],labels={},parent=image)}
            def remove(self,identity,prune):
                parent=self.images.pop(identity)['parent']
                if prune and parent in self.images and not self.images[parent]['tags'] and not any(r['parent']==parent for r in self.images.values()):
                    self.remove(parent,True)
            def run(self,argv,**kw):
                self.calls.append(argv)
                if argv[:3]==['docker','image','inspect']:
                    if argv[3] not in self.images:raise subprocess.CalledProcessError(1,argv,stderr='No such image')
                    row=self.images[argv[3]]
                    return json.dumps([dict(Id=argv[3],RepoTags=row['tags'],Config=dict(Labels=row['labels']))])
                if argv[:3]==['docker','image','rm']:
                    target=argv[-1]
                    identity=target if target in self.images else next(i for i,r in self.images.items() if target in r['tags'])
                    self.remove(identity,'--no-prune' not in argv);return ''
                if argv[:3]==['docker','image','ls']:
                    if '--filter' in argv:
                        target=argv[-1].removeprefix('reference=')
                        return '\n'.join(i for i,r in self.images.items() if target in r['tags'])
                    return '\n'.join(self.images)
                raise AssertionError('unexpected actor in inert graph: '+str(argv))
        return Graph(),out,token,image,borrowed,child

    def test_producer_tag_survives_default_child_retirement_until_explicit_cleanup(self):
        graph,out,token,image,borrowed,child=self.producer_graph()
        graph.run(['docker','image','rm',child])
        self.assertIn(image,graph.images)
        result=job.cleanup_image(graph,out,token,True)
        self.assertEqual(result['status'],'PASS');self.assertTrue(result['tag_absence_verified'])
        self.assertFalse(result['parent_pruning']);self.assertEqual(set(graph.images),{borrowed})
        self.assertIn(['docker','image','rm','--no-prune',job.producer_tag(token)],graph.calls)

    def test_untagged_ancestor_graph_reproduces_absent_producer_without_converting_it_to_pass(self):
        graph,out,token,image,borrowed,child=self.producer_graph(tagged=False)
        graph.run(['docker','image','rm',child]);self.assertNotIn(image,graph.images)
        with self.assertRaises(subprocess.CalledProcessError):job.cleanup_image(graph,out,token,True)
        self.assertIn(borrowed,graph.images)

    def test_final_producer_removal_never_prunes_a_borrowed_untagged_ancestor(self):
        graph,out,token,image,borrowed,child=self.producer_graph(borrowed_parent=True)
        graph.run(['docker','image','rm',child]);result=job.cleanup_image(graph,out,token,True)
        self.assertTrue(result['borrowed_images_preserved']);self.assertEqual(set(graph.images),{borrowed})

    def test_cleanup_refuses_unsafe_or_foreign_tag_image_and_label_before_removal(self):
        graph,out,token,image,borrowed,child=self.producer_graph();original=job.read(out/'producer-owner.json')
        for variant in ('unsafe','foreign-tag','not-fresh','borrowed-image','foreign-label','extra-tag'):
            with self.subTest(variant=variant):
                ledger=copy.deepcopy(original);graph.images[image]['labels']={job.LABEL:token};graph.images[image]['tags']=[job.producer_tag(token)]
                if variant=='foreign-tag':ledger['tag']='cachy-asahi-full26-producer:'+'c'*32
                elif variant=='not-fresh':ledger['tag_absent_before']=False
                elif variant=='borrowed-image':ledger['before_images'].append(image)
                elif variant=='foreign-label':graph.images[image]['labels']={job.LABEL:'c'*32}
                elif variant=='extra-tag':graph.images[image]['tags'].append('borrowed:keep')
                job.save(out/'producer-owner.json',ledger)
                with self.assertRaises(ValueError):job.cleanup_image(graph,out,token,variant!='unsafe')
                self.assertIn(image,graph.images)
        self.assertFalse(any(argv[:3]==['docker','image','rm'] for argv in graph.calls))

    def test_producer_lease_tag_requires_exact_run_token(self):
        self.assertEqual(job.producer_tag('a'*32),'cachy-asahi-full26-producer:'+'a'*32)
        for token in ('','a'*31,'A'*32,'../foreign','a'*32+':foreign'):
            with self.subTest(token=token),self.assertRaises(ValueError):job.producer_tag(token)


if __name__=='__main__':unittest.main()
