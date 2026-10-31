# SPDX-License-Identifier: MIT
"""Inert packet/ownership/export controls; synthetic temporary data, no actors."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import job
import snapshot


def synthetic_copy_scope(case):
    repo=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file());sys.path.insert(0,str(repo/'scripts/update'))
    scope=job.load('fixture_copy_scope',repo/'scripts/ci/glibc-gnu-provider-lifecycle/copy_scope.py');derived=scope.qualified()
    return dict(proof=dict(status='PROVED_DISJOINT_READONLY_SOURCE_AND_OWNED_WORK_BIND_ROOTS',source='/held',destination_parent='/work/'+case),checkpoints=7,apps_proof_sha256=scope.PROOF_SHA256,gnu_proof_sha256=derived.gnu_proof_sha256,lifetime_sha256=scope.aux_copy.LIFETIME_SHA256,original_copier_sha256=scope.aux_copy.COPY_SHA256,adapted_copier_sha256=scope.ADAPTED_COPIER_SHA256)


class Controls(unittest.TestCase):
    def test_000_outer_owner_can_load_bridge_without_inner_helper_setup(self):
        # This runs first in the isolated mandatory owner suite: no common.helpers.
        repo=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
        bridge=job.load('cold_copy_scope_bridge',repo/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py')
        self.assertEqual(bridge.scope.qualified().SOURCE,Path('/held'))

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        no=patch.object(subprocess,'Popen',side_effect=AssertionError('no actual actor'));no.start();self.addCleanup(no.stop)

    def archive(self,extra):
        file=self.root/'source.tar'
        with tarfile.open(file,'w',format=tarfile.USTAR_FORMAT) as stream:
            entries=[(n,'directory',None) for n in sorted(snapshot.RUNTIME)]+[('usr','directory',None),('usr/lib','directory',None)]+extra
            for n,kind,value in entries:
                m=tarfile.TarInfo(n);m.uid=os.getuid();m.gid=os.getgid();m.mode=0o755 if kind=='directory' else 0o644;m.mtime=12345
                if kind=='directory':m.type=tarfile.DIRTYPE;stream.addfile(m)
                elif kind=='symlink':m.type=tarfile.SYMTYPE;m.linkname=value;stream.addfile(m)
                elif kind=='hardlink':m.type=tarfile.LNKTYPE;m.linkname=value;stream.addfile(m)
                elif kind=='device':m.type=tarfile.CHRTYPE;stream.addfile(m)
                else:m.size=len(value);stream.addfile(m,io.BytesIO(value))
        return file

    def test_unbound_before_subprocess_output_or_mutation(self):
        with patch.object(job,'read',return_value=dict(schema_version=1,status='UNBOUND_DO_NOT_EXECUTE',packet=None)):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):job.selection(self.root)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_workflow_packet_gate_precedes_existing_secret_seed_and_native_build(self):
        root=next(p for p in Path(__file__).resolve().parents if (p/'.github/workflows/native-arm-glibc-gnu-provider-interruption.yml').is_file())
        text=(root/'.github/workflows/native-arm-glibc-gnu-provider-interruption.yml').read_text()
        self.assertLess(text.index('id: proof'),text.index('id: packet'))
        self.assertLess(text.index('id: packet'),text.index('secrets.'))
        self.assertLess(text.index('id: packet'),text.index('Reuse unchanged owned574 native producer'))
        self.assertIn('cancel-in-progress: false',text);self.assertNotIn('--privileged',text)
        self.assertNotIn('sudo ',text)

    def test_never_started_running_or_previously_started_source_refused(self):
        value=dict(State=dict(Running=False,Pid=0,StartedAt='0001-01-01T00:00:00Z'),HostConfig=dict(ReadonlyRootfs=True))
        job.never_started(value)
        for field,bad in [('Running',True),('Pid',42),('StartedAt','2026-10-16T00:00:00Z')]:
            changed=copy.deepcopy(value);changed['State'][field]=bad
            with self.assertRaises(ValueError):job.never_started(changed)
        value['HostConfig']['ReadonlyRootfs']=False
        with self.assertRaises(ValueError):job.never_started(value)

    def test_export_metadata_and_hardlinks_preserved_without_following_absolute_data_link(self):
        archive=self.archive([('usr/lib/libc.so.6','file',b'fixture libc'),('usr/lib/alias','hardlink','usr/lib/libc.so.6'),('foreign-link','symlink','/never-read-host-root')])
        target=self.root/'original574'
        with patch.object(snapshot,'DATA',self.root),patch.dict(os.environ,OWNER_TOKEN='a'*32):
            result=snapshot.extract(archive,target)
        first=(target/'usr/lib/libc.so.6').stat();second=(target/'usr/lib/alias').stat()
        self.assertEqual((first.st_dev,first.st_ino),(second.st_dev,second.st_ino));self.assertEqual(first.st_nlink,2)
        self.assertEqual(stat.S_IMODE(first.st_mode),0o644);self.assertEqual(first.st_mtime,12345)
        self.assertEqual(os.readlink(target/'foreign-link'),'/never-read-host-root');self.assertEqual(result['logical_bytes'],12)

    def test_archive_hash_and_nanosecond_mtime_are_explicit(self):
        archive=self.archive([('usr/lib/libc.so.6','file',b'fixture')]);target=self.root/'refused'
        with self.assertRaises(ValueError):snapshot.extract(archive,target,'0'*64)
        self.assertFalse(target.exists())
        member=tarfile.TarInfo('fixture');member.pax_headers={'mtime':'12345.123456789'}
        self.assertEqual(snapshot.mtime_ns(member),12345123456789)

    def test_escaping_paths_symlink_parents_and_special_persistent_nodes_refused(self):
        for extra in [[('../escape','file',b'x')],[('alias','symlink','usr'),('alias/write','file',b'x')],[('usr/device','device',None)]]:
            with self.subTest(extra=extra),self.assertRaises(ValueError):snapshot.records(self.archive(extra))

    def test_only_five_explicit_transient_subtrees_omitted(self):
        archive=self.archive([('dev/null','device',None),('tmp/owned-build-marker','file',b'not persistent'),('usr/lib/persistent','file',b'keep')])
        members,total,excluded=snapshot.records(archive)
        self.assertEqual(set(excluded),{'dev/null','tmp/owned-build-marker'});self.assertIn('usr/lib/persistent',members);self.assertEqual(total,4)
        self.assertEqual(snapshot.RUNTIME,{'proc','sys','dev','run','tmp'})

    def test_hardlink_must_target_actual_regular_member(self):
        for target in ['missing','foreign-link','../outside']:
            with self.subTest(target=target),self.assertRaises(ValueError):
                snapshot.records(self.archive([('foreign-link','symlink','/outside'),('usr/lib/alias','hardlink',target)]))

    def pending_export(self):
        token='a'*32;name='caa-gnu-provider-interruption-owner-'+token+'-export'
        return dict(Name='/'+name,Image='sha256:'+'b'*64,Id='c'*64,Config=dict(Labels={job.LABEL:token},Entrypoint=['/usr/bin/false']),
            AppArmorProfile='',RestartCount=0,State=dict(Status='created',ExitCode=0,Error='',Running=False,Pid=0,StartedAt='0001-01-01T00:00:00Z',FinishedAt='0001-01-01T00:00:00Z',Paused=False,Restarting=False,OOMKilled=False,Dead=False),
            HostConfig=dict(ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=None,NetworkMode='none',SecurityOpt=['no-new-privileges']))

    def test_never_started_empty_profile_export_identity_is_retirable_without_start(self):
        value=self.pending_export();name=value['Name'][1:];image=value['Image'];token='a'*32
        self.assertEqual(job.verify_actor(value,name,image,job.LABEL,token,'c'*64),'c'*64)
        report=dict(actors=[dict(name=name,id='c'*64,role='export',status='RESERVED')]);output=self.root/'retire';output.mkdir();calls=[]
        with patch.object(job,'inspect',side_effect=[value,None]):job.retire(report['actors'],image,job.LABEL,token,lambda argv:calls.append(argv),output,report)
        self.assertEqual(calls,[['/usr/bin/docker','rm','--force','c'*64]]);self.assertEqual(report['actors'][0]['status'],'PASS_ABSENCE_VERIFIED')

    def test_empty_profile_export_guard_refuses_started_or_changed_confinement(self):
        changes=[('State','ExitCode',1),('State','Error','failed start'),('State','Status','exited'),('State','Running',True),('State','Pid',42),('State','StartedAt','2026-10-17T00:00:00Z'),('State','FinishedAt','2026-10-17T00:00:00Z'),
                 ('State','Paused',True),('State','Restarting',True),('State','OOMKilled',True),('State','Dead',True),('HostConfig','ReadonlyRootfs',False),('HostConfig','Privileged',True),
                 ('HostConfig','CapDrop',[]),('HostConfig','CapAdd',['SYS_ADMIN']),('HostConfig','NetworkMode','host'),('HostConfig','SecurityOpt',['no-new-privileges','apparmor=unconfined']),('Config','Entrypoint',['/usr/bin/sleep'])]
        for section,key,bad in changes:
            value=self.pending_export();value[section][key]=bad
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):job.verify_actor(value,value['Name'][1:],value['Image'],job.LABEL,'a'*32)
        value=self.pending_export();value['RestartCount']=1
        with self.assertRaises(ValueError):job.verify_actor(value,value['Name'][1:],value['Image'],job.LABEL,'a'*32)

    def test_empty_profile_nonexport_and_foreign_export_remain_refused(self):
        for suffix in ('extract','source-cleanup','inner-scrub'):
            value=self.pending_export();name=value['Name'][1:].removesuffix('export')+suffix;value['Name']='/'+name
            with self.assertRaises(ValueError):job.verify_actor(value,name,value['Image'],job.LABEL,'a'*32)
        value=self.pending_export();value['Config']['Labels'][job.LABEL]='foreign'
        with self.assertRaises(ValueError):job.verify_actor(value,value['Name'][1:],value['Image'],job.LABEL,'a'*32)

    def test_foreign_actor_and_unknown_daemon_state_preserved(self):
        value=dict(Name='/owned',Image='sha256:'+'a'*64,Config=dict(Labels={job.LABEL:'b'*32}),Id='c'*64,AppArmorProfile='docker-default')
        self.assertEqual(job.verify_actor(value,'owned','sha256:'+'a'*64,job.LABEL,'b'*32),'c'*64)
        value['AppArmorProfile']='unexpected-custom-profile'
        with self.assertRaises(ValueError):job.verify_actor(value,'owned','sha256:'+'a'*64,job.LABEL,'b'*32)
        value['AppArmorProfile']='docker-default'
        value['Config']['Labels'][job.LABEL]='foreign'
        with self.assertRaises(ValueError):job.verify_actor(value,'owned','sha256:'+'a'*64,job.LABEL,'b'*32)
        with self.assertRaises(ValueError):job.inspect('owned',lambda *a,**k:dict(code=1,out=b'',err=b'daemon unavailable'))

    def test_private_binding_changes_only_policy_and_policy_manifest_entry(self):
        workspace=self.root/'source';lane=workspace/job.LANE;lane.mkdir(parents=True)
        for name,raw in [('common.py',b'never executed fixture\n'),('input-policy.json',b'{"status":"UNBOUND_DO_NOT_EXECUTE","binding":null}\n')]:
            (lane/name).write_bytes(raw)
        original=dict(schema_version=1,files={p.name:dict(bytes=p.stat().st_size,sha256=job.sha(p)) for p in lane.iterdir()})
        job.save(lane/'source-manifest.json',original)
        packet=self.root/'packet';packet.mkdir();proof=packet/'private.json';job.save(proof,dict(candidate_package_sha256='a'*64))
        p=dict(files={'private.json':{k:v for k,v in job.ref(packet,proof).items() if k!='path'}},private16k=job.ref(packet,proof),provider_pair=job.ref(packet,proof),probe_receipt=job.ref(packet,proof),held=job.ref(packet,proof),archives={'a':job.ref(packet,proof),'b':job.ref(packet,proof)},probes={},provider_pkgbuild_sha256='c'*64)
        base=self.root/'base';base.mkdir();(base/'installed-packages.lock').write_bytes(b'fixture lock');job.save(base/'report.json',dict(status='fixture'))
        output=self.root/'output';output.mkdir();job.save(output/'owner.json',{})
        report=dict(image='sha256:'+'d'*64,token='e'*32,producer_token='f'*16,source_snapshot=dict(observation=dict(node_sha256='0'*64,security_capabilities={'usr/bin/INERT':'0100000240000000000000000000000000000000'},source_capabilities_sha256=hashlib.sha256((json.dumps({'usr/bin/INERT':'0100000240000000000000000000000000000000'},sort_keys=True,indent=2)+'\n').encode()).hexdigest())))
        inputs,runner=job.materialize(workspace,base,packet,p,output,report)
        self.assertEqual((lane/'common.py').read_bytes(),(runner/'common.py').read_bytes());self.assertEqual(job.read(lane/'input-policy.json')['status'],'UNBOUND_DO_NOT_EXECUTE')
        self.assertEqual(job.read(runner/'input-policy.json')['binding']['index_sha256'],job.sha(inputs/'interruption-input.json'))
        changed=job.read(runner/'source-manifest.json');self.assertEqual(changed['files']['common.py'],original['files']['common.py'])
        self.assertEqual(report['private_binding']['changed_files'],['input-policy.json','source-manifest.json']);self.assertEqual(job.read(inputs/'interruption-input.json')['source_capabilities'],report['source_snapshot']['observation']['security_capabilities'])

    def consumer_fixture(self):
        output=self.root/'complete-owner';public=output/'inner/public';public.mkdir(parents=True)
        observation='a'*64;cases={}
        for case in ('pristine','modified'):
            interrupted=dict(status='PASS_ACTUAL_REMOVE_PHASE_KILL_AND_EXTERNAL_RECOVERY',
                writer=dict(group_absence_verified=True,exit_code=-9),
                observed_stop='KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER',
                checkpoint=dict(phase='ALPM_COMMIT_REMOVE_PAYLOAD_BEFORE_OLD_DATABASE_REMOVAL',event=4,package='glibc'),
                partial_state='HELD574_DATABASE_WITH_PARTIALLY_REMOVED_HELD_PAYLOAD_CANDIDATE_NOT_ADDED',
                lock_recovery=dict(status='PASS_EXACT_OWNED_STALE_LOCK_REMOVED_AFTER_GROUP_ABSENCE'),
                outer_runtime_before=dict(synthetic='only'),outer_runtime_after=dict(synthetic='only'))
            row=dict(status='PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE',source_before=observation,
                     source_after=observation,copy_lifetime=dict(copy={'gnu_bind_scope':synthetic_copy_scope(case)},cleanup='PASS-owned-workspace-removed',security_capabilities='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED',source_capabilities_sha256=hashlib.sha256(b'{}\n').hexdigest()),interruption=interrupted,capability_checks={})
            for name in ('before_runtime','recovered_runtime','provider_runtime','reinstalled_runtime','held_runtime'):
                row[name]=dict(normal_parent_and_child=True,result=dict(status='PASS',cases=8,page_size=4096))
            cases[case]=row
            for stage in ('source-before','source-after','clone','before574','precommit-refused',
                          'interrupted-before-unlock','recovered-held574','provider574','reinstalled574','held574'):
                row['capability_checks'][case+'-'+stage]=dict(status='EXACT_SOURCE_MAP_PRESERVED',sha256=hashlib.sha256(b'{}\n').hexdigest(),paths=0)
                (public/(case+'-'+stage+'-root.json.gz')).write_bytes(b'synthetic observation fixture only')
        value=dict(status='PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY',hardware='NOT_RUN',
                   interrupted_in_progress_replacement='REMOVE_PHASE_ONLY_CANDIDATE_EXTRACTION_NOT_TESTED',cases=cases)
        job.save(public/'result.json',value)
        return output,observation,value

    def test_complete_interruption_records_are_required(self):
        output,source,value=self.consumer_fixture();result=job.consumer_records(output,source)
        self.assertEqual(len(result['files']),21)
        (output/'inner/public/pristine-interrupted-before-unlock-root.json.gz').unlink()
        with self.assertRaises(FileNotFoundError):job.consumer_records(output,source)

    def test_synthetic_precommit_or_unknown_writer_never_qualifies(self):
        output,source,value=self.consumer_fixture()
        for field,bad in [('phase','PREPARED_NOT_COMMITTED'),('event',0)]:
            changed=copy.deepcopy(value);changed['cases']['pristine']['interruption']['checkpoint'][field]=bad
            job.save(output/'inner/public/result.json',changed)
            with self.assertRaisesRegex(ValueError,'real stopped/killed writer'):job.consumer_records(output,source)
        for field,bad in [('group_absence_verified',False),('exit_code',0)]:
            changed=copy.deepcopy(value);changed['cases']['pristine']['interruption']['writer'][field]=bad
            job.save(output/'inner/public/result.json',changed)
            with self.assertRaisesRegex(ValueError,'real stopped/killed writer'):job.consumer_records(output,source)

    def test_recovered_normal_probe_and_source_preservation_are_mandatory(self):
        output,source,value=self.consumer_fixture()
        changed=copy.deepcopy(value);changed['cases']['modified']['recovered_runtime']['normal_parent_and_child']=False
        job.save(output/'inner/public/result.json',changed)
        with self.assertRaisesRegex(ValueError,'normal parent/child'):job.consumer_records(output,source)
        job.save(output/'inner/public/result.json',value)
        with self.assertRaisesRegex(ValueError,'source preservation'):job.consumer_records(output,'b'*64)

    def test_manifest_pins_all_fifteen_consumer_files_and_unchanged_helpers(self):
        repo=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
        manifest=job.read(job.HERE/'integration-manifest.json')['files']
        lane=repo/job.LANE;names={f.name for f in lane.iterdir() if f.is_file()}
        self.assertEqual(len(names),15)
        self.assertEqual({n.removeprefix(job.LANE+'/') for n in manifest if n.startswith(job.LANE+'/')},names)
        for name,row in manifest.items():
            file=job.HERE/Path(name).name if name.startswith('scripts/ci/glibc-gnu-provider-interruption-owner/') else repo/name
            self.assertEqual(file.stat().st_size,row['bytes']);self.assertEqual(job.sha(file),row['sha256'])
        dependencies=job.read(lane/'dependencies.json')['files']
        self.assertTrue(set(dependencies)<=set(manifest))

    def test_manual_workflow_bootstrap_matches_frozen_owner(self):
        root=next(p for p in Path(__file__).resolve().parents if (p/'.github/workflows/native-arm-glibc-gnu-provider-interruption.yml').is_file())
        text=(root/'.github/workflows/native-arm-glibc-gnu-provider-interruption.yml').read_text()
        self.assertIn("'"+job.sha(job.HERE/'job.py')+"' \"$SLICE/job.py\"",text)
        self.assertIn("'"+job.sha(job.HERE/'integration-manifest.json')+"' \"$SLICE/integration-manifest.json\"",text)
        self.assertIn('test_lifecycle_controls.py',text);self.assertIn('test_interruption.py',text)
        self.assertEqual(text.count('workflow_dispatch:'),1)

    def test_snapshot_only_changes_the_import_to_the_new_lane(self):
        repo=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
        original=(repo/'scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py').read_text()
        expected=original.replace("source/'scripts/ci/glibc-gnu-provider-lifecycle'","source/'scripts/ci/glibc-gnu-provider-interruption'")
        self.assertEqual((job.HERE/'snapshot.py').read_text(),expected)

    def test_wrong_inner_name_keeps_the_producer(self):
        output=self.root/'owner';(output/'inner').mkdir(parents=True)
        (output/'owner.lock').touch();(output/'inner/lease').touch()
        token='a'*32;image='sha256:'+'b'*64
        job.save(output/'owner.json',dict(token=token,producer_token='c'*16,image=image,actors=[],commands=[]))
        job.save(output/'inner/owner.json',dict(token=token,image_id=image,actors=[dict(role='trial',name='caa-glibc-provider-'+token+'-trial')]))
        proof=self.root/'proof.json';job.save(proof,dict(consumer_token=token,producer_token='c'*16))
        base=self.root/'base';base.mkdir();job.save(base/'report.json',{})
        args=NS(workspace=self.root,proof=proof,base=base,output=output,receipt=self.root/'cleanup.json')
        with patch.object(job,'selection'),patch.object(job,'command_api'),patch.object(job,'runtime',side_effect=AssertionError('producer retained')):
            self.assertEqual(job.cleanup(args),1)
        self.assertEqual(job.read(args.receipt)['producer'],'PRESERVED')

    def retain_fixture(self,missing_binding=False):
        output,source,value=self.consumer_fixture()
        (output/'apparmor').mkdir();(output/'apparmor/trial.profile').write_bytes(b'inert fixture only\n')
        apparmor=dict(status='PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS',profile=dict(bytes=19,sha256=hashlib.sha256(b'inert fixture only\n').hexdigest()))
        job.save(output/'apparmor/state.json',apparmor)
        job.save(output/'owner.json',dict(status='PASS_INTERRUPTION_PENDING_ORDERED_PRODUCER_CLEANUP',
                 apparmor=apparmor,consumer_cleanup='PASS_ALL_ACTORS_CLONES_AND_SOURCE_DATA_RETIRED',source_snapshot=dict(observation=dict(node_sha256=source,security_capabilities={},source_capabilities_sha256=hashlib.sha256(b'{}\n').hexdigest())),capabilities=dict(status='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256=hashlib.sha256(b'{}\n').hexdigest(),paths=0,cases=2,stages=10,copy_scope_sha256={case:hashlib.sha256((json.dumps(synthetic_copy_scope(case),sort_keys=True,indent=2)+'\n').encode()).hexdigest() for case in ('pristine','modified')})))
        job.save(output/'inner/owner.json',dict(synthetic=True))
        (output/'snapshot-public').mkdir();job.save(output/'snapshot-public/snapshot.json',dict(synthetic=True))
        (output/'snapshot-public/original574-root.json.gz').write_bytes(b'synthetic observation only')
        (output/'inputs').mkdir();(output/'interruption-runner').mkdir()
        if not missing_binding:job.save(output/'inputs/interruption-input.json',dict(synthetic=True,source_capabilities={},source_capabilities_sha256=hashlib.sha256(b'{}\n').hexdigest()))
        repo=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file());(self.root/'manifests').mkdir(exist_ok=True);(self.root/'manifests/packages.toml').write_bytes(b'# inert source-shape fixture only\n')
        for relative in ('scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py','scripts/ci/glibc-gnu-provider-lifecycle/copy_scope.py','scripts/apps/full574_copy.py'):
            target=self.root/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((repo/relative).read_bytes())
        for name in ('input-policy.json','source-manifest.json'):job.save(output/'interruption-runner'/name,dict(synthetic=True))
        proof=self.root/'proof.json';job.save(proof,{})
        receipt=self.root/'ordered.json';job.save(receipt,dict(status='PASS_ORDERED_ALL_CONSUMERS_THEN_PRODUCER',apparmor=apparmor))
        base=self.root/'base';base.mkdir();job.save(base/'report.json',dict(synthetic=True));(base/'installed-packages.lock').write_bytes(b'synthetic lock')
        packet=self.root/'packet';packet.mkdir();job.save(packet/'packet.json',dict(synthetic=True))
        here=self.root/'owner-source';here.mkdir();job.save(here/'integration-manifest.json',dict(files={}))
        return NS(workspace=self.root,proof=proof,receipt=receipt,base=base,output=output,packet_root=packet,public=self.root/'public'),here

    def test_retainer_captures_new_interruption_binding_and_complete_records(self):
        args,here=self.retain_fixture()
        with patch.object(job,'HERE',here),patch.object(job,'selection'),patch.object(job,'packet',return_value=(args.packet_root,dict(files={}))):
            self.assertEqual(job.retain(args),0)
        value=job.read(args.public/'export.json');self.assertIn('binding/interruption-input.json',value['files'])
        self.assertTrue(all('interruption/'+n in value['files'] for n in value['consumer_records']['files']))
        self.assertFalse(any('source.tar' in n or 'original574/' in n for n in value['files']))

    def test_missing_binding_does_not_export_a_complete_pass(self):
        args,here=self.retain_fixture(missing_binding=True)
        with patch.object(job,'HERE',here),patch.object(job,'selection'),patch.object(job,'packet',return_value=(args.packet_root,dict(files={}))):
            self.assertEqual(job.retain(args),1)
        self.assertEqual(job.read(args.public/'export.json')['status'],'FAIL_OR_INCOMPLETE')

    def test_unknown_consumer_blocks_producer_cleanup(self):
        output=self.root/'owner';output.mkdir();(output/'owner.lock').touch()
        token='a'*32;image='sha256:'+'b'*64
        report=dict(token=token,producer_token='c'*16,image=image,actors=[dict(name='owned',id=None,status='RESERVED',role='export')],commands=[])
        job.save(output/'owner.json',report);proof=self.root/'proof.json';job.save(proof,dict(consumer_token=token,producer_token='c'*16))
        base=self.root/'base';base.mkdir();job.save(base/'report.json',{})
        args=NS(workspace=self.root,proof=proof,base=base,output=output,receipt=self.root/'cleanup.json')
        command=lambda *a,**k:dict(code=1,out=b'',err=b'daemon unavailable')
        with patch.object(job,'selection'),patch.object(job,'command_api',return_value=command),patch.object(job,'runtime',side_effect=AssertionError('producer must remain')):
            self.assertEqual(job.cleanup(args),1)
        result=job.read(args.receipt);self.assertEqual(result['producer'],'PRESERVED');self.assertEqual(result['status'],'FAIL')

    def test_existing_producer_directory_flock_is_exclusive(self):
        with job.producer_lease(self.root):
            with self.assertRaises(BlockingIOError):
                with job.producer_lease(self.root):pass

    def test_retainer_cannot_export_rootfs_or_unindexed_private_root(self):
        output=self.root/'owner';output.mkdir();(output/'data').mkdir();(output/'data/source.tar').write_bytes(b'never public')
        proof=self.root/'proof.json';job.save(proof,{})
        cleanup=self.root/'cleanup.json';job.save(cleanup,dict(status='FAIL'))
        packet=self.root/'packet';packet.mkdir();job.save(packet/'packet.json',dict(files={}))
        args=NS(workspace=self.root,proof=proof,receipt=cleanup,base=self.root/'base',output=output,packet_root=packet,public=self.root/'public')
        with patch.object(job,'selection'),patch.object(job,'packet',return_value=(packet,dict(files={}))):job.retain(args)
        files=job.read(args.public/'export.json')['files'];self.assertFalse(any('source.tar' in n or 'original574/' in n for n in files))


    def test_setfcap_grant_is_only_the_exact_extraction_actor(self):
        for role in ('extract','source-cleanup','inner-scrub'):
            output=self.root/role;output.mkdir();report=dict(token='a'*32,image='sha256:'+'b'*64,actors=[],snapshot_point=dict(archive_sha256='c'*64));command=unittest.mock.Mock(return_value=dict(code=0))
            with patch.object(job,'inspect',side_effect=[None,dict(AppArmorProfile='docker-default')]),patch.object(job,'verify_actor',return_value='d'*64):job.observer(self.root,output,report,command,role,'/runner/capability_snapshot.py')
            argv=command.call_args.args[0];self.assertEqual('--cap-add=SETFCAP' in argv,role=='extract');self.assertIn('--network=none',argv);self.assertIn('--security-opt=no-new-privileges',argv)

    def test_capability_wrapper_is_isolated_and_original_extractors_are_unchanged(self):
        repo=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
        original=repo/'scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py';self.assertEqual(job.sha(original),'9738acb125ce6d468d5359ecfbd5540454826567fd4ac4481576ec31da37190c')
        text=(job.HERE/'capability_snapshot.py').read_text();self.assertIn("scripts/ci/apps-full574-native/export_extract.py",text);self.assertIn("old=derivative.isolated",text);self.assertIn("api['caps'].restore",text)

if __name__=='__main__':unittest.main()
