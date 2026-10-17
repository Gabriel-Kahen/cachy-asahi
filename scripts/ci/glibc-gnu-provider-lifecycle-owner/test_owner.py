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


class Controls(unittest.TestCase):
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
        root=next(p for p in Path(__file__).resolve().parents if (p/'.github/workflows/native-arm-glibc-gnu-provider-lifecycle.yml').is_file())
        text=(root/'.github/workflows/native-arm-glibc-gnu-provider-lifecycle.yml').read_text()
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
        self.assertEqual(job.read(runner/'input-policy.json')['binding']['index_sha256'],job.sha(inputs/'lifecycle-input.json'))
        changed=job.read(runner/'source-manifest.json');self.assertEqual(changed['files']['common.py'],original['files']['common.py'])
        self.assertEqual(report['private_binding']['changed_files'],['input-policy.json','source-manifest.json']);self.assertEqual(job.read(inputs/'lifecycle-input.json')['source_capabilities'],report['source_snapshot']['observation']['security_capabilities'])

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
