#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actor-fenced synthetic hosted bootstrap DATA controls; no actual Reader role."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace


def deny(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('operational actor forbidden: '+event)


sys.addaudithook(deny)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('modeled_hosted_reader',HERE/'payload/hosted/reader.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


def binding():return dict(source='1'*40,ref='refs/heads/codex/MODELED',run='123',job='456',approval='2'*64,source_map_sha256='3'*64,component_map_sha256=r.COMPONENT_MAP,operation='perl5423-native-pair-v2')


def natural(code=0):return dict(pid=100,exit=code,natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,leader_held_until_group_inspection=True,ownership_lost=False,exit_observed_via_waitpid=True,elapsed_seconds=.1)


def signature_status():return '[GNUPG:] VALIDSIG '+r.SIGNER+' 2026-11-15 1 0 4 0 1 8 00 '+r.SIGNER+'\n'


def daemon_fixture():
    return dict(schema=1,status='OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS',native_acceptance=False,
        info=dict(ID='MODELED-local-daemon',DockerRootDir='/MODELED/docker',OSType='linux',Architecture='aarch64',
                  SecurityOptions=['name=seccomp,profile=builtin'],CgroupVersion='2',CpuCfsQuota=True,MemoryLimit=True,SwapLimit=True,PidsLimit=True),
        version={'Server':{'Os':'linux','Arch':'arm64'}},host=dict(system='Linux',machine='aarch64',uid=1001,gid=1001,MemAvailable_bytes=8*1024*r.MIB),
        socket=dict(path='/var/run/docker.sock',uid=0,socket=True,stable=True),storage=dict(path='/MODELED/docker',canonical=True,accessible=True,device=1,
            available_bytes=8*1024*r.MIB,total_inodes=1000000,available_inodes=200000,
            work_filesystems=[dict(path='/MODELED/runner-temp'+suffix,canonical=True,accessible=True,device=index,
                available_bytes=8*1024*r.MIB,total_inodes=1000000,available_inodes=200000)
                for index,suffix in enumerate(('','/perl-hosted','/alarm-cache','/pgo-hosted-retained'),10)]))


def fixture(root):
    """Invented archives/statuses/operation streams; no signed native payloads."""
    b=binding();image='sha256:'+'4'*64
    def item(index):return dict(filename='MODELED-'+str(index)+'.pkg.tar.xz',url='https://invalid.example/MODELED-'+str(index),sha256='5'*64,size=100,signature_size=20,signature_sha256='6'*64)
    original=dict(packages=[item(i) for i in range(248)],rootfs=item(999),keyring_files=[dict(filename='MODELED-key-'+str(i),url='https://invalid.example/key',sha256='7'*64,size=10) for i in range(3)],signer_fingerprint=r.SIGNER)
    extras=[item(248+i) for i in range(8)];combined=dict(original,packages=original['packages']+extras)
    source={'original/bootstrap/scripts/ci/inputs.lock.json':r.encoded(original),'original/native/input-profile.json':r.encoded({'additions':{'rows':extras}})}
    lock=(HERE.parent/'perl5423-repro-native-source/references/expected349.lock').read_bytes();source['original/native/expected349.lock']=lock
    for name,raw in source.items():
        leaf=root/name;leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(raw)
    data={'bootstrap/inputs.lock.json':r.encoded(combined),'bootstrap/packages.lock':lock}
    payloads=[combined['rootfs'],*combined['packages']];inputs=combined['keyring_files'][:]
    for row in payloads:inputs.extend((row,dict(filename=row['filename']+'.sig',sha256=row['signature_sha256'],size=row['signature_size'])))
    acq=dict(schema_version=1,acquisition='PASS',signature_authentication='NOT RUN',counts={'total':517,'pass':517,'fail':0,'pending':0},inputs={x['filename']:dict(status='PASS',expected_sha256=x['sha256'],expected_bytes=x['size']) for x in inputs})
    data['bootstrap/acquisition.json']=r.encoded(acq)
    token=r.hashlib.sha256((b['source']+':'+b['ref']+':'+b['run']).encode()).hexdigest()[:24];tag='perl-native-base:'+token;label='cachy-asahi.hosted-perl'
    operations=[]
    def emit(argv,out=b'',err=b'',code=0):
        index=len(operations);base='bootstrap/operations/'+str(index).zfill(3)
        data[base+'.stdout']=out;data[base+'.stderr']=err
        operations.append(dict(argv=argv,stdout=base+'.stdout',stderr=base+'.stderr',stdout_pin=r.pin(out),stderr_pin=r.pin(err),lifecycle=natural(code),returncode=code))
    daemon=daemon_fixture();data['daemon.json']=r.encoded(daemon)
    for key in ('info','version'):emit(r.DOCKER+[key,'--format','{{json .}}'],r.encoded(daemon[key]))
    for selector in ('reference='+tag,'label='+label+'='+token):emit(r.DOCKER+['image','ls','--no-trunc','-q','--filter',selector])
    signatures={}
    for row in payloads:
        argv=['gpg','--batch','--no-options','--homedir','/MODELED/bootstrap/gpg','--no-auto-key-retrieve','--status-fd','1','--verify','/MODELED/cache/'+row['filename']+'.sig','/MODELED/cache/'+row['filename']]
        signatures[row['filename']]=dict(command=argv,exit_code=0,status=signature_status(),diagnostic='MODELED GPG diagnostic\n')
        emit(argv,signature_status().encode(),b'MODELED GPG diagnostic\n')
    data['bootstrap/signatures.json']=r.encoded(signatures)
    build=r.DOCKER+['build','--no-cache','--tag',tag,'--label',label+'='+token,'--label',label+'.source='+b['source'],'--network=none','--pull=false','--platform=linux/arm64','--iidfile','/MODELED/bootstrap/image-id','/MODELED/bootstrap/context']
    emit(build,b'MODELED bootstrap stdout\n')
    probe='perl-bootstrap-inventory-'+token
    emit(r.DOCKER+['run','--name',probe,'--label',label+'='+token,'--label',label+'.source='+b['source'],'--cpus=1','--memory=128m','--memory-swap=128m','--pids-limit=32','--rm','--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',image,'/builder-packages.lock'],lock)
    emit(['gpgconf','--homedir','/MODELED/bootstrap/gpg','--kill','gpg-agent'])
    emit(r.DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'])
    inspected=[dict(Id=image,Architecture='arm64',Os='linux',RepoTags=[tag],Config={'Labels':{label:token,label+'.source':b['source']}})]
    emit(r.DOCKER+['image','inspect',image],r.encoded(inspected));emit(r.DOCKER+['image','rm',image],('Deleted: '+image+'\n').encode());emit(r.DOCKER+['image','inspect',image],b'[]\n',('Error response from daemon: No such image: '+image+'\n').encode(),1)
    data['bootstrap/bootstrap.json']=r.encoded(dict(status='image-provisioned',image_id=image,packages_lock_sha256=r.EXPECTED349))
    h=dict(schema=1,status='PAIR_COMPLETED',binding=b,source_readback_sha256='8'*64,daemon_identity_sha256='9'*64,pair_exit=0,cleanup={'image':image,'gpg_agent_absent':True,'probe_absent':True,'image_removed':True,'image_absent':True,'error':None},bootstrap={'image':image,'expected349_sha256':r.EXPECTED349})
    def refresh():
        data['bootstrap/operations.json']=r.encoded(operations)
        for key,name in [('acquisition_sha256','acquisition'),('signatures_sha256','signatures'),('operations_sha256','operations')]:h['bootstrap'][key]=r.pin(data['bootstrap/'+name+'.json'])['sha256']
    refresh()
    return b,h,data,operations,refresh


class HostedData(unittest.TestCase):
    def test_positive_is_only_synthetic_signed349_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            b,h,data,ops,refresh=fixture(Path(tmp));result=r.bootstrap_data(data.__getitem__,Path(tmp),h,b)
            self.assertEqual((result['input_files'],result['signed_payloads'],result['packages']),(517,257,349));self.assertTrue(result['image_absence_verified'])

    def test_acquisition_missing_bad_count_and_byte_pin_refuse(self):
        for change in (lambda v:v['inputs'].pop(next(iter(v['inputs']))),lambda v:v['counts'].update(total=501),lambda v:next(iter(v['inputs'].values())).update(expected_bytes=99),lambda v:next(iter(v['inputs'].values())).update(status='FAIL')):
            with tempfile.TemporaryDirectory() as tmp:
                b,h,data,ops,refresh=fixture(Path(tmp));v=r.decode(data['bootstrap/acquisition.json']);change(v);data['bootstrap/acquisition.json']=r.encoded(v);refresh()
                with self.subTest(change=change),self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)

    def test_signature_expired_wrong_signer_and_missing_payload_refuse(self):
        for change in (lambda v:v.pop(next(iter(v))),lambda v:next(iter(v.values())).update(exit_code=1),lambda v:next(iter(v.values())).update(status=signature_status()+'[GNUPG:] EXPKEYSIG MODELED\n'),lambda v:next(iter(v.values())).update(status=signature_status().replace(r.SIGNER,'A'*40))):
            with tempfile.TemporaryDirectory() as tmp:
                b,h,data,ops,refresh=fixture(Path(tmp));v=r.decode(data['bootstrap/signatures.json']);change(v);data['bootstrap/signatures.json']=r.encoded(v);refresh()
                with self.subTest(change=change),self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)

    def test_gpg_json_cannot_replace_actual_raw_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            b,h,data,ops,refresh=fixture(Path(tmp));v=r.decode(data['bootstrap/signatures.json']);next(iter(v.values()))['diagnostic']='SUBSTITUTED';data['bootstrap/signatures.json']=r.encoded(v);refresh()
            with self.assertRaisesRegex(ValueError,'raw command streams'):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)

    def test_forced_wrong_pin_or_unexpected_nonzero_retirement_refuse(self):
        for change in (lambda rows:rows[4]['lifecycle'].update(forced_cleanup=True),lambda rows:rows[4].update(stdout_pin={'bytes':0,'sha256':'0'*64}),lambda rows:rows[0].update(returncode=1,lifecycle=natural(1))):
            with tempfile.TemporaryDirectory() as tmp:
                b,h,data,ops,refresh=fixture(Path(tmp));change(ops);refresh()
                with self.subTest(change=change),self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)

    def test_cleanup_booleans_cannot_replace_actual_owned_absence(self):
        for change in (lambda rows:rows[-2]['argv'].append('--force'),lambda rows:rows[-3]['argv'].__setitem__(-1,'sha256:'+'A'*64),lambda rows:rows[-1].update(returncode=0,lifecycle=natural(0))):
            with tempfile.TemporaryDirectory() as tmp:
                b,h,data,ops,refresh=fixture(Path(tmp));change(ops);refresh()
                with self.subTest(change=change),self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)
        with tempfile.TemporaryDirectory() as tmp:
            b,h,data,ops,refresh=fixture(Path(tmp));data[ops[-1]['stderr']]=b'MODELED unrelated error';ops[-1]['stderr_pin']=r.pin(data[ops[-1]['stderr']]);refresh()
            with self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)

    def test_gpg_agent_retirement_requires_same_home_natural_command_and_absence(self):
        for change in (lambda rows:rows[-5]['argv'].__setitem__(2,'/MODELED/other-gpg'),
                       lambda rows:rows[-5]['argv'].__setitem__(-1,'dirmngr'),
                       lambda rows:rows[-5]['lifecycle'].update(forced_cleanup=True)):
            with tempfile.TemporaryDirectory() as tmp:
                b,h,data,ops,refresh=fixture(Path(tmp));change(ops);refresh()
                with self.subTest(change=change),self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)
        with tempfile.TemporaryDirectory() as tmp:
            b,h,data,ops,refresh=fixture(Path(tmp));h['cleanup']['gpg_agent_absent']=False
            with self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)

    def test_foreign_bootstrap_labels_and_nonempty_baseline_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            b,h,data,ops,refresh=fixture(Path(tmp));v=r.decode(data[ops[-3]['stdout']]);v[0]['Config']['Labels']['cachy-asahi.hosted-perl']='FOREIGN';raw=r.encoded(v);data[ops[-3]['stdout']]=raw;ops[-3]['stdout_pin']=r.pin(raw);refresh()
            with self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)
        with tempfile.TemporaryDirectory() as tmp:
            b,h,data,ops,refresh=fixture(Path(tmp));data[ops[2]['stdout']]=b'sha256:MODELED-preexisting\n';ops[2]['stdout_pin']=r.pin(data[ops[2]['stdout']]);refresh()
            with self.assertRaises(ValueError):r.bootstrap_data(data.__getitem__,Path(tmp),h,b)

    def test_actual_daemon_preconditions_refuse_remapping_or_unbounded_resources(self):
        r.daemon_data(daemon_fixture())
        for change in (lambda value:value['info'].update(Architecture='x86_64'),lambda value:value['info'].update(SecurityOptions=['name=rootless']),
                       lambda value:value['info'].update(SwapLimit=False),lambda value:value['socket'].update(stable=False),
                       lambda value:value['storage'].update(available_inodes=0,total_inodes=0),lambda value:value['host'].update(MemAvailable_bytes=1),
                       lambda value:value['storage']['work_filesystems'].pop(),
                       lambda value:value['storage']['work_filesystems'][2].update(path='/MODELED/wrong-cache'),
                       lambda value:value['storage']['work_filesystems'][1].update(available_bytes=8*1024*r.MIB-1),
                       lambda value:value['storage']['work_filesystems'][0].update(available_inodes=0,total_inodes=0)):
            value=daemon_fixture();change(value)
            with self.subTest(change=change),self.assertRaises(ValueError):r.daemon_data(value)

    def test_readback_actor_streams_join_whole_source_and_actual_daemon(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);b=binding();body=b'MODELED Source DATA\n';(root/'MODELED.txt').write_bytes(body)
            source_map={'schema':1,'files':{'MODELED.txt':dict(**r.pin(body),mode=0o644)}};map_raw=r.encoded(source_map);(root/'source-map.json').write_bytes(map_raw)
            files={name:dict(**r.pin(raw),mode=0o644,blob=r.hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()) for name,raw in [('MODELED.txt',body),('source-map.json',map_raw)]}
            native_source=Path('/MODELED/NATIVE/Source')
            git=['/usr/bin/git','--no-replace-objects','--git-dir='+str(native_source/'.git'),'--work-tree='+str(native_source),'-c','protocol.allow=never','-c','core.fsmonitor=false']
            outputs=[(b['source']+'\n').encode(),b''.join(('100644 blob '+row['blob']+'\t'+name).encode()+b'\0' for name,row in files.items())]
            data={};actors=[]
            for index,(argv,out) in enumerate(zip([git+['rev-parse','--verify','HEAD'],git+['ls-tree','-rz','--full-tree',b['source']]],outputs)):
                prefix='proof/operations/'+str(index).zfill(3);data[prefix+'.stdout']=out;data[prefix+'.stderr']=b''
                actors.append(dict(argv=argv,stdout=prefix+'.stdout',stderr=prefix+'.stderr',stdout_pin=r.pin(out),stderr_pin=r.pin(b''),lifecycle=natural(),returncode=0))
            value=dict(schema=1,status='PASS_EXACT_HOSTED_SOURCE_READBACK',binding={k:v for k,v in b.items() if k!='job'},files=files,actors=actors,
                       storage_before_inputs=daemon_fixture()['storage']['work_filesystems'][0])
            data['source-readback.json']=r.encoded(value);data['daemon.json']=r.encoded(daemon_fixture())
            def header():return dict(source_readback_sha256=r.pin(data['source-readback.json'])['sha256'],daemon_identity_sha256=r.pin(data['daemon.json'])['sha256'])
            r.provenance_data(data.__getitem__,root,header(),b,source_map)
            for change in (lambda v:v['actors'][0]['lifecycle'].update(forced_cleanup=True),
                           lambda v:v['actors'][0]['argv'].__setitem__(2,'--git-dir=/MODELED/OTHER/.git'),
                           lambda v:v['actors'][1]['argv'].__setitem__(3,'--work-tree=/MODELED/OTHER'),
                           lambda v:v['storage_before_inputs'].update(path='/MODELED/OTHER-temp'),
                           lambda v:v['storage_before_inputs'].update(path=str(native_source/'inside')),
                           lambda v:v['storage_before_inputs'].update(available_bytes=1)):
                changed=copy.deepcopy(value);change(changed);data['source-readback.json']=r.encoded(changed)
                with self.subTest(change=change),self.assertRaises(ValueError):r.provenance_data(data.__getitem__,root,header(),b,source_map)

    def test_null_binding_refuses_before_source_or_artifact_reads(self):
        b=binding();b['approval']=None
        with patch.object(r,'read',side_effect=AssertionError('must refuse before any reads')):
            with self.assertRaises(ValueError):r.source_data(Path('/MODELED/absent'),b)

    def test_whole_source_proof_is_closed_and_preserves_held_subtrees(self):
        # Explicitly patched pins identify an inert miniature Source model only.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);files={'original/held.txt':b'MODELED original DATA\n','perl/held.txt':b'MODELED component DATA\n','hosted/entry.py':b'# MODELED inert source\n'}
            descriptor=lambda body:dict(**r.pin(body),mode=0o644)
            for prefix,map_name in [('original','native/source-map.json'),('perl','source-map.json')]:
                raw=r.encoded({'schema':1,'files':{'held.txt':descriptor(files[prefix+'/held.txt'])}});files[prefix+'/'+map_name]=raw
            for name,raw in files.items():
                leaf=root/name;leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(raw);leaf.chmod(0o644)
            raw=r.encoded({'schema':1,'actual':r.ACTUAL,'files':{name:descriptor(body) for name,body in files.items()}});(root/'source-map.json').write_bytes(raw)
            b=binding();b.update(source_map_sha256=r.pin(raw)['sha256'],component_map_sha256=r.pin(files['perl/source-map.json'])['sha256'])
            with patch.object(r,'ORIGINAL_MAP',r.pin(files['original/native/source-map.json'])['sha256']),patch.object(r,'COMPONENT_MAP',b['component_map_sha256']):
                r.source_data(root,b)
                changed=r.decode(raw);changed['actual']=dict(r.ACTUAL,authority='MODELED_FAKE_AUTHORITY');bad=r.encoded(changed)
                (root/'source-map.json').write_bytes(bad);b['source_map_sha256']=r.pin(bad)['sha256']
                with self.assertRaisesRegex(ValueError,'selectors remain NULL'):r.source_data(root,b)
                (root/'source-map.json').write_bytes(raw);b['source_map_sha256']=r.pin(raw)['sha256']
                (root/'unexpected').mkdir()
                with self.assertRaisesRegex(ValueError,'directory membership'):r.source_data(root,b)
                (root/'unexpected').rmdir();(root/'original/held.txt').write_bytes(b'CHANGED')
                with self.assertRaises(ValueError):r.source_data(root,b)

    def test_hosted_composition_checks_bootstrap_before_delegating_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();b,h,data,ops,refresh=fixture(source)
            data['source-readback.json']=r.encoded({'MODELED':'readback'})
            h['source_readback_sha256']=r.pin(data['source-readback.json'])['sha256'];h['daemon_identity_sha256']=r.pin(data['daemon.json'])['sha256']
            a=dict(source={'sha':b['source'],'ref':b['ref'].removeprefix('refs/heads/')},**{key:b[key] for key in ('operation','run','job','approval')},source_map_sha256=b['component_map_sha256'],image=h['bootstrap']['image'],input_signature_audit_sha256=h['bootstrap']['signatures_sha256'])
            q=dict(source_readback_sha256=h['source_readback_sha256'],native_daemon_identity_sha256=h['daemon_identity_sha256'],input_signature_audit_sha256=h['bootstrap']['signatures_sha256'])
            data.update({'hosted.json':r.encoded(h),'adapter-admission.json':r.encoded(a),'adapter-qualification.json':r.encoded(q)})
            evidence=root/'evidence';evidence.mkdir()
            for name,raw in data.items():
                leaf=evidence/name;leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(raw)
            # Composition model: actual whole-Source parser tested separately;
            # immutable Perl Reader is never imported as an operational role.
            with patch.object(r.sys,'version_info',(3,14,6)),patch.object(r,'source_data',return_value={'MODELED':'source'}),patch.object(r,'provenance_data'),patch.object(r,'pair_data',return_value=({'status':'PASS_NATIVE_PAIR_DATA','native_acceptance':False},{'MODELED':'transport'})) as pair:
                result=r.validate(evidence,source,b);self.assertEqual(result['status'],'PASS_HOSTED_PERL_PAIR_DATA');self.assertFalse(result['native_acceptance']);self.assertEqual(pair.call_count,1)
                pair.reset_mock();(evidence/'bootstrap/packages.lock').write_bytes(b'MODELED wrong inventory\n')
                with self.assertRaises(ValueError):r.validate(evidence,source,b)
                pair.assert_not_called()

    def test_read_only_pair_transport_routes_both_roots_and_restores_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();evidence=root/'evidence';physical=evidence/'pair';physical.mkdir(parents=True)
            logical=Path('/MODELED/NATIVE/pair');(physical/'report.json').write_bytes(r.encoded({'inputs':str(logical/'inputs')}));(physical/'DATA').write_bytes(b'MODELED artifact')
            calls=[];expected={'MODELED':'namespace'}
            def bounded(root,name,cap,**kwargs):
                calls.append(('read',root,name,cap,kwargs))
                if root==source/'perl':return b'MODELED helper'
                return r.read(root,name,cap)
            def namespace(root,name,expected_rows):calls.append(('namespace',root,name,expected_rows))
            def delegate(root,c,a,q):
                self.assertEqual(root,logical);self.assertEqual(reader.read(root,'DATA',64,empty=False),b'MODELED artifact')
                self.assertEqual(reader.read(source/'perl','helpers/MODELED',32),b'MODELED helper')
                reader.export_namespace(root,'build-1',expected)
                if c=='FAIL':raise RuntimeError('MODELED held refusal')
                return {'status':'PASS_NATIVE_PAIR_DATA','native_acceptance':False}
            reader=SimpleNamespace(read=bounded,export_namespace=namespace,validate_pair=delegate)
            result,view=r.relocated_pair(reader,evidence,source,'PASS',{},{});self.assertEqual(result['status'],'PASS_NATIVE_PAIR_DATA')
            self.assertEqual(view['logical_pair_root'],str(logical));self.assertEqual(view['physical_pair_root'],str(physical));self.assertFalse(view['artifact_bytes_changed']);self.assertFalse(view['held_decision_checks_changed'])
            self.assertEqual(calls[0],('read',physical,'DATA',64,{'empty':False}));self.assertEqual(calls[1][1],source/'perl');self.assertEqual(calls[2],('namespace',physical,'build-1',expected))
            self.assertIs(reader.read,bounded);self.assertIs(reader.export_namespace,namespace)
            with self.assertRaisesRegex(RuntimeError,'held refusal'):r.relocated_pair(reader,evidence,source,'FAIL',{}, {})
            self.assertIs(reader.read,bounded);self.assertIs(reader.export_namespace,namespace)
            native_logical=logical;logical=physical;(physical/'report.json').write_bytes(r.encoded({'inputs':str(physical/'inputs')}))
            result,view=r.relocated_pair(reader,evidence,source,'PASS',{},{});self.assertEqual(view['logical_pair_root'],view['physical_pair_root']);logical=native_logical
            for inputs in ('/MODELED/../pair/inputs','/MODELED/pair/other',str(source/'inputs'),str(evidence/'inputs')):
                (physical/'report.json').write_bytes(r.encoded({'inputs':inputs}))
                with self.subTest(inputs=inputs),self.assertRaises(ValueError):r.relocated_pair(reader,evidence,source,'PASS',{}, {})

    def test_stable_data_reads_and_ambiguous_json_refuse(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}'):
            with self.assertRaises(ValueError):r.decode(raw)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'leaf').write_bytes(b'MODELED');self.assertEqual(r.read(root,'leaf'),b'MODELED');(root/'alias').symlink_to(root/'leaf')
            with self.assertRaises((ValueError,OSError)):r.read(root,'alias')
            with self.assertRaises(ValueError):r.read(root,'../escape')


if __name__=='__main__':unittest.main(verbosity=2)
