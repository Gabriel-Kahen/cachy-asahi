# SPDX-License-Identifier: MIT
"""Synthetic bytes/mocks only; never invoke the Reader CLI or a native role."""
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fenced_current_reader',HERE/'reader.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('Reader DATA controls forbid '+event)
sys.addaudithook(fence)


def fixture():
    body=b'FENCED_PAYLOAD\n';packages={'base':'1-1','python':'3.14-1'}
    recipe=dict(name='cachy-asahi-first-login',version='0.1.0-3',depends=['python>=3.11'],makedepends=[],checkdepends=[],optdepends=[],
                files={'PKGBUILD':R.pin(b'FENCED_RECIPE')},payload_files={'usr/bin/fenced':dict(mode=0o755,**R.pin(body))})
    pkg='pkgname = '+recipe['name']+'\npkgbase = '+recipe['name']+'\npkgver = '+recipe['version']+'\narch = any\nlicense = MIT\ndepend = python>=3.11\nbuilddate = 17\n'
    build='format = 2\npkgname = '+recipe['name']+'\npkgbase = '+recipe['name']+'\npkgver = '+recipe['version']+'\npkgarch = any\npkgbuild_sha256sum = '+recipe['files']['PKGBUILD']['sha256']+'\nbuildenv = check\nbuilddate = 17\n'
    build+=''.join('installed = '+name+'-'+version+'-aarch64\n' for name,version in sorted(packages.items()))
    return recipe,packages,{'.PKGINFO':pkg.encode(),'.BUILDINFO':build.encode(),'.MTREE':b'FENCED_MTREE','usr/bin/fenced':body}


def archive(bodies):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as tf:
        for name in ('usr','usr/bin'):
            item=tarfile.TarInfo(name);item.type=tarfile.DIRTYPE;item.mode=0o755;tf.addfile(item)
        for name,body in bodies.items():
            item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o755 if name=='usr/bin/fenced' else 0o644
            tf.addfile(item,io.BytesIO(body))
    return out.getvalue()


class Controls(unittest.TestCase):
    def test_unissued_template_refuses_before_data_or_source_access(self):
        binding=json.loads((HERE/'binding.TEMPLATE.json').read_bytes())
        with patch.object(R.Reads,'read',side_effect=AssertionError('no evidence read')),self.assertRaisesRegex(ValueError,'unissued'):
            R.check('/FENCED/output','/FENCED/source','/FENCED/profile','/FENCED/inputs','/FENCED/admission',binding)
        self.assertTrue(all(v is None for k,v in binding.items() if k!='operation'))

    def test_exact_current_check_counts_and_enrollment_report(self):
        p={'packages':{'first-login':{'check_counts':[14,6]},'ui':{'check_counts':[38,6]}},'enrollment_check_report':{'status':'FENCED_COMPLETE','payload_files':16}}
        for kind in R.KINDS:
            log=b'Starting check()\n'
            log+=json.dumps(p['enrollment_check_report']).encode()+b'\n' if kind=='enrollment' else b''.join(('Ran '+str(n)+' tests in 0.1s\nOK\n').encode() for n in p['packages'][kind]['check_counts'])
            R.check_log(log,kind,p)
            for extra in (b'FAILED\n',b'OK (skipped=1)\n',b'expected failures=1\n',log):
                with self.subTest(kind=kind,extra=extra),self.assertRaises(ValueError):R.check_log(log+extra,kind,p)

    def test_strict_test_signature_no_unknown_expired_or_subkey_substitution(self):
        signer='A'*40
        good=('[GNUPG:] VALIDSIG '+signer+' 2026-11-16 1 0 4 0 1 10 00 '+signer+'\n[GNUPG:] TRUST_ULTIMATE\n').encode()
        R.strict_signature(good,signer)
        for bad in (good+b'[GNUPG:] BADSIG A\n',good+b'[GNUPG:] KEYEXPIRED 1\n',good.replace(b'TRUST_ULTIMATE',b'TRUST_UNDEFINED'),good+good,good.replace(signer.encode(),b'B'*40)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):R.strict_signature(bad,signer)

    def test_complete_inert_package_payload_metadata_inventory_epoch(self):
        recipe,packages,bodies=fixture();raw=archive(bodies)
        result=R.archive_tar(raw,recipe,packages,17)
        self.assertEqual(result['payload'],recipe['payload_files'])
        self.assertEqual(R.package(lzma.compress(raw,preset=0),recipe,packages,17),result)
        try:from compression import zstd
        except ImportError:
            with self.assertRaisesRegex(ValueError,'Python3.14'):R.package(b'\x28\xb5\x2f\xfd',recipe,packages,17)
        else:self.assertEqual(R.package(zstd.compress(raw,level=1),recipe,packages,17),result)

    def test_package_drift_extra_missing_checks_and_dependencies_refuse(self):
        recipe,packages,bodies=fixture()
        for kind in ('payload','extra','missing','nocheck','dependency','inventory','epoch'):
            current=dict(bodies)
            if kind=='payload':current['usr/bin/fenced']=b'CHANGED'
            elif kind=='extra':current['.INSTALL']=b'NEVER_EXECUTE'
            elif kind=='missing':current.pop('.MTREE')
            elif kind=='nocheck':current['.BUILDINFO']=current['.BUILDINFO'].replace(b'buildenv = check',b'buildenv = !check')
            elif kind=='dependency':current['.PKGINFO']=current['.PKGINFO'].replace(b'python>=3.11',b'python')
            elif kind=='inventory':current['.BUILDINFO']=current['.BUILDINFO'].replace(b'base-1-1-aarch64',b'base-2-1-aarch64')
            else:current['.PKGINFO']=current['.PKGINFO'].replace(b'builddate = 17',b'builddate = 18')
            with self.subTest(kind=kind),self.assertRaises(ValueError):R.archive_tar(archive(current),recipe,packages,17)

    def test_inventory_literal_complete_and_duplicate_refusal(self):
        self.assertEqual(R.inventory(b'base 1-1\npython 3.14-1\n'),{'base':'1-1','python':'3.14-1'})
        for raw in (b'base 1-1',b'base 1-1\nbase 1-1\n',b'base  1-1\n',b'../bad 1-1\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):R.inventory(raw)

    def test_natural_commands_and_raw_log_pins(self):
        with tempfile.TemporaryDirectory(prefix='fenced-reader-') as t:
            root=Path(t);(root/'commands').mkdir();raw=b'FENCED_STDOUT\n';(root/'commands/000-current-enrollment-a.log').write_bytes(raw)
            supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,timeout=False,signals=[],error=None,exit=0,seconds=0.1)
            row=dict(step='current-enrollment-a',argv=['/usr/bin/NEVER_EXECUTED'],cwd=str(root),expected=0,success=True,log='000-current-enrollment-a.log',log_pin=R.pin(raw),supervision=supervision,channels='stdout+stderr combined in pipe order')
            cap=dict(command_rows=512,build_seconds=180,total_seconds=1800)
            self.assertEqual(list(R.command_index([row],root,R.Reads(),cap)),[row['step']])
            for change in ({'timeout':True},{'signals':[15]},{'ownership':'UNKNOWN'},{'exit':1},{'emergency_retirement':True}):
                bad=copy.deepcopy(row);bad['supervision'].update(change)
                with self.subTest(change=change),self.assertRaises(ValueError):R.command_index([bad],root,R.Reads(),cap)
            (root/'commands'/row['log']).write_bytes(b'CHANGED')
            with self.assertRaises(ValueError):R.command_index([row],root,R.Reads(),cap)

    def test_closed_v3_source_data_membership_and_extra_empty_directory(self):
        with tempfile.TemporaryDirectory(prefix='fenced-source-') as t:
            root=Path(t);files={}
            for i in range(58):
                p=root/('leaf'+str(i));p.write_bytes(b'FENCED_SOURCE_DATA');p.chmod(0o644);files[p.name]=dict(mode=0o644,**R.pin(p.read_bytes()))
            lock=dict(schema=1,kind='CURRENT_ONBOARDING_CLOSED_SOURCE_V3',operation=R.OP,files=files,actual=dict.fromkeys(('source','ref','run','job','artifact','Root_trust','Root_resources','Root_runtime','Root_signing','actual_images','dispatch_grant','publication')))
            (root/'source.lock.json').write_bytes(R.encoded(lock));(root/'source-map.json').write_bytes(R.encoded(lock))
            _,rows=R.source_tree(root,R.Reads());self.assertEqual(len(rows),58)
            (root/'EMPTY').mkdir()
            with self.assertRaises(ValueError):R.source_tree(root,R.Reads())

    def test_refs_refuse_aliases_drift_and_unknown_json_fields(self):
        with tempfile.TemporaryDirectory(prefix='fenced-ref-') as t:
            p=Path(t)/'data';p.write_bytes(b'FENCED');row=dict(path=str(p),**R.pin(b'FENCED'))
            self.assertEqual(R.Reads().reference(row),b'FENCED');p.write_bytes(b'CHANGE')
            with self.assertRaises(ValueError):R.Reads().reference(row)
            with self.assertRaises(ValueError):R.decode(b'{"a":1,"a":2}')
            with self.assertRaises(ValueError):R.decode(b'{"a":NaN}')

    def test_lifecycle_complete_observations_and_temporal_refusals(self):
        # Synthetic command DATA only. Archive contents have separate parser
        # controls above; this isolates the installed-observation protocol.
        output=Path('/FENCED/output');base={'base%03d'%i:'1-1' for i in range(372)}
        signer='A'*40;data={};commands={};life=dict(status='PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY',Root_acceptance=None,native16K='NOT_RUN',GUI='NOT_RUN',M2='NOT_RUN',inventories={},payloads={})
        def keep(path,raw):
            data[str(path)]=raw;return dict(path=str(path),**R.pin(raw))
        p={'packages':{}};signed={}
        for key in ('setup8',*R.KINDS):
            name,version=('cachy-asahi-setup','0.3.0-1') if key=='setup8' else R.VERSIONS[key]
            payload={'usr/bin/'+name:dict(mode=0o755,**R.pin(key.encode()))}
            recipe=dict(name=name,version=version,payload_files=payload)
            if key=='setup8':p['setup8']=recipe
            else:p['packages'][key]=recipe
            a=keep(output/'signed'/(key+'.archive'),key.encode());s=keep(output/'signed'/(key+'.signature'),b'FENCED_SIG')
            signed[key]=dict(name=name,version=version,payload_files=payload,archive='/actor/'+key,signature='/actor/'+key+'.sig',archive_pin=R.pin(data[a['path']]),signature_pin=R.pin(b'FENCED_SIG'))
        p['setup8']['archive_pin']=signed['setup8']['archive_pin']
        inputs={'source_date_epoch':17,'setup8':dict(archive=keep('/inputs/setup8',b'setup8'),signature=keep('/inputs/setup8.sig',b'FENCED_SIG'),current_TEST_signature_verification=keep('/inputs/proof',R.encoded({'fingerprint':signer})))}
        for key,size in (('builder_inventory',350),('ui_builder_inventory',374)):
            rows={'builder%03d'%i:'1-1' for i in range(size)};inputs[key]=dict(packages=rows,**keep('/inputs/'+key,R.inventory_bytes(rows)))
        config='/tmp/build-tools-test-FENCED/pacman.conf';trust='/tmp/build-tools-test-FENCED/trust';pacman=['/usr/bin/pacman','--config',config]
        config_raw=('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+trust+'\nHookDir = /builder-disabled-hooks\nLogFile = /tmp/build-tools-test-FENCED/pacman.log\n').encode()
        keep(output/'signature-config.txt',config_raw)
        def emit(step,argv,raw=b''):
            commands[step]=(len(commands),dict(argv=argv),raw)
        def inv(step,versions):
            raw=R.inventory_bytes(base|versions);emit(step,['/usr/bin/pacman','-Q'],raw);life['inventories'][step]=R.pin(raw)
        def payload(key,label):
            row=signed[key];name=next(iter(row['payload_files']));leaf=row['payload_files'][name]
            emit(label+'-file-list',pacman+['-Qlq',row['name']],('/'+name+'\n').encode())
            emit(label+'-owner-0',pacman+['-Qqo','/'+name],(row['name']+'\n').encode())
            emit(label+'-stat-0',['/usr/bin/stat','-c','%u:%g:%a:%s:%h:%F','--','/'+name],('0:0:755:%d:1:regular file\n'%leaf['bytes']).encode())
            emit(label+'-sha256-0',['/usr/bin/sha256sum','--','/'+name],(leaf['sha256']+'  /'+name+'\n').encode())
        def absent(label,keys):
            for i,name in enumerate(sorted(n for k in keys for n in signed[k]['payload_files'])):
                for flag in ('-e','-L'):emit(label+'-'+str(i)+flag,['/usr/bin/test','!',flag,'/'+name])
        emit('current-baseline',['/usr/bin/pacman','-Q'],R.inventory_bytes(base))
        for key,row in signed.items():
            status=('[GNUPG:] VALIDSIG '+signer+' 2026-11-16 1 0 4 0 1 10 00 '+signer+'\n[GNUPG:] TRUST_ULTIMATE\n').encode()
            emit('current-signature-'+key,['/usr/bin/gpg','--homedir',trust,'--batch','--no-auto-key-retrieve','--auto-key-locate','clear','--status-fd=1','--verify',row['signature'],row['archive']],status)
            emit('current-pkginfo-'+key,['/usr/bin/bsdtar','-xOf',row['archive'],'.PKGINFO'],('pkgname = '+row['name']+'\npkgver = '+row['version']+'\narch = any\n').encode())
        added={'cachy-asahi-setup':'0.3.0-1'}
        emit('current-install-setup8',pacman+['--noconfirm','--asdeps','-U',signed['setup8']['archive']]);inv('current-dependency-inventory',added);payload('setup8','current-setup8')
        life['payloads']['setup8']=dict(verified=True,files=p['setup8']['payload_files'])
        for cycle in ('install','reinstall'):
            emit('current-'+cycle,pacman+['--noconfirm','-U',*[signed[k]['archive'] for k in R.KINDS]]);inv('current-'+cycle+'-inventory',added|dict(R.VERSIONS.values()))
            for key in R.KINDS:payload(key,'current-'+cycle+'-'+key)
            life['payloads'][cycle]={k:dict(verified=True,files=p['packages'][k]['payload_files']) for k in R.KINDS}
            for key in R.KINDS:emit('current-'+cycle+'-help-'+key,['/usr/bin/runuser','-u','alarm','--','/usr/bin/'+R.VERSIONS[key][0],'--help'])
            emit('current-remove-'+cycle,pacman+['--noconfirm','-R',*[R.VERSIONS[k][0] for k in reversed(R.KINDS)]]);inv('current-after-remove-'+cycle,added);absent('current-absent-'+cycle,R.KINDS)
        emit('current-remove-setup8',pacman+['--noconfirm','-R','cachy-asahi-setup']);inv('current-final-inventory',{});absent('current-absent-setup8',('setup8',))
        report=dict(owner_facts={'execution_domain':'OWNED_SIGNED_IMAGE_LOCAL'},protected_before={k:dict(files=1,**R.pin(b'FENCED_TREE')) for k in ('alpm_db','alarm_home','root_home','global_trust','global_config','package_cache')},protected_after={k:dict(files=1,**R.pin(b'FENCED_TREE')) for k in ('alpm_db','alarm_home','root_home','global_trust','global_config','package_cache')},lifecycle=life,signed=signed,signature_config_pin=R.pin(config_raw))
        reads=R.Reads();reads.read=lambda path,*_:data[str(path)];reads.reference=lambda row,*_:data[row['path']]
        with patch.object(R,'package',return_value={}):
            self.assertEqual(R.lifecycle(output,p,inputs,{'signed':signed,'owner':{'test_fingerprint':signer}},report,commands,reads,base)['signed_inputs'],4)
            bad_report=copy.deepcopy(report);del bad_report['protected_before']['root_home'];del bad_report['protected_after']['root_home']
            with self.assertRaises(ValueError):R.lifecycle(output,p,inputs,{'signed':signed,'owner':{'test_fingerprint':signer}},bad_report,commands,reads,base)
            for step in ('current-install-enrollment-stat-0','current-absent-install-0-e','current-reinstall-help-ui'):
                bad=copy.deepcopy(commands);_,row,raw=bad[step];bad[step]=(0,row,raw)
                with self.subTest(step=step),self.assertRaises(ValueError):R.lifecycle(output,p,inputs,{'signed':signed,'owner':{'test_fingerprint':signer}},report,bad,reads,base)

    def test_v3_program_binds_committed_data_closure_modes_registry_and_typed_locks(self):
        with tempfile.TemporaryDirectory(prefix='fenced-program-') as directory:
            source=Path(directory);repo=HERE.parents[2];files={}
            for name,row in R.CODE.items():
                body=(repo/name).read_bytes();self.assertEqual(R.pin(body),{k:row[k] for k in ('bytes','sha256')})
                target=source/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body);target.chmod(row['mode']);files[name]=body
            program=dict(schema=1,kind='CURRENT_ONBOARDING_COMMITTED_OWNER_PROGRAM_V3',operation=R.OP,api=R.API,entrypoint='open_current_session',
                closure=R.CODE,closure_commit='a'*40,actual=dict.fromkeys(('Root_trust','Root_resources','Root_runtime','Root_signing','actual_images','dispatch_grant','publication')),
                owner=dict(path=R.OWNER,**R.pin(files[R.OWNER])),route=dict(path=R.ROUTE,**R.pin(files[R.ROUTE])),expected_inventories={})
            dispatch=R.PREFIX+'/dispatch.py';files[dispatch]=b'FENCED DATA NEVER IMPORTED';program['registry']=dict(path=dispatch,**R.pin(files[dispatch]))
            closure=dict(schema=1,kind='CURRENT_ONBOARDING_COMMITTED_OWNER_ROUTE_CLOSURE_V3',api=R.API,operation=R.OP,
                owner=R.OWNER,route=R.ROUTE,files=R.CODE,commit=program['closure_commit'])
            registry=dict(schema=3,actual_Root_admission=None,operations={R.OP:dict(api=R.API,owner=program['owner'],route=program['route'],entry=program['registry'])})
            for stage,count in R.COUNTS.items():
                body=R.inventory_bytes({'fiction%03d'%i:'1-1' for i in range(count)});files['inputs/stages/'+stage+'.expected.lock']=body
                program['expected_inventories'][stage]=dict(packages=count,**R.pin(body))
            inventory=source/'backend.lock';inventory.write_bytes(files['inputs/stages/backend.expected.lock'])
            files[R.PREFIX+'/owner-program.json']=R.encoded(program);files['provenance/owner-closure.json']=R.encoded(closure);files[R.PREFIX+'/operation-registry.json']=R.encoded(registry)
            ad=dict(stage='backend',owner=dict(api=R.API,code=dict(path=str(source/R.OWNER),**R.pin(files[R.OWNER]))),images={'backend':dict(inventory_pin=dict(path=str(inventory),**R.pin(inventory.read_bytes())))})
            self.assertEqual(R.source_program(source,files,ad,R.Reads())['code_files'],8)
            bad=dict(files);bad[R.OWNER]+=b'CHANGED'
            with self.assertRaises(ValueError):R.source_program(source,bad,ad,R.Reads())
            (source/R.OWNER).chmod(0o755)
            with self.assertRaises(ValueError):R.source_program(source,files,ad,R.Reads())
            (source/R.OWNER).chmod(0o644)
            invalid=copy.deepcopy(registry);invalid['operations'][R.OP]['route']['sha256']='0'*64
            bad=dict(files);bad[R.PREFIX+'/operation-registry.json']=R.encoded(invalid)
            with self.assertRaises(ValueError):R.source_program(source,bad,ad,R.Reads())

    def test_lifecycle_pairs_require_completed_build_bindings_and_exact_signed_archives(self):
        source=Path('/FENCED/source');actual={'source':'FENCED-SAME-SOURCE'}
        signed={kind:dict(archive_pin=R.pin(kind.encode())) for kind in R.KINDS}
        previous={stage:dict(stage=stage,operation=R.OP,output='/FENCED/'+stage,
            profile={'path':'/FENCED/profile'},inputs={'path':'/FENCED/'+stage+'-inputs'},admission={'path':'/FENCED/'+stage+'-grant'}) for stage in ('backend','ui')}
        data={stage:R.encoded(row) for stage,row in previous.items()}
        binding={'build_stage_bindings':{stage:{'path':stage} for stage in previous}}
        reads=R.Reads();reads.reference=lambda row,*_:data[row['path']]
        def prior(output,*args,**kwargs):
            self.assertTrue(kwargs['_dependency']);self.assertIs(kwargs['_reads'],reads)
            stage=output.name;kinds=('ui',) if stage=='ui' else ('enrollment','first-login')
            return dict(binding=actual,verified={k:{'archive':signed[k]['archive_pin']} for k in kinds})
        report=dict(binding=actual,signed=signed)
        with patch.object(R,'check',side_effect=prior):
            self.assertEqual(R.prior_pairs(source,binding,report,reads,('FENCED',{})),{k:signed[k]['archive_pin'] for k in R.KINDS})
        with patch.object(R,'check',side_effect=lambda *a,**k:dict(binding={'source':'OTHER'},verified={})),self.assertRaises(ValueError):
            R.prior_pairs(source,binding,report,reads,('FENCED',{}))
        invalid=copy.deepcopy(previous['backend']);invalid['stage']='lifecycle';data['backend']=R.encoded(invalid)
        with patch.object(R,'check',side_effect=AssertionError('recursive lifecycle read')),self.assertRaises(ValueError):
            R.prior_pairs(source,binding,report,reads,('FENCED',{}))
        with self.assertRaises(ValueError):R.prior_pairs(source,{'build_stage_bindings':None},report,reads,('FENCED',{}))

    def test_operational_primitives_remain_fenced(self):
        for event in ('subprocess.Popen','socket.__new__','ctypes.dlopen','fcntl.flock','os.exec'):
            with self.assertRaises(RuntimeError):fence(event,())


if __name__=='__main__':unittest.main(verbosity=2)
