#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic 587-name capacity fixtures; never the real 587-package composition."""
import argparse
import ctypes as C
import json
import functools
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from test_snapshot import module, encoded, digest, make_bundle, make_envelope

legacy = module('legacy_tiny_transaction_tests',Path(__file__).with_name('test_bound_update.py'))
scale = module('scale_under_test',Path(__file__).with_name('scale_update.py'))


# Fixed status tags only; signature identities/UIDs/arguments are never retained.
SIGNATURE_STATUS = {'NEWSIG','KEY_CONSIDERED','SIG_ID','GOODSIG','VALIDSIG','BADSIG','ERRSIG','NO_PUBKEY',
    'EXPSIG','EXPKEYSIG','REVKEYSIG','TRUST_UNDEFINED','TRUST_NEVER','TRUST_MARGINAL','TRUST_FULLY',
    'TRUST_ULTIMATE','NODATA','FAILURE','ERROR','UNEXPECTED','KEYEXPIRED','SIGEXPIRED','KEYREVOKED'}


# Public read-only GPGME 2.2.0 engine-info ABI; see retained headers in proposal.
class GpgmeEngineInfo(C.Structure):
    pass
GpgmeEngineInfo._fields_=[('next',C.POINTER(GpgmeEngineInfo)),('protocol',C.c_int),
    ('file_name',C.c_char_p),('version',C.c_char_p),('req_version',C.c_char_p),('home_dir',C.c_char_p)]


def pre_load_handle(alpm,gpgdir):
    """Capture before load: libalpm option getters clear handle errno."""
    value=dict(handle_getter_available=False,handle_home_matches='UNKNOWN')
    try:
        home=alpm.lib.alpm_option_get_gpgdir
        home.restype=C.c_char_p;home.argtypes=[C.c_void_p]
        value['handle_getter_available']=True
        actual=home(alpm.handle)
        value['handle_home_matches']=actual is not None and actual.rstrip(b'/') == os.fsencode(gpgdir).rstrip(b'/')
    except Exception:pass
    return value


def post_load_engine(alpm,configuration,gpgdir):
    """Read global configuration after refusal; never touch ALPM handle errno."""
    value=dict(configuration,state='UNAVAILABLE',engine_getter_available=False,
        engine_home_matches='UNKNOWN',engine_home_default='UNKNOWN',engine_binary_matches='UNKNOWN')
    try:
        engines=alpm.lib.gpgme_get_engine_info
        engines.restype=C.c_uint;engines.argtypes=[C.POINTER(C.POINTER(GpgmeEngineInfo))]
        value['engine_getter_available']=True
        info=C.POINTER(GpgmeEngineInfo)()
        if engines(C.byref(info)) != 0:
            value['state']='API_ERROR';return value
        seen=set();openpgp=[]
        while info:
            address=C.cast(info,C.c_void_p).value
            if address in seen or len(seen)>=16:
                value['state']='ENGINE_LIST_BOUND';return value
            seen.add(address);entry=info.contents
            if entry.protocol == 0:  # GPGME_PROTOCOL_OpenPGP, public enum.
                openpgp.append((entry.home_dir,entry.file_name))
            info=entry.next
        if len(openpgp) != 1:
            value['state']='NO_UNIQUE_OPENPGP_ENGINE';return value
        engine_home,binary=openpgp[0]
        value.update(state='OBSERVED',engine_home_default=engine_home is None,
            engine_home_matches=engine_home is not None and engine_home.rstrip(b'/') == os.fsencode(gpgdir).rstrip(b'/'),
            engine_binary_matches=binary == b'/usr/bin/gpg')
    except Exception:value['state']='DIAGNOSTIC_ERROR'
    return value


ORIGINAL_VERIFY_LIMITS=(19,13,19,19,8,19,8,4)
ORIGINAL_VERIFY_C = r'''/* TEST-only callback bridge: public alpm.h owns the va_list ABI. */
#include <alpm.h>
#include <errno.h>
#include <gpgme.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

static int active;
static uint64_t values[10];
static const char *const summaries[]={"valid","green","red","key revoked","key expired",
    "sig expired","key missing","crl missing","crl too old","bad policy","sys error","(empty)"};
static const char *const validity[]={"unknown","undefined","never","marginal","full","ultimate","???"};
static const int errors[]={GPG_ERR_NO_ERROR,GPG_ERR_GENERAL,GPG_ERR_BAD_SIGNATURE,GPG_ERR_NO_PUBKEY,
    GPG_ERR_BAD_DATA,GPG_ERR_NO_DATA,GPG_ERR_INV_VALUE,GPG_ERR_INV_ENGINE,GPG_ERR_NO_AGENT,
    GPG_ERR_NOT_SUPPORTED,GPG_ERR_UNSUPPORTED_PROTOCOL,GPG_ERR_KEY_EXPIRED,GPG_ERR_SIG_EXPIRED,
    GPG_ERR_EOF,GPG_ERR_ENOENT,GPG_ERR_EACCES,GPG_ERR_EIO,GPG_ERR_ENOMEM};

static unsigned token(const char *value,const char *const *allowed,unsigned count)
{
    for(unsigned i=0;value && i<count;i++) if(strcmp(value,allowed[i])==0) return i;
    return count;
}
static unsigned error_class(const char *value)
{
    for(unsigned i=0;value && i<sizeof(errors)/sizeof(errors[0]);i++)
        if(strcmp(value,gpgme_strerror(errors[i]))==0) return i;
    return sizeof(errors)/sizeof(errors[0]);
}
static void record(const char *fmt,va_list args)
{
    static const char *const events[]={
        "Signature verification will fail!\n","no signatures returned\n","key lookup failed, unknown key\n",
        "signature timestamp is greater than system time.\n","missing optional signature\n",
        "missing required signature\n","signature check failed\n","signature is valid\n",
        "signature is fully trusted\n","signature is marginal trust\n","signature is unknown trust\n",
        "signature should never be trusted\n","signature is not valid\n",
        "required key missing from keyring\n"};
    unsigned found=token(fmt,events,sizeof(events)/sizeof(events[0]));
    if(found<sizeof(events)/sizeof(events[0])) {values[0]|=UINT64_C(1)<<found;return;}
    if(strcmp(fmt,"checking signature for %s\n")==0) {values[0]|=UINT64_C(1)<<14;return;}
    if(strcmp(fmt,"sig path %s could not be opened\n")==0) {values[0]|=UINT64_C(1)<<15;return;}
    if(strcmp(fmt,"Public keyring not found; have you run '%s'?\n")==0) {values[0]|=UINT64_C(1)<<16;return;}
    if(strcmp(fmt,"failed to read signature file: %s\n")==0) {values[0]|=UINT64_C(1)<<17;return;}
    va_list copy;va_copy(copy,args);
    if(strcmp(fmt,"summary: %s\n")==0) {
        values[1]|=UINT64_C(1)<<token(va_arg(copy,const char *),summaries,sizeof(summaries)/sizeof(summaries[0]));
    } else if(strcmp(fmt,"status: %s\n")==0) {
        values[2]|=UINT64_C(1)<<error_class(va_arg(copy,const char *));
    } else if(strcmp(fmt,"GPGME error: %s\n")==0) {
        values[3]|=UINT64_C(1)<<error_class(va_arg(copy,const char *));
    } else if(strcmp(fmt,"validity: %s; reason: %s\n")==0) {
        values[4]|=UINT64_C(1)<<token(va_arg(copy,const char *),validity,sizeof(validity)/sizeof(validity[0]));
        values[5]|=UINT64_C(1)<<error_class(va_arg(copy,const char *));
    } else if(strcmp(fmt,"key: %s, %s, owner_trust %s, disabled %d\n")==0) {
        (void)va_arg(copy,const char *);(void)va_arg(copy,const char *); /* Never inspect fpr/UID. */
        values[6]|=UINT64_C(1)<<token(va_arg(copy,const char *),validity,sizeof(validity)/sizeof(validity[0]));
        if(va_arg(copy,int)) values[0]|=UINT64_C(1)<<18;
    } else if(strcmp(fmt,"%d signatures returned\n")==0) {
        int count=va_arg(copy,int);values[7]|=UINT64_C(1)<<(count==0?0:count==1?1:count>1?2:3);
    } else if(values[9]<4095) values[9]++;
    va_end(copy);
}
static void capture(void *ctx,alpm_loglevel_t level,const char *fmt,va_list args)
{
    (void)ctx;(void)level;
    if(!active || !fmt) return;
    int saved=errno;
    if(values[8]<4095) values[8]++;
    record(fmt,args);
    errno=saved;
}
int probe_install(alpm_handle_t *handle)
{
    if(alpm_option_get_logcb(handle)!=NULL) return 1;
    return alpm_option_set_logcb(handle,capture,NULL)==0?0:2;
}
void probe_begin(void) {memset(values,0,sizeof(values));active=1;}
void probe_end(void) {active=0;}
uint64_t probe_read(unsigned index) {return index<10?values[index]:0;}
'''


def compile_original_probe(case):
    """TEST-only fixed source; outside copied root/workspace; never fatal to load."""
    try:
        directory=case/'original-verification-bridge';directory.mkdir(mode=0o700)
        output=directory/'probe.so'
        result=subprocess.run(['/usr/bin/cc','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',
            '-std=c11','-x','c','-','-o',str(output),'-lalpm','-lgpgme'],input=ORIGINAL_VERIFY_C.encode(),
            capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TMPDIR':str(directory)})
        return output if result.returncode==0 and len(result.stdout)+len(result.stderr)<=65536 else None
    except Exception:return None


def install_original_probe(path,alpm):
    try:
        if path is None:return None
        bridge=C.CDLL(str(path))
        bridge.probe_install.restype=C.c_int;bridge.probe_install.argtypes=[C.c_void_p]
        bridge.probe_begin.restype=bridge.probe_end.restype=None
        bridge.probe_begin.argtypes=bridge.probe_end.argtypes=[]
        bridge.probe_read.restype=C.c_uint64;bridge.probe_read.argtypes=[C.c_uint]
        return bridge if bridge.probe_install(alpm.handle)==0 else None
    except Exception:return None


def original_probe_result(bridge):
    if bridge is None:return {'state':'UNAVAILABLE'}
    try:
        values=[bridge.probe_read(index) for index in range(10)]
        if any(type(value) is not int or not 0<=value<2**bits for value,bits in zip(values,ORIGINAL_VERIFY_LIMITS)) or any(
                type(value) is not int or not 0<=value<=4095 for value in values[8:]):
            return {'state':'UNAVAILABLE'}
        return dict(state='OBSERVED',bits=values)
    except Exception:return {'state':'UNAVAILABLE'}


class ScaleTransactions(unittest.TestCase):
    setUpClass = classmethod(legacy.ActualTransactions.setUpClass.__func__)
    assert_refused = legacy.ActualTransactions.assert_refused
    run_update = legacy.ActualTransactions.run_update

    def setUp(self):
        legacy.ActualTransactions.setUp(self)
        local=self.root/'var/lib/pacman/local'
        for index in range(580):
            name=f'synthetic-held-{index:03d}'
            self.versions[name]='1-1'
            self.owned[name]=[]
            directory=local/(name+'-1-1'); directory.mkdir()
            (directory/'desc').write_text(f'%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n')
            (directory/'files').write_text('%FILES%\n\n')
        self.base=[dict(name=name,version=version,arch='any',depend=[],provides=[],conflict=[],files=self.owned[name])
                   for name,version in self.versions.items()]
        self.select('gz')
        self.args.measure_only=False
        self.args.scale=str(self.case/'scale.json')
        self.config=dict(schema_version=1,purpose='disposable-bound-update-scale',platform_mode='apple',
            before_lock_sha256=scale.inventory_sha(self.versions),
            after_lock_sha256=scale.inventory_sha(dict(self.versions,fixture='1-1')),
            limits=dict(root_nodes=10000,root_bytes=64*1024**2,file_bytes=8*1024**2,package_files=10000,
                archive_bytes=8*1024**2,archive_total_bytes=16*1024**2,decoded_bytes=32*1024**2,
                archive_members=10000,window_bytes=64*1024**2,seconds=30),
            capacity=dict(root_reserve_bytes=1024**2,root_reserve_inodes=100,
                workspace_future_bytes=1024**2,workspace_future_inodes=100))
        self.configure()

    def configure(self):
        Path(self.args.scale).write_bytes(encoded(self.config))
        self.args.scale_sha256=digest(self.args.scale)

    def select(self,compression):
        shutil.rmtree(self.bundle)
        self.bundle=make_bundle(self.case,self.signer,self.sign,base_packages=self.base,compression=compression)
        self.metadata.unlink()
        make_envelope(self.case,self.bundle,self.signer,self.public,self.sign)
        release=json.loads((self.bundle/'release.json').read_text())
        self.policy['transitions'][0]['evidence_sha256']=dict(release_manifest=digest(self.bundle/'release.json'),
                                                            transition_validation=release['files']['base.json'])
        self.policy_path.write_bytes(encoded(self.policy));self.args.policy_sha256=digest(self.policy_path)
        self.settings.update(metadata_sha256=digest(self.metadata),release_sha256=digest(self.bundle/'release.json'))
        self.settings_path.write_bytes(encoded(self.settings));self.args.settings_sha256=digest(self.settings_path)

    def invoke(self):
        read,write=os.pipe();pid=os.fork()
        if pid==0:
            os.close(read)
            try:
                # This host's Btrfs reports no free-inode count. Test a declared
                # synthetic inode budget while retaining real byte availability;
                # production has no fallback and refuses unknown inode counts.
                real_statvfs=os.statvfs
                override=[]
                def fixture_statvfs(path):
                    info=real_statvfs(path)
                    if info.f_favail==0 and info.f_files==0:
                        values=list(info);values[5]=values[6]=values[7]=1000000
                        override.append(True)
                        return os.statvfs_result(values)
                    return info
                check=scale.space.check
                with mock.patch.object(scale.space,'check',functools.partial(check,statvfs=fixture_statvfs)):
                    row=scale.apply(self.args)
                row['synthetic_inode_budget_injected']=bool(override)
                if hasattr(self,'_scale_drift_diagnostic'):
                    row['test_scale_precommit_reached']=self._scale_drift_precommit_reached
                    row['test_scale_post_load_signature']=self._scale_drift_post_load_signature
                    row['test_scale_post_load_engine']=self._scale_drift_post_load_engine
                    row['test_scale_original_verification']=self._scale_original_verification
                with os.fdopen(write,'wb') as stream:stream.write(encoded(row))
            finally:os._exit(0)
        os.close(write)
        with os.fdopen(read,'rb') as stream:data=stream.read(1024**2+1)
        _,status=os.waitpid(pid,0)
        diagnostic=getattr(self,'_scale_drift_diagnostic',None)
        if diagnostic is not None:diagnostic['stage']='child-exit'
        self.assertEqual(status,0)
        if diagnostic is not None:diagnostic['stage']='child-output-size'
        self.assertLessEqual(len(data),1024**2)
        if diagnostic is not None:diagnostic['stage']='child-json'
        return json.loads(data)

    def post_load_signature(self,filename,gpgdir):
        """TEST-only, after failed ALPM load, while its exact inputs still exist."""
        value=dict(state='STARTED',gpg_exit='UNAVAILABLE',gpg_status=[],unknown_status=False,
                   archive_equal='UNKNOWN',signature_equal='UNKNOWN',inputs_stable='UNKNOWN')
        try:
            path=Path(os.fsdecode(filename));gpgdir=Path(gpgdir)
            name='fixture-1-1-any.pkg.tar.gz'
            expected=gpgdir.parent/'authenticated/bundle/repo'/name
            if path != expected or path.is_symlink() or Path(str(path)+'.sig').is_symlink():
                value['state']='INPUT_REFUSED';return value
            original=self.bundle/'repo'/name;signature=Path(str(path)+'.sig')
            release=json.loads((self.bundle/'release.json').read_text())['files']
            before=(digest(path),digest(signature))
            value['archive_equal']=before[0] == digest(original) == release['repo/'+name]
            value['signature_equal']=before[1] == digest(str(original)+'.sig') == release['repo/'+name+'.sig']
            command=['/usr/bin/gpg','--no-options','--batch','--no-tty','--no-autostart',
                '--homedir',str(gpgdir),'--no-auto-key-retrieve','--no-auto-key-import',
                '--auto-key-locate','clear','--disable-dirmngr','--no-auto-check-trustdb',
                '--status-fd','1','--verify',str(signature),str(path)]
            result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,timeout=5,
                env={'PATH':'/usr/bin:/bin','HOME':str(gpgdir),'GNUPGHOME':str(gpgdir),'LC_ALL':'C'})
            if len(result.stdout)+len(result.stderr)>65536:
                value['state']='OUTPUT_BOUND';return value
            value['gpg_exit']=result.returncode if result.returncode in (0,1,2) else 'OTHER'
            statuses=set()
            for line in result.stdout.splitlines():
                parts=line.split(b' ',2)
                token=parts[1].decode('ascii',errors='replace') if len(parts)>1 and parts[0]==b'[GNUPG:]' else None
                if token in SIGNATURE_STATUS:statuses.add(token)
                elif line:value['unknown_status']=True
            value.update(state='OBSERVED',gpg_status=sorted(statuses),
                         inputs_stable=before == (digest(path),digest(signature)))
        except subprocess.TimeoutExpired:value.update(state='TIMEOUT',gpg_exit='TIMEOUT')
        except (OSError,ValueError,KeyError,TypeError):value['state']='DIAGNOSTIC_ERROR'
        return value

    def upgrade(self,compression):
        self.select(compression)
        row=self.run_update()
        self.assertEqual(row['status'],'PASS',row)
        self.assertEqual(len(row['before']),587)
        self.assertEqual(row['after'],dict(row['before'],fixture='1-1'))
        self.assertTrue(row['packages_committed'])
        self.assertEqual(row['prepared_add'],{'fixture':'1-1'})
        self.assertEqual(row['full587_composition'],'NOT ESTABLISHED')
        self.assertEqual((self.root/'usr/share/fixture/config').read_bytes(),b'TEST ONLY\n')

    def test_actual_gzip_single_upgrade_holds586_synthetic_versions(self): self.upgrade('gz')
    def test_actual_xz_single_upgrade_holds586_synthetic_versions(self): self.upgrade('xz')
    def test_actual_zstd_single_upgrade_holds586_synthetic_versions(self): self.upgrade('zst')

    def test_insufficient_capacity_refuses_before_commit(self):
        self.config['capacity']['root_reserve_bytes']=64*1024**3;self.configure()
        self.assert_refused(self.run_update(),'insufficient')

    def test_scale_input_drift_after_prepare_refused(self):
        # Only this test exposes finite diagnostic facts through native Results.
        diagnostic=self._scale_drift_diagnostic={'stage':'invoke','row':None}
        self._scale_drift_precommit_reached=False
        self._scale_drift_post_load_signature={'state':'NOT_RUN'}
        self._scale_drift_post_load_engine={'state':'NOT_RUN'}
        self._scale_original_verification={'state':'NOT_RUN'}
        bridge_path=compile_original_probe(self.case)
        class ObserveLoad(scale.roots.Alpm):
            def __init__(alpm,root,gpgdir,log,architecture='aarch64',*,limits):
                super().__init__(root,gpgdir,log,architecture,limits=limits)
                configuration=pre_load_handle(alpm,gpgdir)
                # Retain the CDLL/callback until the owned handle is released.
                bridge=alpm._test_original_bridge=install_original_probe(bridge_path,alpm)
                load=alpm.alpm_pkg_load
                def observed(handle,filename,full,level,package):
                    active_bridge=bridge
                    try:
                        if active_bridge is not None:active_bridge.probe_begin()
                    except Exception:active_bridge=None
                    try:
                        code=load(handle,filename,full,level,package)
                    finally:
                        # No ALPM calls here: setters/getters would clear failure errno.
                        try:
                            if active_bridge is not None:active_bridge.probe_end()
                        except Exception:active_bridge=None
                    self._scale_original_verification=original_probe_result(active_bridge)
                    try:
                        if code != 0 and alpm.alpm_strerror(alpm.alpm_errno(handle)) == b'invalid or corrupted package (PGP signature)':
                            self._scale_drift_post_load_engine=post_load_engine(alpm,configuration,gpgdir)
                            self._scale_drift_post_load_signature=self.post_load_signature(filename,gpgdir)
                    except Exception:
                        self._scale_drift_post_load_signature={'state':'DIAGNOSTIC_ERROR'}
                    return code
                alpm.alpm_pkg_load=observed
        precommit=scale.Runtime.precommit
        def change(runtime):
            self._scale_drift_precommit_reached=True
            Path(runtime.args.scale).write_bytes(Path(runtime.args.scale).read_bytes()+b' ')
            return precommit(runtime)
        with mock.patch.object(scale.roots,'Alpm',ObserveLoad), mock.patch.object(scale.Runtime,'precommit',change):
            value=self.invoke();diagnostic['row']=value
            # Preserve run_update/assert_refused checks and order, marking the
            # stage before every assertion, including the early trust checks.
            diagnostic['stage']='trust-stable'
            self.assertEqual(legacy.bound.trust_rows(legacy.bound.install.tree(self.root)),self.trust)
            diagnostic['stage']='package-lock-absent'
            self.assertFalse((self.root/'var/lib/pacman/db.lck').exists())
            diagnostic['stage']='workspace-clean'
            self.assertEqual(list(self.workspace.iterdir()),[self.root])
            diagnostic['stage']='refusal-status'
            self.assertEqual(value['status'],'FAIL',value)
            diagnostic['stage']='commit-not-started'
            self.assertFalse(value['commit_started'],value)
            diagnostic['stage']='checkpoint-unchanged'
            self.assertFalse(value['checkpoint_changed'],value)
            diagnostic['stage']='fixture-unchanged'
            self.assertEqual((self.root/self.owned['fixture'][0]).read_bytes(),b'BASE TEST ONLY\n')
            diagnostic['stage']='checkpoint-empty'
            self.assertEqual(list(self.state.iterdir()),[])
            diagnostic['stage']='scale-error-match'
            self.assertIn('scale configuration changed',value.get('error',''))
            diagnostic['stage']='complete'

    def test_existing_ldconfig_still_refuses(self):
        path=self.root/'usr/bin/ldconfig';path.parent.mkdir(parents=True)
        path.write_bytes(b'#!/bin/sh\nexit 99\n');path.chmod(0o755)
        self.assert_refused(self.run_update(),'auxiliary-present')

    def test_absent_required_platform_package_is_not_synthesized(self):
        runtime=scale.Runtime(self.args,self.config)
        before=dict(self.versions);before.pop('speakersafetyd');before['generic-audio']='1-1'
        with self.assertRaisesRegex(ValueError,'actual protected platform packages absent'):
            runtime.authorize(self.policy,self.settings,{},before,before,{}, {})

    def test_explicit_generic_mode_uses_real_observed_names_without_apple_fallback(self):
        renamed={'asahi-audio':'glibc','speakersafetyd':'pacman','fixture-asahi-kernel':'linux-aarch64'}
        local=self.root/'var/lib/pacman/local'
        for old,new in renamed.items():
            version=self.versions.pop(old);self.versions[new]=version
            self.owned[new]=self.owned.pop(old)
            oldpath=local/(old+'-'+version);newpath=local/(new+'-'+version);oldpath.rename(newpath)
            path=newpath/'desc';path.write_text(path.read_text().replace('\n'+old+'\n','\n'+new+'\n'))
        self.base=[dict(name=name,version=version,arch='any',depend=[],provides=[],conflict=[],files=self.owned[name])
                   for name,version in self.versions.items()]
        self.select('zst')
        self.config.update(platform_mode='generic-development',before_lock_sha256=scale.inventory_sha(self.versions),
            after_lock_sha256=scale.inventory_sha(dict(self.versions,fixture='1-1')))
        self.configure()
        generic=dict(schema_version=1,purpose='cachy-asahi-generic-development-update-policy',release_id='fixture-1',
            protected_packages=sorted(set(self.versions)-{'fixture'}),
            protected_versions={name:version for name,version in self.versions.items() if name!='fixture'},
            platform_roles={'kernel':['linux-aarch64']},protected_units=self.policy['protected_units'],
            before_lock_sha256=self.config['before_lock_sha256'],after_lock_sha256=self.config['after_lock_sha256'])
        self.policy_path.write_bytes(encoded(generic));self.args.policy_sha256=digest(self.policy_path)
        self.settings['model']='generic-development-only'
        self.settings_path.write_bytes(encoded(self.settings));self.args.settings_sha256=digest(self.settings_path)
        row=self.run_update();self.assertEqual(row['status'],'PASS',row)
        self.assertEqual(row['platform_mode'],'generic-development')
        self.assertEqual(row['apple_acceptance'],'NOT ESTABLISHED')
        self.assertNotIn('speakersafetyd',row['before']);self.assertNotIn('asahi-audio',row['before'])
        self.assertEqual(row['after'],dict(row['before'],fixture='1-1'))

    def test_explicit_generic_mode_does_not_accept_an_apple_policy_file(self):
        self.config['platform_mode']='generic-development';self.configure()
        self.assert_refused(self.run_update(),'generic development policy')

    def test_supervised_cli_preserves_known_worker_failure_truth(self):
        argv=[sys.executable,'-B',str(Path(__file__).with_name('scale_update.py'))]
        for key in ('root','workspace','settings','settings_sha256','policy','bundle','metadata','signature',
                    'public_keyring','state_dir','scale','scale_sha256'):
            argv.extend(['--'+key.replace('_','-'),str(getattr(self.args,key))])
        argv.extend(['--policy-sha256','0'*64])
        completed=subprocess.run(argv,capture_output=True,timeout=40)
        row=json.loads(completed.stdout)
        self.assertEqual(completed.returncode,1)
        self.assert_refused(row)
        self.assertIs(row['packages_committed'],False);self.assertIs(row['checkpoint_changed'],False)

    def test_measure_only_has_no_package_or_checkpoint_mutation(self):
        self.args.measure_only=True
        row=self.invoke()
        self.assertEqual(row['status'],'MEASURED',row)
        self.assertGreater(row['footprint']['database_files'],587)
        self.assertFalse(row['packages_committed']);self.assertFalse(row['checkpoint_changed'])
        self.assertEqual(list(self.state.iterdir()),[])


class ScaleReportingTruth(unittest.TestCase):
    def setUp(self):
        self.args=argparse.Namespace(root='/owned/root',workspace='/owned/work',scale='scale',scale_sha256='pin',
            measure_only=False,settings='settings',settings_sha256='pin',policy='policy',policy_sha256='pin',
            bundle='bundle',metadata='metadata',signature='signature',public_keyring='keyring',state_dir='state')
        patcher=mock.patch.object(scale.bound,'guard',return_value=None)
        patcher.start();self.addCleanup(patcher.stop)
        patcher=mock.patch.object(scale,'configuration',return_value={'platform_mode':'generic-development'})
        patcher.start();self.addCleanup(patcher.stop)

    def test_reporting_fault_after_committed_return_preserves_known_facts(self):
        class ReportingFault:
            @property
            def footprints(self):raise RuntimeError('post-return reporting fault')
        committed=dict(status='PASS',commit_started=True,packages_committed=True,checkpoint_changed=True,
                       before={'fixture':'0-1'},after={'fixture':'1-1'})
        with mock.patch.object(scale,'Runtime',return_value=ReportingFault()), \
             mock.patch.object(scale.bound,'apply',return_value=committed):
            row=scale.apply(self.args)
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['phase'],'scale-reporting')
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            self.assertIs(row[field],True)
        self.assertEqual(row['before'],committed['before']);self.assertEqual(row['after'],committed['after'])

    def test_interrupted_delegation_without_terminal_result_is_unknown(self):
        with mock.patch.object(scale,'Runtime'),mock.patch.object(scale.bound,'apply',side_effect=KeyboardInterrupt):
            row=scale.apply(self.args)
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            self.assertEqual(row[field],'UNKNOWN')

    def test_predelegation_failure_is_known_uncommitted(self):
        with mock.patch.object(scale,'Runtime',side_effect=ValueError('configuration fault')), \
             mock.patch.object(scale.bound,'apply') as delegate:
            row=scale.apply(self.args)
        delegate.assert_not_called()
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            self.assertIs(row[field],False)


if __name__=='__main__':unittest.main(verbosity=2)
