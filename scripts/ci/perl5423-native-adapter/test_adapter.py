#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actor-fenced proposed Source/entry controls; fixtures are MODELED DATA only."""
import ast
import copy
import importlib.util
import json
import io
import tarfile
import signal
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,file);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
common=module('adapter_common_controls',HERE/'common.py')
producer=module('adapter_producer_controls',HERE/'producer.py')
prepare=module('adapter_source_controls',HERE/'prepare.py')
exporter=module('adapter_export_controls',HERE/'data_export.py')


def deny(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.posix_spawn','os.fork'):
        raise AssertionError('actor forbidden in source controls: '+event)
sys.addaudithook(deny)


def fixtures():
    c=common.decode(common.read(HERE/'contract.json'))
    natural=dict(natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,leader_held_until_group_inspection=True,ownership_lost=False,exit_observed_via_waitpid=True,exit=0)
    before=dict(uid=1001,gid=1001,namespaces={k:k+':['+str(i)+']' for i,k in enumerate(('user','mnt','net','pid'),1)},uid_map=[[0,0,4294967295]],gid_map=[[0,0,4294967295]])
    bwrap=copy.deepcopy(before);bwrap['namespaces'].update(user='user:[11]',mnt='mnt:[12]',net='net:[13]');bwrap['uid_map']=bwrap['gid_map']=[[1001,1001,1]]
    unshare=copy.deepcopy(before);unshare.update(uid=0,gid=0,uid_map=[[0,1001,1]],gid_map=[[0,1001,1]]);unshare['namespaces']['user']='user:[14]'
    q=dict(schema=1,status='PASS_NAMESPACE_EFFECTS',source='2'*40,run='123',job='456',image='sha256:'+'4'*64,domain_sha256=c['domain_sha256'],reader_sha256='5'*64,cases={name:dict(exit_code=0,outcome='SUPPORTED',before=copy.deepcopy(before),after=after,retirement=copy.deepcopy(natural)) for name,after in [('bwrap-user-mount-net',bwrap),('unshare-mapped-root',unshare)]})
    a=dict(schema=1,operation=c['operation'],source=dict(sha='1'*40,ref='codex/MODELED-ONLY'),source_map_sha256='6'*64,run='123',job='456',approval='7'*64,image=q['image'],domain_sha256=c['domain_sha256'],qualification_sha256=common.pin(common.encode(q))['sha256'],expected349_sha256=c['expected349_sha256'],input_signature_audit_sha256='8'*64)
    return c,a,q


class SourceControls(unittest.TestCase):
    def test_separate_domain_modeled_positive_and_3937_refusal(self):
        c,a,q=fixtures();common.admission(a,q,c)
        q['source']=c['namespace']['Source3937']
        with self.assertRaisesRegex(ValueError,'separate'):common.admission(a,q,c)
    def test_missing_effect_denial_wrong_mapping_forced_retirement_refuse(self):
        c,a,original=fixtures()
        for kind in ('denied','no-change','wrong-map','forced','wrong-image'):
            q=copy.deepcopy(original);row=q['cases']['bwrap-user-mount-net']
            if kind=='denied':row['outcome']='DENIED'
            if kind=='no-change':row['after']['namespaces']=row['before']['namespaces']
            if kind=='wrong-map':row['after']['uid_map']=[[1001,0,1]]
            if kind=='forced':row['retirement']['forced_cleanup']=True
            if kind=='wrong-image':q['image']='sha256:'+'9'*64
            with self.subTest(kind=kind),self.assertRaises(ValueError):common.admission(a,q,c)
    def test_all_actual_selectors_null_templates_fail(self):
        c=common.decode(common.read(HERE/'contract.json'));a=common.decode(common.read(HERE/'admission.TEMPLATE.json'));q=common.decode(common.read(HERE/'qualification.TEMPLATE.json'))
        self.assertTrue(all(v is None for v in c['actual'].values()))
        with self.assertRaises(ValueError):common.admission(a,q,c)
    def test_unqualified_producer_refuses_before_output_or_actor(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);a=common.read(HERE/'admission.TEMPLATE.json');q=common.read(HERE/'qualification.TEMPLATE.json')
            (parent/'admission').write_bytes(a);(parent/'qualification').write_bytes(q)
            args=SimpleNamespace(admission=parent/'admission',qualification=parent/'qualification',admission_sha256=common.pin(a)['sha256'],qualification_sha256=common.pin(q)['sha256'],output=parent/'MUST_NOT_CREATE')
            with self.assertRaises(ValueError):producer.run(args)
            self.assertFalse(args.output.exists())
    def test_exact_create_options_cap0_and_bound_mounts(self):
        c,a,q=fixtures();item=dict(name='perl-native-123-aaaaaaaaaaaa-1',volume='private-work',admission_sha256='a'*64)
        argv=producer.options(item,a['image'],Path('/owned/inputs'),c)
        for flag in ['--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--user=1001:1001']:self.assertIn(flag,argv)
        self.assertFalse(any('privileged' in v or 'unconfined' in v for v in argv));self.assertIn('type=bind,src=/owned/inputs,dst=/inputs,readonly',argv)
    def test_entry_has_fixed_environment_full_configured_makepkg_and_provider_roots(self):
        c,_,_=fixtures();tree=ast.parse((HERE/'entry.py').read_text());strings={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)}
        for value in ['C','UTC','1','-j2','/usr/lib/libcrypt.so','/usr/lib/libcrypt.so.2','makepkg-base.conf','makepkg-effective.conf']:self.assertIn(value,strings)
        self.assertEqual(c['epoch'],1785628800);self.assertEqual(c['makepkg_argv'],['/usr/bin/makepkg','--config','/work/makepkg.conf','--cleanbuild','--nosign','--noconfirm','--log'])
        self.assertNotIn('--nocheck',c['makepkg_argv']);self.assertNotIn('--nodeps',c['makepkg_argv'])
        text=(HERE/'entry.py').read_text();self.assertLess(text.index('os.environ.update(env)'),text.index('provenance.main()'))
    def test_compression_config_exact_inverse_preserves_base(self):
        c,_,_=fixtures();base=b"PKGEXT='.pkg.tar.xz'\n";suffix=c['makepkg_config_suffix'].encode();effective=base+suffix
        self.assertEqual(effective[:-len(suffix)],base);self.assertTrue(effective.endswith(b"MAKEFLAGS='-j2'\n"));self.assertIn(b'COMPRESSZST=(zstd -c -T2 -19 -)',effective)
    def test_additions_only_whole_source_inverse_and_null_authority(self):
        actual={k:None for k in ('source','ref','run','job','approval','artifact','image')}
        before={'packet/DATA.txt':(b'MODELED inert input\n',0o644)};after=prepare.compose(before,{'entry.py':(b'# inert fixture\n',0o644)},actual)
        inverse=common.decode(after['inverse.json'][0]);undo={n:r for n,r in after.items() if n not in inverse['additions']}
        self.assertEqual(undo,before);self.assertEqual(prepare.atomic.tree(undo),inverse['before_tree']);self.assertEqual(common.decode(after['source-map.json'][0])['actual'],actual)
        with self.assertRaises(ValueError):prepare.compose(before,{'packet/DATA.txt':(b'changed',0o644)},actual)
    def test_complete_source_map_refuses_unrecorded_directories_and_aliases(self):
        actual={k:None for k in ('source','ref','run','job','approval','artifact','image')}
        files=prepare.compose({'packet/DATA.txt':(b'MODELED\n',0o644)},{'entry.py':(b'# fixture\n',0o644)},actual)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,(raw,mode) in files.items():
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
            expected=common.pin(files['source-map.json'][0])['sha256'];common.source(root,expected)
            extra=root/'unrecorded';extra.mkdir()
            with self.assertRaises(ValueError):common.source(root,expected)
            extra.rmdir();extra.symlink_to(root/'packet',target_is_directory=True)
            with self.assertRaises(ValueError):common.source(root,expected)

    def test_output_disjoint_guard_before_source_render(self):
        with self.assertRaisesRegex(ValueError,'disjoint'):prepare.construct(Path('/abs/packet'),'0'*64,HERE/'MUST_NOT_CREATE')
        self.assertFalse((HERE/'MUST_NOT_CREATE').exists())
    def test_signal_flag_defers_until_owned_tick_and_restores(self):
        old={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM)}
        with common.cancellation_scope() as cancelled:
            handler=signal.getsignal(signal.SIGTERM);handler(signal.SIGTERM,None);handler(signal.SIGTERM,None)
            self.assertEqual(cancelled,[True])
            with self.assertRaises(common.Cancelled):common.check_cancelled(cancelled)
        self.assertEqual({sig:signal.getsignal(sig) for sig in old},old)
    def test_anonymous_image_volume_refuses(self):
        _,a,_=fixtures();row=dict(Id=a['image'],Architecture='arm64',Os='linux',Config={'Volumes':{}})
        producer.image_identity(row,a['image']);row['Config']['Volumes']={'/untracked':{}}
        with self.assertRaisesRegex(ValueError,'anonymous'):producer.image_identity(row,a['image'])
    def test_namespace_malformed_map_refuses_before_actors(self):
        c,a,original=fixtures()
        for maps in [[[0,0,2**32]],[[0,0,10],[5,10,5]],[[i,i,1] for i in range(9)]]:
            q=copy.deepcopy(original);q['cases']['bwrap-user-mount-net']['before']['uid_map']=maps
            with self.assertRaises(ValueError):common.admission(a,q,c)
    def test_export_data_tar_boundaries_and_inert_bytes(self):
        def make(*,link=False,escape=False,root=True,root_mode=0o700,root_pax=None):
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as archive:
                if root:
                    d=tarfile.TarInfo('output');d.type=tarfile.DIRTYPE;d.mode=root_mode;d.pax_headers=root_pax or {};archive.addfile(d)
                item=tarfile.TarInfo('output/../escape' if escape else 'output/MODELED.txt');item.mode=0o644
                if link:item.type=tarfile.SYMTYPE;item.linkname='/tmp/escape';archive.addfile(item)
                else:item.size=4;archive.addfile(item,io.BytesIO(b'DATA'))
            return stream.getvalue()
        raw=make();self.assertEqual(exporter.parse(raw),{'MODELED.txt':(b'DATA',0o644)})
        for bad in [make(link=True),make(escape=True),make(root=False),make(root_mode=0o777),make(root_pax={'GNU.sparse.name':'output'}),raw+b'nonzero',raw[:1024]]:
            with self.assertRaises((ValueError,tarfile.TarError)):exporter.parse(bad)

    def test_strict_json_and_natural_retirement_refusals(self):
        for raw in [b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}']:
            with self.assertRaises(ValueError):common.decode(raw)
        _,_,q=fixtures();row=q['cases']['bwrap-user-mount-net']['retirement'];self.assertTrue(common.natural(row))
        for key,value in [('forced_cleanup',True),('ownership_lost',True),('group_absent',False),('exit_observed_via_waitpid',False)]:self.assertFalse(common.natural(dict(row,**{key:value})))


if __name__=='__main__':unittest.main(verbosity=2)
