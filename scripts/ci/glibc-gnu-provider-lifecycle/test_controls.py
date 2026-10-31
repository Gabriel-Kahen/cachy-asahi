# SPDX-License-Identifier: MIT
"""Bounded inert controls: synthetic inputs only; forbid every process actor."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C
import run
import container as lane


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        no=patch.object(subprocess,'Popen',side_effect=AssertionError('no actual actor'));no.start();self.addCleanup(no.stop)

    def elf(self,interpreter=b'/lib/ld-linux-aarch64.so.1\0'):
        raw=bytearray(120+len(interpreter));raw[:7]=b'\x7fELF\x02\x01\x01'
        struct.pack_into('<H',raw,18,183);struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1)
        struct.pack_into('<IIQQQQQQ',raw,64,3,4,120,0,0,len(interpreter),len(interpreter),1)
        raw[120:]=interpreter;return raw

    def test_unbound_policy_refuses_before_files_or_actors(self):
        with self.assertRaisesRegex(ValueError,'UNBOUND'):C.configuration(self.root,'0'*64)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_normal_interpreter_rejects_private_or_foreign_arch(self):
        self.assertEqual(C.interpreter(self.elf()),'/lib/ld-linux-aarch64.so.1')
        for value in [b'/opt/private/ld.so\0',b'/usr/lib/ld-linux-x86-64.so.2\0']:
            with self.assertRaises(ValueError):C.interpreter(self.elf(value))
        raw=self.elf();struct.pack_into('<H',raw,18,62)
        with self.assertRaises(ValueError):C.interpreter(raw)

    def test_payload_identity_modes_and_ownership_are_required(self):
        good={'usr/lib/libc.so.6':dict(type='file',sha256='a'*64,bytes=12,mode=493,uid=0,gid=0)}
        lane.payload(good,good)
        for field,value in [('sha256','b'*64),('mode',511),('uid',1)]:
            changed=copy.deepcopy(good);changed['usr/lib/libc.so.6'][field]=value
            with self.assertRaises(ValueError):lane.payload(changed,good)

    def test_all_574_ownership_intersections_excluding_only_glibc(self):
        rows=[dict(name='glibc',files=['usr/lib/libc.so.6']),dict(name='tzdata',files=['usr/bin/zic'])]
        new=dict(nodes={'usr/lib/libc.so.6':dict(type='file')})
        self.assertEqual(lane.collisions(new,rows),{'usr/lib/libc.so.6':'glibc'})
        new['nodes']['usr/bin/zic']=dict(type='file')
        with self.assertRaises(ValueError):lane.collisions(new,rows)

    def test_precommit_and_replace_use_one_complete_prepare_and_no_bypass(self):
        events=[]
        class Alpm:
            def __init__(self,*a,**kw):self.handle=1;self.started=False;self.lib=True
            def ok(self,code,label):self.assert_code=code;C.need(code==0,label)
            def inventory(self):return {'glibc':'held'}
            def alpm_trans_init(self,handle,flags):events.append(('flags',flags));return 0
            def alpm_pkg_load(self,*args):events.append('load');return 0
            def alpm_get_localdb(self,*a):return 3
            def alpm_db_get_pkg(self,*a):return 4
            def alpm_remove_pkg(self,*a):events.append('remove-declared');return 0
            def alpm_add_pkg(self,*a):events.append('add-declared');return 0
            def alpm_trans_prepare(self,*a):events.append('prepare');return 0
            def alpm_trans_get_add(self,*a):return 'add'
            def alpm_trans_get_remove(self,*a):return 'remove'
            def packages(self,value):return {C.NAME:C.VERSION} if value=='add' else {'glibc':'held'}
            def alpm_trans_commit(self,*a):events.append('commit');return 0
            def close(self):events.append('release')
        import ctypes
        api={'roots':NS(Alpm=Alpm,Limits=lambda **kw:kw,installer=NS(Ptr=ctypes.c_void_p))}
        result=lane.transaction(api,self.root,self.root/'provider','glibc',C.NAME,self.root/'log',True)
        self.assertFalse(result['commit_started']);self.assertNotIn('commit',events)
        self.assertEqual(events,[('flags',(1<<7)|(1<<10)),'load','remove-declared','add-declared','prepare','release'])
        events.clear();result=lane.transaction(api,self.root,self.root/'provider','glibc',C.NAME,self.root/'log')
        self.assertTrue(result['commit_started']);self.assertEqual(events[-3:],['prepare','commit','release'])

    def test_prepare_failure_releases_handle_without_commit(self):
        events=[]
        class Alpm:
            def __init__(self,*a,**k):self.handle=1;self.started=False
            def inventory(self):return {'glibc':'held'}
            def ok(self,*a):raise ValueError('injected preparation failure')
            def alpm_trans_init(self,*a):return 1
            def close(self):events.append('released')
        api={'roots':NS(Alpm=Alpm,Limits=lambda **kw:kw)}
        with self.assertRaises(ValueError):lane.transaction(api,self.root,self.root/'provider','glibc',C.NAME,self.root/'log')
        self.assertEqual(events,['released'])

    def test_unrelated_file_or_other_package_db_mutation_fails(self):
        old=dict(nodes={'usr/lib/libc.so.6':dict(type='file')});new=dict(nodes={'usr/lib/libc.so.6':dict(type='file')})
        before=dict(nodes={'etc/user-data':dict(type='file',sha256='a')})
        changed=copy.deepcopy(before);changed['nodes']['etc/user-data']['sha256']='b'
        with self.assertRaises(ValueError):lane.unchanged(before,changed,old,new,'held')
        changed=copy.deepcopy(before);changed['nodes']['var/lib/pacman/local/filesystem-1/desc']={}
        with self.assertRaises(ValueError):lane.unchanged(before,changed,old,new,'held')

    def test_actor_foreign_image_label_or_cid_refused(self):
        row=dict(Name='/owned',Image='sha256:'+'a'*64,Config=dict(Labels={C.LABEL:'b'*32}),Id='c'*64)
        self.assertEqual(run.owned(row,'owned','sha256:'+'a'*64,'b'*32),'c'*64)
        for field,value in [('Image','sha256:'+'d'*64),('Id','short')]:
            changed=copy.deepcopy(row);changed[field]=value
            with self.assertRaises(ValueError):run.owned(changed,'owned','sha256:'+'a'*64,'b'*32)
        row['Config']['Labels'][C.LABEL]='foreign'
        with self.assertRaises(ValueError):run.owned(row,'owned','sha256:'+'a'*64,'b'*32)

    def test_unknown_daemon_error_is_not_absence(self):
        with self.assertRaises(ValueError):run.inspect('owned',lambda *a,**k:dict(code=1,out=b'',err=b'daemon unavailable'))
        self.assertIsNone(run.inspect('owned',lambda *a,**k:dict(code=1,out=b'',err=b'No such container: owned')))

    def test_normal_exec_source_changes_only_declared_child_exec(self):
        change=json.loads(C.read(C.HERE/'normal-exec-change.json'))
        source=C.read(C.HERE/'smoke-normal.c');self.assertEqual(C.sha(source),change['after_sha256'])
        self.assertEqual(source.count(change['replacement_after'].encode()),1)
        restored=source.replace(change['replacement_after'].encode(),change['replacement_before'].encode())
        self.assertEqual(C.sha(restored),change['before_sha256'])
        self.assertIn(b'execve(child, arguments, environ)',source)

    def test_real_identity_gate_rejects_loader_exec_or_forged_mapping(self):
        expected=dict(nodes={});mapping=[];roles={}
        paths={**C.ROLES,'gconv':'usr/lib/gconv/ISO8859-1.so','locale':'usr/lib/locale/C.utf8/LC_CTYPE'}
        for role,name in paths.items():
            file=self.root/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(role.encode())
            info=file.stat();digest=C.sha(file.read_bytes());expected['nodes'][name]=dict(type='file',sha256=digest)
            row=dict(path='/'+name,inode=info.st_ino,device_major=os.major(info.st_dev),device_minor=os.minor(info.st_dev));mapping.append(row)
            if role in C.ROLES:roles[role]=dict(row,sha256=digest)
        tests=[dict(kind='test',name=n,process='parent',status='PASS') for n in ['allocation','dlopen_dlsym','pthread_tls_join','utf8_iconv_locale','numeric_math','fd_stat_clock_random','numeric_address_lookup','fork_exec_wait']]
        tests.append(dict(kind='test',name='exec_child',process='child',status='PASS'))
        providers=[dict(symbol=n,path=roles['libm' if n=='cos' else 'libc']['path']) for n in ['malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos']]
        identities=[dict(kind='identity',process=kind,executable='/'+lane.FIXTURE+'/'+executable,objects=mapping[:3],mapped_files=mapping,providers=providers) for kind,executable in [('parent','smoke-normal'),('child','exec-child')]]
        records=tests+identities+[dict(kind='result',status='PASS',cases=8,page_size=4096,glibc_version='2.43')]
        self.assertTrue(lane.validate_runtime(records,self.root,roles,expected)['normal_parent_and_child'])
        changed=copy.deepcopy(records);changed[9]['executable']=roles['loader']['path']
        with self.assertRaises(ValueError):lane.validate_runtime(changed,self.root,roles,expected)
        changed=copy.deepcopy(records);changed[9]['mapped_files'][0]['inode']+=1
        with self.assertRaises(ValueError):lane.validate_runtime(changed,self.root,roles,expected)
        changed=copy.deepcopy(records);changed[9]['mapped_files']=mapping[:3]
        with self.assertRaises(ValueError):lane.validate_runtime(changed,self.root,roles,expected)

    def test_seeded_backup_snapshots_detect_changed_or_deleted_configs(self):
        (self.root/'etc').mkdir();(self.root/'etc/gai.conf').write_bytes(b'preserve modified gai')
        before=lane.configs(self.root);(self.root/'etc/gai.conf').write_bytes(b'changed')
        self.assertNotEqual(before,lane.configs(self.root));(self.root/'etc/gai.conf').unlink()
        self.assertNotEqual(before,lane.configs(self.root))


    def capability_api(self):
        repo=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
        sys.path.insert(0,str(repo/'scripts/update'))
        bridge=C.load('control_capability_bridge',repo/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py');caps=C.load('control_capability_primitive',repo/'scripts/apps/file_capabilities.py')
        sys.path.insert(0,str(repo/'scripts/update'));import full_root
        return dict(capabilities=bridge,caps=caps,roots=full_root)

    def test_complete_tempfile_capability_map_and_unknown_attribute_refusal(self):
        api=self.capability_api();path=self.root/'inert';path.write_bytes(b'never executed');budget=lane.limits(api);nodes=api['roots'].observe(self.root,limits=budget,hardlinks='generic-development-internal')['nodes'];index=dict(source_capabilities={},source_capabilities_sha256=api['capabilities'].digest({}))
        self.assertEqual(api['capabilities'].observe(api,self.root,nodes,index,budget),{})
        os.setxattr(path,'user.UNIT-inert',b'refuse')
        with self.assertRaisesRegex(ValueError,'unknown xattr'):api['capabilities'].observe(api,self.root,nodes,index,budget)
        os.removexattr(path,'user.UNIT-inert');self.assertEqual(api['caps'].restore(self.root,nodes,{},budget),{})

    def test_copy_restore_happens_before_yield_and_refusal_keeps_original_cleanup(self):
        from contextlib import contextmanager
        api=self.capability_api();bridge=api['capabilities'];mapping={'inert':'0100000240000000000000000000000000000000'};index=dict(source_capabilities=mapping,source_capabilities_sha256=bridge.digest(mapping));events=[];lifetime={}
        @contextmanager
        def copied(source,workspace,**kwargs):
            events.append('copy')
            try:yield self.root,lifetime
            finally:events.append('original-cleanup')
        patcher=patch.object(bridge.scope,'copied_root',side_effect=copied);patcher.start();self.addCleanup(patcher.stop);api['copy']=NS(copied_root=copied);api['roots']=NS(observe=lambda *a,**k:{'nodes':{'inert':{}}})
        with patch.object(api['caps'],'restore',side_effect=lambda *a:(events.append('restore') or mapping)):
            with bridge.copied_root(api,Path('/INERT-source'),self.root,index,limits=NS(),cleanup_seconds=120):events.append('accepted-yield')
        self.assertEqual(events,['copy','restore','accepted-yield','original-cleanup']);self.assertEqual(lifetime['source_capabilities_sha256'],index['source_capabilities_sha256'])
        events.clear()
        with patch.object(api['caps'],'restore',side_effect=ValueError('unexpected capability')),self.assertRaisesRegex(ValueError,'unexpected capability'):
            with bridge.copied_root(api,Path('/INERT-source'),self.root,index,limits=NS(),cleanup_seconds=120):self.fail('must never accept copy')
        self.assertEqual(events,['copy','original-cleanup'])

    def test_source_map_hash_and_selected_provider_overlap_refuse(self):
        bridge=self.capability_api()['capabilities'];mapping={'usr/bin/UNIT-cap':'0100000240000000000000000000000000000000'};index=dict(source_capabilities=mapping,source_capabilities_sha256=bridge.digest(mapping));empty=dict(nodes={})
        bridge.disjoint(index,empty,empty)
        with self.assertRaisesRegex(ValueError,'selected provider'):bridge.disjoint(index,empty,dict(nodes={'usr/bin/UNIT-cap':dict(type='file')}))
        with self.assertRaisesRegex(ValueError,'map/hash'):bridge.binding(dict(index,source_capabilities_sha256='f'*64))

    def test_all_stage_capability_hashes_and_copy_receipt_are_required(self):
        bridge=self.capability_api()['capabilities'];index=dict(source_capabilities={},source_capabilities_sha256=bridge.digest({}));stages=('source-before','clone','held574','source-after')
        cases={case:dict(copy_lifetime=dict(copy={'gnu_bind_scope':{'UNIT':'inert-model-only'}},security_capabilities='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED',source_capabilities_sha256=index['source_capabilities_sha256']),capability_checks={case+'-'+stage:dict(status='EXACT_SOURCE_MAP_PRESERVED',sha256=index['source_capabilities_sha256'],paths=0) for stage in stages}) for case in ('pristine','modified')}
        with patch.object(bridge.scope,'receipt') as checked:self.assertEqual(bridge.records(index,cases,stages)['cases'],2)
        self.assertEqual(checked.call_count,2)
        for kind in ('missing','changed','copy'):
            bad=copy.deepcopy(cases)
            if kind=='missing':del bad['pristine']['capability_checks']['pristine-held574']
            elif kind=='changed':bad['pristine']['capability_checks']['pristine-held574']['sha256']='f'*64
            else:bad['pristine']['copy_lifetime']['security_capabilities']='NOT_RESTORED'
            with patch.object(bridge.scope,'receipt'),self.subTest(kind=kind),self.assertRaises(ValueError):bridge.records(index,bad,stages)

    def test_provider_and_held_archive_metadata_cannot_introduce_capabilities(self):
        import io,tarfile
        for pax in ({'SCHILY.xattr.security.capability':bytes.fromhex('0100000240000000000000000000000000000000').decode('utf8','surrogateescape')},{'SCHILY.xattr.user.UNIT':'unknown'}):
            path=self.root/'inert.tar'
            with tarfile.open(path,'w',format=tarfile.PAX_FORMAT) as archive:
                member=tarfile.TarInfo('usr/bin/inert');member.pax_headers=pax;archive.addfile(member,io.BytesIO(b''))
            with self.assertRaisesRegex(ValueError,'package xattrs'):C.archive(path)

    def package_fixture(self,entries):
        import io,tarfile
        path=self.root/'inert-package.tar'
        with tarfile.open(path,'w') as stream:
            for name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                raw=b'pkgname = inert\n';m=tarfile.TarInfo(name);m.size=len(raw);m.mode=0o644;stream.addfile(m,io.BytesIO(raw))
            for row in entries:
                m=tarfile.TarInfo(row['name']);m.type=row.get('type',tarfile.REGTYPE);m.mode=row.get('mode',0o644);m.uid=row.get('uid',0);m.gid=row.get('gid',0);m.linkname=row.get('target','');m.pax_headers=row.get('pax',{})
                raw=row.get('raw',b'inert never executed') if m.isfile() else row.get('raw',b'');m.size=len(raw)
                stream.addfile(m,io.BytesIO(raw) if raw else None)
        return path
    def test_archive_resolves_forward_internal_hardlink_chain_with_exact_bytes(self):
        import tarfile
        rows=[dict(name='usr/c',type=tarfile.LNKTYPE,target='usr/b'),dict(name='usr/b',type=tarfile.LNKTYPE,target='usr/a'),dict(name='usr/a')]
        value=C.archive(self.package_fixture(rows));nodes=value['nodes']
        self.assertEqual(set(nodes),{'usr/a','usr/b','usr/c'})
        for name in nodes:
            self.assertEqual(nodes[name],dict(type='file',mode=0o644,uid=0,gid=0,bytes=20,sha256=C.sha(b'inert never executed'),hardlink_group='usr/a'))
            self.assertEqual(value['data'][name],b'inert never executed')
        lane.payload(nodes,nodes)
    def test_archive_hardlink_missing_cycles_escape_and_special_targets_refuse(self):
        import tarfile
        bad=[[dict(name='usr/a',type=tarfile.LNKTYPE,target=target)] for target in ('usr/missing','/etc/passwd','../escape','usr/../escape','usr//bad','usr/./bad')]
        bad += [[dict(name='usr/a',type=tarfile.LNKTYPE,target='usr/b'),dict(name='usr/b',type=tarfile.LNKTYPE,target='usr/a')]]
        for kind in (tarfile.DIRTYPE,tarfile.SYMTYPE,tarfile.FIFOTYPE):
            bad.append([dict(name='usr/a',type=tarfile.LNKTYPE,target='usr/b'),dict(name='usr/b',type=kind,target='regular')])
        for rows in bad:
            with self.subTest(rows=rows),self.assertRaises(ValueError):C.archive(self.package_fixture(rows))
    def test_archive_hardlink_header_identity_size_metadata_and_ancestors_refuse(self):
        import tarfile
        regular=dict(name='usr/a');alias=dict(name='usr/b',type=tarfile.LNKTYPE,target='usr/a')
        for change in (dict(mode=0o600),dict(uid=1),dict(gid=1),dict(raw=b'invalid hardlink data'),dict(pax={'SCHILY.xattr.security.capability':'refuse'}),dict(target='.PKGINFO')):
            with self.subTest(change=change),self.assertRaises(ValueError):C.archive(self.package_fixture([regular,alias|change]))
        with self.assertRaisesRegex(ValueError,'ancestor'):
            C.archive(self.package_fixture([dict(name='usr',type=tarfile.SYMTYPE,target='elsewhere'),regular,alias]))
    def test_archive_hardlink_group_bound_remains_finite(self):
        import tarfile
        rows=[dict(name='usr/a')]+[dict(name='usr/alias-%04d'%n,type=tarfile.LNKTYPE,target='usr/a') for n in range(4096)]
        with self.assertRaisesRegex(ValueError,'group bound'):C.archive(self.package_fixture(rows))
    def test_real_inert_hardlinks_pass_payload_but_equal_byte_copies_and_extra_alias_refuse(self):
        import tarfile
        expected=C.archive(self.package_fixture([dict(name='usr/a'),dict(name='usr/b',type=tarfile.LNKTYPE,target='usr/a')]))['nodes']
        # Only temp fixture ownership is projected to this ordinary test UID/GID.
        expected={n:dict(row,uid=os.getuid(),gid=os.getgid()) for n,row in expected.items()}
        root=self.root/'tree';(root/'usr').mkdir(parents=True);a=root/'usr/a';a.write_bytes(b'inert never executed');a.chmod(0o644);b=root/'usr/b';os.link(a,b)
        api=self.capability_api()
        def observed():return api['roots'].observe(root,limits=lane.limits(api),hardlinks='generic-development-internal')['nodes']
        lane.payload(observed(),expected)
        b.unlink();b.write_bytes(a.read_bytes());b.chmod(0o644)
        with self.assertRaises(ValueError):lane.payload(observed(),expected)
        b.unlink();os.link(a,b);os.link(a,root/'usr/c')
        with self.assertRaisesRegex(ValueError,'hardlink group'):lane.payload(observed(),expected)
    def test_payload_hardlink_members_cannot_use_config_exception_or_changed_bytes(self):
        import tarfile
        nodes=C.archive(self.package_fixture([dict(name='usr/a'),dict(name='usr/b',type=tarfile.LNKTYPE,target='usr/a')]))['nodes']
        with self.assertRaisesRegex(ValueError,'hardlink group'):lane.payload(nodes,nodes,('usr/b',))
        for key,value in (('sha256','0'*64),('bytes',1),('mode',0o600),('uid',1),('gid',1)):
            changed=copy.deepcopy(nodes);changed['usr/b'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):lane.payload(changed,nodes)


    def test_pre_yield_copy_failure_keeps_stage_and_original_error(self):
        from contextlib import contextmanager
        bridge=self.capability_api()['capabilities'];evidence={}
        @contextmanager
        def refused(*a,**kw):
            raise ValueError('original copy guard')
            yield
        with patch.object(bridge.scope,'copied_root',side_effect=refused),self.assertRaisesRegex(ValueError,'original copy guard'):
            with bridge.copied_root({},'/held','/work/pristine',{},evidence=evidence):self.fail('no yield')
        self.assertEqual(evidence['stage'],'COPY_ENTER')
        self.assertEqual(evidence['failure'][0]['message'],'original copy guard')
        self.assertNotIn('lifetime',evidence)

    def test_restore_refusal_retains_real_retired_lifetime_before_caller_yield(self):
        from contextlib import contextmanager
        api=self.capability_api();bridge=api['capabilities'];lifetime={};evidence={}
        @contextmanager
        def copied(*a,**kw):
            try:yield self.root,lifetime
            finally:lifetime['cleanup']='PASS-owned-workspace-removed'
        api['roots']=NS(observe=lambda *a,**k:{'nodes':{}})
        index=dict(source_capabilities={},source_capabilities_sha256=bridge.digest({}))
        with patch.object(bridge.scope,'copied_root',side_effect=copied),patch.object(api['caps'],'restore',side_effect=ValueError('original cap guard')),self.assertRaisesRegex(ValueError,'original cap guard'):
            with bridge.copied_root(api,'/held','/work/pristine',index,evidence=evidence,limits=None):self.fail('no yield')
        self.assertEqual(evidence['stage'],'CAPABILITY_RESTORE')
        self.assertEqual(evidence['lifetime']['cleanup'],'PASS-owned-workspace-removed')

    def test_original_primary_is_not_masked_by_missing_clone_lifetime(self):
        from contextlib import contextmanager
        bridge=self.capability_api()['capabilities'];report={}
        @contextmanager
        def refused(*a,**kw):
            raise ValueError('primary copy guard')
            yield
        api=dict(capabilities=bridge);source={'nodes':{'inert':{'sha256':'a'*64}}}
        sha=C.sha(json.dumps(source['nodes'],sort_keys=True).encode())
        with patch.object(bridge,'copied_root',side_effect=refused),patch.object(lane,'limits',return_value=None),patch.object(lane,'snapshot',return_value=source),patch.object(lane,'database',return_value=[]),patch.object(lane,'inventory',return_value={}),self.assertRaisesRegex(ValueError,'primary copy guard'):
            lane.run_case(api,None,{'source_nodes_sha256':sha},{},{},{},'pristine',report)
        self.assertEqual(report['primary_failure'][0]['message'],'primary copy guard')
        self.assertEqual(report['cleanup_failure'][0]['message'],'complete clone cleanup verified')
        self.assertEqual(report['clone_cleanup_check'],'FAIL_OR_UNESTABLISHED')
        self.assertEqual(report['source_before'],report['source_after'])

    def test_failure_chain_metadata_is_bounded_and_excludes_frame_locals(self):
        bridge=self.capability_api()['capabilities']
        try:
            try:raise ValueError('p'*10000)
            except ValueError as first:raise RuntimeError('outer') from first
        except RuntimeError as error:rows=bridge.failure(error)
        self.assertEqual([r['type'] for r in rows],['RuntimeError','ValueError'])
        self.assertEqual(len(rows[1]['message']),512)
        self.assertLess(len(json.dumps(rows)),8192)
        self.assertTrue(all(set(f)=={'file','function','line'} for r in rows for f in r['frames']))


    def test_trial_alone_has_fsetid_and_kill_for_metadata_and_owned_uid65534_retirement(self):
        import ast
        tree=ast.parse(Path(run.__file__).read_bytes())
        assignments=[n for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='caps' for t in n.targets)]
        self.assertEqual(len(assignments),1)
        expression=compile(ast.Expression(assignments[0].value),str(run.__file__),'eval')
        def caps(role):return eval(expression,{'__builtins__':{}},{'role':role})
        self.assertEqual(caps('trial'),('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','KILL','SETUID','SETGID','SYS_CHROOT','SYS_ADMIN','SETFCAP'))
        self.assertEqual(caps('scrub'),('CHOWN','DAC_OVERRIDE','FOWNER'))
        self.assertNotIn('FSETID',caps('scrub'));self.assertNotIn('KILL',caps('scrub'))

    def test_real_inert_setid_metadata_still_requires_both_exact_mode_bits(self):
        # Never execute this owned tempfile. This exercises the actual unchanged
        # failing metadata guard; foreign-group kernel authority is native-only.
        path=self.root/'inert-never-executed';path.write_bytes(b'inert mode fixture');path.chmod(0o6755)
        api=self.capability_api();copier=api['capabilities'].scope.aux_copy.measure_copy
        expected=dict(mode=0o6755,uid=os.getuid(),gid=os.getgid())
        copier._metadata_equal(path.stat(),expected)
        path.chmod(0o4755)
        with self.assertRaisesRegex(ValueError,'copy metadata differs'):copier._metadata_equal(path.stat(),expected)
        path.chmod(0o2755)
        with self.assertRaisesRegex(ValueError,'copy metadata differs'):copier._metadata_equal(path.stat(),expected)
        path.chmod(0o6755);copier._metadata_equal(path.stat(),expected)

    def init_fixture(self,case='pristine'):
        work=self.root/'work';work.mkdir(exist_ok=True);workspace=work/case;workspace.mkdir(mode=0o700);root=workspace/'root';root.mkdir(mode=0o700);source=self.root/'held';source.mkdir(mode=0o700,exist_ok=True);inputs=self.root/'inputs';inputs.mkdir(exist_ok=True)
        probes={}
        for name in ('smoke-normal','exec-child','plugin.so'):
            (inputs/name).write_bytes(b'UNIT inert never executed');probes[name]=dict(path=name)
        return root,source,work,inputs,dict(probes=probes,held=dict(path='held.pkg'))
    def initialize(self,root,source,work,inputs,index):
        with patch.object(lane,'WORK',work),patch.object(lane,'HELD',source),patch.object(lane,'INPUTS',inputs),patch.object(lane.C,'archive',return_value=dict(data={'.INSTALL':b'UNIT inert script never sourced'})):return lane.copy_probes(root,index)
    def test_owned_clone_search_mode_after_copy_preserves_source_parent_and_payload(self):
        import stat
        for case in ('pristine','modified'):
            root,source,work,inputs,index=self.init_fixture(case);(root/'payload').write_bytes(b'preserve payload');before=(root/'payload').stat();source_before=source.stat();fds=len(list(Path('/proc/self/fd').iterdir()));receipt=self.initialize(root,source,work,inputs,index)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o755);self.assertEqual(stat.S_IMODE(root.parent.stat().st_mode),0o700);self.assertEqual(stat.S_IMODE(source.stat().st_mode),0o700);self.assertEqual(source_before,source.stat());self.assertEqual(before,(root/'payload').stat());self.assertEqual((root/'payload').read_bytes(),b'preserve payload');self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),fds)
            self.assertEqual(receipt['before']['mode'],0o700);self.assertEqual(receipt['after'],dict(receipt['before'],mode=0o755));self.assertEqual(receipt['source_before'],receipt['source_after']);self.assertEqual(receipt['parent_before'],receipt['parent_after'])
    def test_clone_search_mode_refuses_foreign_or_symlink_or_nonprivate_parent(self):
        root,source,work,inputs,index=self.init_fixture();root.parent.chmod(0o755)
        with self.assertRaises(ValueError):self.initialize(root,source,work,inputs,index)
        self.assertEqual(root.stat().st_mode&0o777,0o700);root.parent.chmod(0o700);root.rmdir();root.symlink_to(source,target_is_directory=True)
        with self.assertRaises(ValueError):self.initialize(root,source,work,inputs,index)
        with self.assertRaises(ValueError):self.initialize(source,source,work,inputs,index)
        self.assertEqual(source.stat().st_mode&0o777,0o700)
    def test_clone_root_mode_drift_is_fatal_and_never_silently_accepted(self):
        root,source,work,inputs,index=self.init_fixture();original=lane.os.fchmod
        def wrong(fd,mode):original(fd,0o777)
        with patch.object(lane.os,'fchmod',side_effect=wrong),self.assertRaisesRegex(ValueError,'only owned cloned'):self.initialize(root,source,work,inputs,index)
        self.assertEqual(source.stat().st_mode&0o777,0o700);self.assertEqual(root.parent.stat().st_mode&0o777,0o700)
    def test_complete_copy_proof_precedes_root_mode_initialization_and_baseline(self):
        import ast
        text=Path(lane.__file__).read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='run_case');body=ast.get_source_segment(text,node)
        self.assertLess(body.index("case+'-clone'"),body.index("copy_byte_identical_before_initialization"));self.assertLess(body.index("copy_byte_identical_before_initialization"),body.index("report['root_initialization']"));self.assertLess(body.index("report['root_initialization']"),body.index("case+'-before574'"))

# Real tempfile configuration handoff controls, with no actor execution.
import ast
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def need(ok,why):
    if not ok:raise ValueError(why)
def node(data,mode=0o640):return dict(type='file',bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mode=mode,uid=os.geteuid(),gid=os.getegid())
def code(role):
    path=HERE.parent/('glibc-gnu-provider-'+role)/'container.py';tree=ast.parse(path.read_bytes());function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='config_handoff')
    return compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),str(path),'exec')

class ConfigHandoffControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name);self.parent=self.work/'modified';self.root=self.parent/'root';self.root.mkdir(parents=True);self.parent.chmod(0o700);self.root.chmod(0o755)
        (self.root/'etc').mkdir();(self.root/'tmp/provider-lifecycle').mkdir(parents=True)
        self.gai=b'original modified gai\n';self.locale=b'original modified locale\n';self.default=b'provider gai default\n';self.held=b'held gai default\n';self.held_locale=b'held locale default\n'
        self.before=dict(nodes={'etc/gai.conf':node(self.gai),'etc/locale.gen':node(self.locale)})
        self.new=dict(nodes={'etc/gai.conf':node(self.default,0o644)},data={'etc/gai.conf':self.default})
        self.old=dict(nodes={'etc/gai.conf':node(self.held,0o644),'etc/locale.gen':node(self.held_locale,0o644)},data={'etc/gai.conf':self.held,'etc/locale.gen':self.held_locale})
        self.ns=dict(os=os,stat=stat,WORK=self.work,FIXTURE='tmp/provider-lifecycle',C=SimpleNamespace(need=need,sha=lambda b:hashlib.sha256(b).hexdigest()));exec(code('lifecycle'),self.ns);self.call=self.ns['config_handoff']
        self.write('etc/gai.conf',self.default,0o644);self.write('etc/gai.conf.pacsave',self.gai);self.write('etc/locale.gen.pacsave',self.locale)
    def write(self,name,data,mode=0o640):
        p=self.root/name;p.write_bytes(data);p.chmod(mode)
    def run_phase(self,phase):return self.call(self.root,self.before,self.new,self.old,self.gai,self.locale,phase)
    def assert_file(self,name,data,mode):
        p=self.root/name;self.assertEqual(p.read_bytes(),data);s=p.stat();self.assertEqual((stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid,s.st_nlink),(mode,os.geteuid(),os.getegid(),1))
    def test_provider_handoff_preserves_active_backup_default_and_metadata(self):
        r=self.run_phase('provider');self.assertEqual(r['status'],'PASS_EXPLICIT_CLONE_CONFIG_HANDOFF');self.assertEqual(r['ALPM_active_configuration_preservation'],'NOT_CLAIMED');self.assertEqual(len(r['operations']),2)
        self.assert_file('etc/gai.conf',self.gai,0o640);self.assert_file('etc/gai.conf.pacsave',self.gai,0o640);self.assert_file('etc/gai.conf.pacnew',self.default,0o644);self.assert_file('etc/locale.gen.pacsave',self.locale,0o640)
    def test_full_rollback_stash_recreated_backup_and_restored_active(self):
        self.run_phase('provider');prepare=self.run_phase('rollback_prepare');self.assertEqual(len(prepare['operations']),2);self.assertFalse((self.root/'etc/gai.conf.pacsave').exists());self.assert_file('tmp/provider-lifecycle/gai-pacsave-before-rollback',self.gai,0o640)
        # Exact ordinary remove/add outcome required by rollback_finish, not an ALPM test.
        self.write('etc/gai.conf.pacsave',self.gai);self.write('etc/gai.conf',self.held,0o644);self.write('etc/locale.gen',self.held_locale,0o644)
        r=self.run_phase('rollback_finish');self.assertEqual(len(r['operations']),1);self.assert_file('etc/gai.conf',self.gai,0o640);self.assert_file('etc/gai.conf.pacsave',self.gai,0o640);self.assert_file('etc/gai.conf.pacnew',self.default,0o644);self.assert_file('etc/locale.gen',self.held_locale,0o644);self.assert_file('etc/locale.gen.pacsave',self.locale,0o640)
    def test_preexisting_pacnew_refused_before_any_change(self):
        self.write('etc/gai.conf.pacnew',b'foreign')
        with self.assertRaisesRegex(ValueError,'fresh configuration'):self.run_phase('provider')
        self.assert_file('etc/gai.conf',self.default,0o644)
    def test_unknown_sidecar_refused(self):
        self.write('etc/gai.conf.pacsave.1',b'foreign')
        with self.assertRaisesRegex(ValueError,'unknown configuration'):self.run_phase('provider')
    def test_modified_backup_bytes_refused(self):
        self.write('etc/gai.conf.pacsave',b'changed')
        with self.assertRaisesRegex(ValueError,'exact configuration'):self.run_phase('provider')
        self.assertFalse((self.root/'etc/gai.conf.pacnew').exists())
    def test_modified_backup_metadata_refused(self):
        (self.root/'etc/gai.conf.pacsave').chmod(0o600)
        with self.assertRaisesRegex(ValueError,'exact configuration'):self.run_phase('provider')
    def test_locale_backup_mismatch_refused(self):
        self.write('etc/locale.gen.pacsave',b'changed')
        with self.assertRaisesRegex(ValueError,'exact configuration'):self.run_phase('provider')
    def test_hardlink_backup_refused(self):
        os.link(self.root/'etc/gai.conf.pacsave',self.work/'alias')
        with self.assertRaisesRegex(ValueError,'single-link'):self.run_phase('provider')
    def test_symbolic_backup_refused(self):
        (self.root/'etc/gai.conf.pacsave').unlink();(self.root/'etc/gai.conf.pacsave').symlink_to(self.root/'etc/gai.conf')
        with self.assertRaisesRegex(ValueError,'ordinary configuration'):self.run_phase('provider')
    def test_foreign_root_and_nonprivate_parent_refused(self):
        with self.assertRaisesRegex(ValueError,'exact modified'):self.call(self.work,self.before,self.new,self.old,self.gai,self.locale,'provider')
        self.parent.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'private parent'):self.run_phase('provider')
    def test_rollback_foreign_stash_refused_without_unlink(self):
        self.run_phase('provider');self.write('tmp/provider-lifecycle/gai-pacsave-before-rollback',b'foreign')
        with self.assertRaisesRegex(ValueError,'fresh configuration'):self.run_phase('rollback_prepare')
        self.assert_file('etc/gai.conf.pacsave',self.gai,0o640)
    def test_rollback_finish_requires_exact_recreated_backup(self):
        self.run_phase('provider');self.run_phase('rollback_prepare');self.write('etc/gai.conf',self.held,0o644);self.write('etc/locale.gen',self.held_locale,0o644);self.write('etc/gai.conf.pacsave',b'foreign')
        with self.assertRaisesRegex(ValueError,'exact configuration'):self.run_phase('rollback_finish')
    def test_drift_before_active_write_refused(self):
        original=os.open
        def changed(path,flags,*args,**kwargs):
            if str(path).endswith('gai.conf.pacnew') and flags&os.O_EXCL:self.write('etc/gai.conf.pacsave',b'changed')
            return original(path,flags,*args,**kwargs)
        with patch.object(os,'open',side_effect=changed),self.assertRaisesRegex(ValueError,'changed during handoff'):self.run_phase('provider')
        self.assert_file('etc/gai.conf',self.default,0o644)
    def test_untrusted_directory_refused_before_any_write(self):
        (self.root/'etc').chmod(0o777)
        with self.assertRaisesRegex(ValueError,'nonwritable-by-others'):self.run_phase('provider')
        self.assertFalse((self.root/'etc/gai.conf.pacnew').exists())
    def test_unknown_active_default_refused(self):
        self.write('etc/gai.conf',b'unknown active data',0o644)
        with self.assertRaisesRegex(ValueError,'exact configuration'):self.run_phase('provider')
        self.assertFalse((self.root/'etc/gai.conf.pacnew').exists())
    def test_oversized_backup_refused(self):
        self.write('etc/gai.conf.pacsave',b'x'*(2*1024**2+1))
        with self.assertRaisesRegex(ValueError,'bounded plain configuration'):self.run_phase('provider')
    def test_unknown_phase_refused(self):
        with self.assertRaisesRegex(ValueError,'finite configuration handoff phase'):self.run_phase('unknown')
    def test_extended_attribute_refused(self):
        os.setxattr(self.root/'etc/gai.conf.pacsave','user.UNIT-unknown',b'foreign')
        with self.assertRaisesRegex(ValueError,'bounded plain configuration'):self.run_phase('provider')
    def test_partial_operation_evidence_survives_failure(self):
        evidence={};original=os.pwrite;calls=[]
        def fail(fd,data,offset):
            calls.append(fd)
            if len(calls)==2:raise OSError('inert active write failure')
            return original(fd,data,offset)
        with patch.object(os,'pwrite',side_effect=fail),self.assertRaisesRegex(OSError,'inert active'):
            self.call(self.root,self.before,self.new,self.old,self.gai,self.locale,'provider',evidence=evidence)
        self.assertEqual(evidence['status'],'STARTED_EXPLICIT_CLONE_CONFIG_HANDOFF');self.assertEqual(len(evidence['operations']),1);self.assertIn('before',evidence);self.assert_file('etc/gai.conf.pacsave',self.gai,0o640)
    def test_both_roles_share_exact_helper_and_three_explicit_calls(self):
        funcs=[]
        for role in ('lifecycle','interruption'):
            tree=ast.parse((HERE.parent/('glibc-gnu-provider-'+role)/'container.py').read_bytes());funcs.append(ast.dump(next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='config_handoff')));case=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run_case');calls=[n for n in ast.walk(case) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='config_handoff'];self.assertEqual(sorted(ast.literal_eval(c.args[-1]) for c in calls),['provider','rollback_finish','rollback_prepare'])
        self.assertEqual(*funcs)


import dataclasses
HERE=Path(__file__).resolve().parent
REPO=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(REPO/'scripts/update'))
import full_root

def load_observation(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class ObservationFactsControls(unittest.TestCase):
 def setUp(self):
  no=patch.object(subprocess,'Popen',side_effect=AssertionError('no observation diagnostic actor'));no.start();self.addCleanup(no.stop)
 def lanes(self):
  for lane in ('lifecycle','interruption'):
   common=load_observation('observation_common_'+lane,REPO/'scripts/ci'/('glibc-gnu-provider-'+lane)/'common.py')
   folder=HERE.parent/('glibc-gnu-provider-'+lane)
   with patch.dict(sys.modules,{'common':common}):module=load_observation('observation_lane_'+lane,folder/'container.py')
   yield lane,module
 def api(self,observe):
  return dict(roots=NS(Limits=full_root.Limits,observe=observe),capabilities=NS(observe=lambda *a:(_ for _ in ()).throw(AssertionError('capability observation forbidden after failed gate'))))
 def test_real_incomplete_observation_preserved_before_unchanged_fatal_gate(self):
  for lane,module in self.lanes():
   with self.subTest(lane=lane),tempfile.TemporaryDirectory() as temp:
    root=Path(temp);(root/'one').write_bytes(b'private-payload-not-exported');(root/'two').write_bytes(b'other');observed=[]
    def observe(path,*,limits,hardlinks):
     self.assertEqual(limits.max_nodes,500000);self.assertEqual(limits.max_bytes,8*1024**3)
     value=full_root.observe(path,limits=dataclasses.replace(limits,max_nodes=1),hardlinks=hardlinks);observed.append(value);return value
    api=self.api(observe);report={}
    with patch.object(module,'HELD',root),self.assertRaisesRegex(ValueError,'complete bounded root observation'):module.run_case(api,None,{}, {},{}, {},'pristine',report)
    facts=report['root_observation_failures']['pristine-source-before'];self.assertFalse(facts['complete']);self.assertEqual(facts['unsupported_counts'],observed[0]['unsupported_counts']);self.assertIn('root node limit',facts['unsupported_counts']);self.assertEqual(facts['unsupported_records'],observed[0]['unsupported']);self.assertEqual(facts['root'],str(root));self.assertEqual(facts['observer_budget_seconds'],600);self.assertEqual(report['capability_checks'],{});self.assertNotIn('nodes',facts);self.assertNotIn('private-payload',json.dumps(report));self.assertEqual(sorted(p.name for p in root.iterdir()),['one','two'])
 def test_real_complete_unsupported_observation_still_fails_with_exact_facts(self):
  for lane,module in self.lanes():
   with self.subTest(lane=lane),tempfile.TemporaryDirectory() as temp:
    root=Path(temp);os.mkfifo(root/'original-fifo');observed=[]
    def observe(path,**kwargs):
     value=full_root.observe(path,**kwargs);observed.append(value);return value
    api=self.api(observe);report={}
    with patch.object(module,'HELD',root),self.assertRaisesRegex(ValueError,'complete bounded root observation'):module.run_case(api,None,{}, {},{}, {},'modified',report)
    facts=report['root_observation_failures']['modified-source-before'];self.assertTrue(facts['complete']);self.assertEqual(facts['unsupported_counts'],{'special-node':1});self.assertEqual(facts['unsupported_records'],[{'reason':'special-node','path':'original-fifo'}]);self.assertEqual(facts['footprint']['nodes'],observed[0]['footprint']['nodes']);self.assertNotIn('nodes',facts)
 def test_success_keeps_original_snapshot_result_and_no_failure_facts(self):
  for lane,module in self.lanes():
   with self.subTest(lane=lane),tempfile.TemporaryDirectory() as temp:
    root=Path(temp);(root/'payload').write_bytes(b'original');out=root/'evidence';out.mkdir();api=dict(roots=full_root,capability_checks={},capability_index={},capabilities=NS(observe=lambda *a:{},digest=lambda v:'0'*64))
    with patch.object(module,'OUT',out):value=module.snapshot(api,root,'pristine-source-before')
    self.assertTrue(value['complete']);self.assertNotIn('root_observation_failures',api);self.assertTrue((out/'pristine-source-before-root.json.gz').is_file());self.assertEqual(api['capability_checks']['pristine-source-before']['status'],'EXACT_SOURCE_MAP_PRESERVED')
 def test_arbitrary_or_oversized_returned_objects_never_serialized(self):
  for lane,module in self.lanes():
   for changes in ({'unsupported_counts':{'reason':object()}},{'unsupported':[{'reason':'bad','path':'x'*4097}]},{'footprint':{'bytes':object()}}):
    with self.subTest(lane=lane,changes=list(changes)):
     value=dict(complete=False,unsupported_counts={},unsupported=[],footprint={});value.update(changes);api=self.api(lambda *a,**kw:value);api['root_observation_failures']={}
     with self.assertRaisesRegex(ValueError,'bounded original|finite original'):module.snapshot(api,Path('/held'),'pristine-source-before')
     self.assertEqual(api['root_observation_failures'],{})
if __name__=='__main__':unittest.main()
