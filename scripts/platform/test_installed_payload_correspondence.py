# SPDX-License-Identifier: MIT
"""Actual tiny archive/tree observations only; no package/image executable."""
import copy
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import signal
import stat
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch

P=Path(__file__).with_name('installed_payload_correspondence.py')
a=types.ModuleType('captured_correspondence');a.__file__=str(P);exec(compile(P.read_bytes(),str(P),'exec'),a.__dict__)


def ref(p):
    b=p.read_bytes();return dict(path=str(p),size=len(b),sha256=hashlib.sha256(b).hexdigest(),identity=a.identity(p.stat()))


class CorrespondenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.root=self.base/'tree';self.root.mkdir(mode=0o700)
        (self.root/'usr').mkdir();(self.root/'usr/data').write_bytes(b'tiny immutable payload\n');os.chmod(self.root/'usr/data',0o640)
        (self.root/'usr/alias').symlink_to('data');os.link(self.root/'usr/data',self.root/'usr/hard')
        self.ident={'name':'fixture','version':'1:1.0-1','arch':'any'}
        self.members=[('usr',tarfile.DIRTYPE,b'',None,0o755),('usr/data',tarfile.REGTYPE,b'tiny immutable payload\n',None,0o640),('usr/alias',tarfile.SYMTYPE,b'','data',0o777),('usr/hard',tarfile.LNKTYPE,b'','usr/data',0o640)]
        self.contract=self.make_contract()
    def make_archive(self,members=None,identity=None,uid=None,gid=None):
        out=io.BytesIO();identity=identity or self.ident
        controls=('.PKGINFO',tarfile.REGTYPE,('pkgname = '+identity['name']+'\npkgver = '+identity['version']+'\narch = '+identity['arch']+'\n').encode(),None,0o644)
        with tarfile.open(fileobj=out,mode='w',format=tarfile.GNU_FORMAT if uid is not None or gid is not None else tarfile.USTAR_FORMAT) as t:
            for name,kind,data,target,mode in [controls,*(members if members is not None else self.members)]:
                n=tarfile.TarInfo(name);n.type=kind;n.mode=mode;n.uid=os.getuid() if uid is None else uid;n.gid=os.getgid() if gid is None else gid;n.size=len(data) if kind==tarfile.REGTYPE else 0
                if target:n.linkname=target
                t.addfile(n,io.BytesIO(data) if kind==tarfile.REGTYPE else None)
        p=self.base/'fixture.pkg.tar.xz';p.write_bytes(lzma.compress(out.getvalue()));return p
    def make_contract(self):
        ar=ref(self.make_archive());sig=self.base/'signature';sig.write_bytes(b'MODELED detached signature only')
        auth=self.base/'authentication';auth.write_text(json.dumps({'scope':'MODELED-NOT-CRYPTOGRAPHIC','identity':self.ident,'archive_sha256':ar['sha256'],'signature_sha256':ref(sig)['sha256']}))
        owned=self.base/'ownership';owned.write_text(json.dumps({'schema_version':1,'scope':'inert-tree-fixture','packages':[{'identity':self.ident,'files':[n[0] for n in self.members]}]}))
        return dict(schema_version=1,scope='inert-tree-fixture',packages=[dict(identity=self.ident,archive=ar,signature=ref(sig),authentication=ref(auth))],ownership=ref(owned),tree_identity=a.identity(self.root.stat()))
    def run_model(self,c=None):return a.run(c or self.contract,self.root,time.monotonic()+10)
    def update_tree(self):self.contract['tree_identity']=a.identity(self.root.stat())
    def test_complete_real_tiny_file_directory_symlink_hardlink_and_ownership(self):
        r=self.run_model();self.assertEqual(r['status'],'PASS-inert-tree-correspondence');self.assertEqual((r['packages'],r['expected_paths'],r['observed_paths']),(1,4,4))
        for flag in ('installed_payload_verified','installation_accepted','hardware_accepted','image_issuer_authentication_accepted','independent_key_owner_trust_accepted','archive_signatures_verified_by_helper'):self.assertIs(r[flag],False)
        self.assertEqual(r['ownership']['usr/data'],['fixture'])
    def test_archive_uid_gid_are_observed_without_zero_assumption(self):
        nodes=a.archive_nodes(self.contract['packages'][0]['archive'],self.ident,a.Budget(time.monotonic()+5))
        self.assertEqual((nodes['usr/data']['uid'],nodes['usr/data']['gid']),(os.getuid(),os.getgid()))
        actual=a.tree_nodes(self.root,self.contract['tree_identity'],a.Budget(time.monotonic()+5));nodes['usr/data']['uid']+=1;nodes['usr/data']['gid']+=1
        r=a.compare({'fixture':nodes},actual,{'fixture':list(nodes)});self.assertEqual(r['status'],'FAIL-correspondence');self.assertEqual({p['field'] for p in r['problems'] if p['kind']=='METADATA'},{'uid','gid'})
    def test_same_size_modified_payload_and_mode_remain_fail(self):
        (self.root/'usr/data').write_bytes(b'changed same-size bytes\n');os.chmod(self.root/'usr/data',0o600)
        r=self.run_model();self.assertEqual(r['status'],'FAIL-correspondence');self.assertTrue(any(x['kind']=='CONTENT' for x in r['problems']));self.assertTrue(any(x['kind']=='METADATA' for x in r['problems']))
    def test_missing_generated_unexpected_and_special_nodes_are_not_exempt(self):
        (self.root/'usr/alias').unlink();(self.root/'generated.conf').write_bytes(b'generated');os.mkfifo(self.root/'pipe');self.update_tree()
        r=self.run_model();self.assertEqual(r['status'],'FAIL-correspondence');self.assertEqual({x['kind'] for x in r['problems']},{'MISSING','UNEXPECTED'})
    def test_type_substitution_never_follows_replacement_link(self):
        (self.root/'usr/data').unlink();(self.root/'usr/data').symlink_to('/etc/shadow');r=self.run_model();self.assertEqual(r['status'],'FAIL-correspondence');self.assertIn('TYPE',{x['kind'] for x in r['problems']})
    def test_hardlink_copy_and_outside_tree_links_are_mismatches(self):
        (self.root/'usr/hard').unlink();(self.root/'usr/hard').write_bytes((self.root/'usr/data').read_bytes());r=self.run_model();self.assertIn('HARDLINK_RELATION',{x['kind'] for x in r['problems']})
        os.link(self.root/'usr/data',self.base/'outside');r=self.run_model();self.assertIn('UNOBSERVED_HARDLINK',{x['kind'] for x in r['problems']})
    def test_unexpected_equal_file_hardlink_is_not_valid_content_equivalence(self):
        (self.root/'usr/alias').unlink();os.link(self.root/'usr/data',self.root/'usr/alias');r=self.run_model();self.assertIn('UNEXPECTED_HARDLINK',{x['kind'] for x in r['problems']})
    def test_symbolic_link_namespace_escape_cycle_missing_nondirectory(self):
        rows={'x':dict(type='symlink',target='x'),'data':dict(type='file'),'usr':dict(type='directory')}
        for target,state in [('../../outside','ESCAPE'),('x','CYCLE'),('none','MISSING'),('data/child','NON_DIRECTORY'),('none/../data','MISSING')]:
            self.assertEqual(a.resolve_link('alias',target,rows)[1],state)
        self.assertEqual(a.resolve_link('alias','/data',rows),('data','RESOLVED'))
    def test_tree_root_inode_replacement_and_parent_symlink_refuse(self):
        old=self.root;old.rename(self.base/'old');old.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'reference-identity'):self.run_model()
        p=self.base/'parent';p.symlink_to(self.base/'old')
        with self.assertRaises(OSError):a.tree_nodes(p/'usr',a.identity((self.base/'old/usr').stat()),a.Budget(time.monotonic()+5))
    def test_actual_midread_file_mutation_is_refused_and_fds_close(self):
        before=len(os.listdir('/proc/self/fd'));real=os.read;changed=[]
        def read(fd,n):
            b=real(fd,n)
            if b==b'tiny immutable payload\n' and not changed:changed.append(True);(self.root/'usr/data').write_bytes(b'tiny immutable payload\n')
            return b
        with patch.object(a.os,'read',side_effect=read),self.assertRaisesRegex(ValueError,'tree-read-drift'):a.tree_nodes(self.root,self.contract['tree_identity'],a.Budget(time.monotonic()+5))
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
    def test_actual_midscan_same_bytes_inode_replacement_refused(self):
        real=a.hashed;changed=[]
        def hashed(fd,size,budget,account=False):
            h=real(fd,size,budget,account)
            if account and not changed:
                changed.append(True);p=self.root/'usr/data';q=self.root/'usr/new';q.write_bytes(p.read_bytes());q.chmod(0o640);q.replace(p)
            return h
        with patch.object(a,'hashed',side_effect=hashed),self.assertRaisesRegex(ValueError,'tree-(?:read|node)-drift'):a.tree_nodes(self.root,self.contract['tree_identity'],a.Budget(time.monotonic()+5))
    def test_early_node_changed_after_later_read_refuses_final_snapshot(self):
        (self.root/'usr/z-last').write_bytes(b'last')
        self.members.append(('usr/z-last',tarfile.REGTYPE,b'last',None,0o644));self.contract=self.make_contract()
        real=a.hashed;calls=[]
        def hashed(fd,size,budget,account=False):
            h=real(fd,size,budget,account)
            if account and size==4 and not calls:
                calls.append(True);p=self.root/'usr/data';p.write_bytes(p.read_bytes())
            return h
        with patch.object(a,'hashed',side_effect=hashed),self.assertRaisesRegex(ValueError,'tree-final-drift'):a.tree_nodes(self.root,self.contract['tree_identity'],a.Budget(time.monotonic()+5))

    def test_changed_archive_bytes_inode_signature_and_auth_refuse(self):
        for name in ('archive','signature','authentication'):
            c=copy.deepcopy(self.contract);p=Path(c['packages'][0][name]['path']);old=p.read_bytes();q=p.with_suffix('.replacement');q.write_bytes(old);q.chmod(p.stat().st_mode&0o777);q.replace(p)
            with self.assertRaisesRegex(ValueError,'reference-identity'):self.run_model(c)
            self.contract=self.make_contract()
    def test_exact_full_version_and_arch_no_substitute(self):
        for key,value in [('version','1:1.0-2'),('arch','aarch64'),('name','substitute')]:
            ident={**self.ident,key:value};p=self.make_archive(identity=ident)
            with self.assertRaisesRegex(ValueError,'archive-tuple'):a.archive_nodes(ref(p),self.ident,a.Budget(time.monotonic()+5))
    def test_missing_duplicate_stale_ownership_refuse(self):
        for files in [['usr','usr/data'],['usr','usr','usr/data'],[n[0] for n in self.members]]:
            o={'schema_version':1,'scope':'inert-tree-fixture','packages':[{'identity':dict(self.ident,version='wrong') if len(files)==4 else self.ident,'files':files}]}
            p=self.base/'newownership';p.write_text(json.dumps(o));c=dict(self.contract,ownership=ref(p))
            with self.assertRaises(ValueError):self.run_model(c)
    def test_baseline_or_unknown_schema_fails_before_any_read(self):
        for change in [dict(scope='baseline-261'),dict(schema_version=True),dict(extra='unknown'),dict(packages=[])]:
            with patch.object(a,'read_reference',side_effect=AssertionError('no input read')),self.assertRaises(ValueError):self.run_model(dict(self.contract,**change))
    def test_invalid_reference_size_and_aggregate_refuse_before_any_read(self):
        for size in (-1,True,1.2,None,0,a.ARCHIVE+1):
            c=copy.deepcopy(self.contract);c['packages'][0]['archive']['size']=size
            with patch.object(a,'read_reference',side_effect=AssertionError('no input read')),self.assertRaises(ValueError):self.run_model(c)
        c=copy.deepcopy(self.contract);c['packages']=[]
        for i in range(8):
            p=copy.deepcopy(self.contract['packages'][0]);p['identity']['name']='fixture'+str(i);p['archive']['size']=a.ARCHIVE;p['archive']['identity'][6]=a.ARCHIVE;c['packages'].append(p)
        with patch.object(a,'read_reference',side_effect=AssertionError('no input read')),self.assertRaisesRegex(ValueError,'compressed-bound'):self.run_model(c)
    def test_expired_invalid_deadlines_and_node_file_report_caps(self):
        for end in (True,float('inf'),float('nan'),time.monotonic()-1):
            with self.assertRaises(ValueError):a.Budget(end)
        with patch.object(a,'NODES',2),self.assertRaises(ValueError):self.run_model()
        with patch.object(a,'FILE',1),self.assertRaises(ValueError):self.run_model()
        with patch.object(a,'REPORT',1),self.assertRaisesRegex(ValueError,'report-bound'):self.run_model()
    def test_decoded_aggregate_and_perarchive_caps_without_large_allocations(self):
        for key in ('DECODED','TOTAL_DECODED'):
            with patch.object(a,key,100),self.assertRaises(ValueError):self.run_model()
    def test_traversal_duplicate_unknown_type_bad_link_and_uid_headers_refuse(self):
        for member in [('usr/../escape',tarfile.REGTYPE,b'x',None,0o644),('usr/data',tarfile.REGTYPE,b'x',None,0o644),('fifo',tarfile.FIFOTYPE,b'',None,0o644),('link',tarfile.LNKTYPE,b'','../escape',0o644)]:
            p=self.make_archive(members=[*self.members,member])
            with self.assertRaises(ValueError):a.archive_nodes(ref(p),self.ident,a.Budget(time.monotonic()+5))
        for override in ({'uid':-1},{'gid':-1},{'uid':2**32}):
            p=self.make_archive(**override)
            with self.assertRaisesRegex(ValueError,'archive-member'):a.archive_nodes(ref(p),self.ident,a.Budget(time.monotonic()+5))
    def test_nonfinite_and_duplicate_json_and_noncanonical_reference_path_refuse(self):
        for raw in (b'{"unused":NaN}',b'{"unused":1e999}',b'{"x":1,"x":2}'):
            with self.assertRaises(ValueError):a.decode(raw)
        c=copy.deepcopy(self.contract);c['packages'][0]['archive']['path']=str(self.base)+'//fixture.pkg.tar.xz'
        with self.assertRaises(ValueError):self.run_model(c)
    def test_archive_symlink_hardlink_and_digest_pin_fail_without_payload_read(self):
        original=self.contract['packages'][0]['archive'];p=Path(original['path']);q=self.base/'link';q.symlink_to(p)
        changed={**original,'path':str(q)}
        with self.assertRaisesRegex(ValueError,'ordinary-node'):a.archive_nodes(changed,self.ident,a.Budget(time.monotonic()+5))
        q.unlink();os.link(p,q)
        with self.assertRaisesRegex(ValueError,'reference-hardlink'):a.archive_nodes({**original,'identity':a.identity(p.stat())},self.ident,a.Budget(time.monotonic()+5))
        q.unlink();bad={**ref(p),'sha256':'0'*64}
        with patch.object(a.lzma,'LZMAFile',side_effect=AssertionError('must not parse unhashed bytes')),self.assertRaisesRegex(ValueError,'archive-digest'):a.archive_nodes(bad,self.ident,a.Budget(time.monotonic()+5))

    def test_reference_changed_after_tree_observation_cannot_return_pass(self):
        real=a.tree_nodes
        def snapshot(*args):
            rows=real(*args);p=Path(self.contract['packages'][0]['signature']['path']);p.write_bytes(p.read_bytes());return rows
        with patch.object(a,'tree_nodes',side_effect=snapshot),self.assertRaisesRegex(ValueError,'reference-identity'):self.run_model()

    def test_comparison_deadline_and_truncated_archive_refuse(self):
        budget=a.Budget(time.monotonic()+5);budget.end=time.monotonic()-1
        with self.assertRaisesRegex(ValueError,'deadline'):a.compare({'fixture':{}},{},{'fixture':[]},budget)
        p=Path(self.contract['packages'][0]['archive']['path']);p.write_bytes(p.read_bytes()[:32])
        with self.assertRaises((EOFError,lzma.LZMAError,tarfile.TarError,ValueError)):a.archive_nodes(ref(p),self.ident,a.Budget(time.monotonic()+5))

    def test_cancellation_closes_read_descriptors_and_fifo_is_not_opened(self):
        before=len(os.listdir('/proc/self/fd'));real=a.os.read
        def interrupted(fd,n):raise KeyboardInterrupt()
        with patch.object(a.os,'read',side_effect=interrupted),self.assertRaises(KeyboardInterrupt):a.archive_nodes(self.contract['packages'][0]['archive'],self.ident,a.Budget(time.monotonic()+5))
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        os.mkfifo(self.root/'fifo');self.update_tree();rows=a.tree_nodes(self.root,self.contract['tree_identity'],a.Budget(time.monotonic()+5))
        self.assertEqual(rows['fifo']['type'],'fifo');self.assertNotIn('sha256',rows['fifo'])

    def test_complete261_retained_ownership_shape_and_exact_binding_controls(self):
        inv={'packages':[]};doc=dict(schema_version=1,kind='observed-image-local-file-ownership-metadata',inventory_sha256='1'*64,root_image_sha256='2'*64,packages=[],empty_filelist_packages=[],physical_target=False,hardware_accepted=False,installed_payload_verified=False)
        for i in range(261):
            name='fixture'+str(i);inv['packages'].append({'metadata':{'NAME':[name],'VERSION':['1.0-1'],'ARCH':['any']}})
            text='%FILES%\nusr/file'+str(i)+'\n';doc['packages'].append(dict(name=name,version='1.0-1',directory=name+'-1.0-1',bytes=len(text.encode()),sha256=hashlib.sha256(text.encode()).hexdigest(),text=text,fields={'FILES':['usr/file'+str(i)]},empty_filelist=False))
        self.assertEqual(len(a.image_ownership(doc,inv,'1'*64,'2'*64)),261)
        for mutation in ('incomplete','stale','substitute','text','fields','true'):
            d=copy.deepcopy(doc)
            if mutation=='incomplete':d['packages'].pop()
            elif mutation=='stale':d['root_image_sha256']='3'*64
            elif mutation=='substitute':d['packages'][0]['directory']='fixture0-1.0-2'
            elif mutation=='text':d['packages'][0]['text']+='changed'
            elif mutation=='fields':d['packages'][0]['fields']['FILES']=['substitute']
            else:d['installed_payload_verified']=True
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):a.image_ownership(d,inv,'1'*64,'2'*64)

    def test_comparison_metadata_types_and_unknown_content_are_not_coerced(self):
        nodes=a.archive_nodes(self.contract['packages'][0]['archive'],self.ident,a.Budget(time.monotonic()+5));actual=a.tree_nodes(self.root,self.contract['tree_identity'],a.Budget(time.monotonic()+5));owned={'fixture':list(nodes)}
        for field,value in [('uid',False),('gid',0.0),('mode',False),('bytes',-1),('sha256','invalid'),('extra','unbound')]:
            bad=copy.deepcopy(actual);bad['usr/data'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):a.compare({'fixture':nodes},bad,owned)

    def test_unused_nonfinite_metadata_and_combined_archive_tree_work_refuse(self):
        with self.assertRaisesRegex(ValueError,'nonfinite'):a.image_ownership({}, {'unused':float('nan')}, '1'*64,'2'*64)
        budget=a.Budget(time.monotonic()+5);budget.decoded=a.TOTAL_DECODED-1
        with self.assertRaisesRegex(ValueError,'combined-data-byte-bound'):a.tree_nodes(self.root,self.contract['tree_identity'],budget)

    def test_foreign_filesystem_refusal_without_mounting(self):
        real=a.os.stat
        def observed(name,**kwargs):
            v=real(name,**kwargs)
            if name=='data' and kwargs.get('follow_symlinks') is False:
                values=list(v);values[2]+=1;return os.stat_result(values)
            return v
        with patch.object(a.os,'stat',side_effect=observed),self.assertRaisesRegex(ValueError,'foreign-filesystem'):a.tree_nodes(self.root,self.contract['tree_identity'],a.Budget(time.monotonic()+5))


class CorrectionTests(unittest.TestCase):
    def test_reference_specials_no_readable_open_and_all_handles_disposed(self):
        for mode in (stat.S_IFCHR,stat.S_IFBLK,stat.S_IFIFO,stat.S_IFSOCK,stat.S_IFLNK):
            opened=[];closed=[]
            base=dict(st_dev=1,st_ino=1,st_mode=stat.S_IFDIR|0o700,st_nlink=1,st_uid=1000,st_gid=1000,st_size=0,st_mtime_ns=1,st_ctime_ns=1)
            directory=types.SimpleNamespace(**base);special=types.SimpleNamespace(**dict(base,st_mode=mode|0o600,st_ino=2))
            def op(name,flags,**kw):opened.append((str(name),flags));return len(opened)+100
            with patch.object(a.os,'open',side_effect=op),patch.object(a.os,'fstat',side_effect=lambda fd:special if fd==102 else directory),patch.object(a.os,'close',side_effect=closed.append),patch.object(a.os,'read') as rd,self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'ordinary-node'):
                with a.opened('/input',a.Budget(time.monotonic()+5)):pass
            self.assertEqual(opened[-1][0],'input');self.assertTrue(opened[-1][1]&os.O_PATH);self.assertFalse(any(x.startswith('/proc/self/fd/') for x,_ in opened));rd.assert_not_called();self.assertEqual(len(opened),len(closed))
    def test_tree_regular_to_device_no_readable_open_or_hash(self):
        from contextlib import contextmanager
        base=dict(st_dev=1,st_ino=1,st_mode=stat.S_IFDIR|0o700,st_nlink=1,st_uid=os.geteuid(),st_gid=os.getegid(),st_size=0,st_mtime_ns=1,st_ctime_ns=1)
        directory=types.SimpleNamespace(**base);regular=types.SimpleNamespace(**dict(base,st_mode=stat.S_IFREG|0o600,st_ino=2));special=types.SimpleNamespace(**dict(base,st_mode=stat.S_IFCHR|0o600,st_ino=3))
        @contextmanager
        def root(*args,**kw):yield 50,directory
        opened=[];closed=[]
        def op(name,flags,**kw):opened.append((str(name),flags));return 51
        with patch.object(a,'opened',side_effect=root),patch.object(a.os,'listdir',return_value=['data']),patch.object(a.os,'stat',return_value=regular),patch.object(a.os,'fstat',side_effect=lambda fd:directory if fd==50 else special),patch.object(a.os,'open',side_effect=op),patch.object(a.os,'close',side_effect=closed.append),patch.object(a,'hashed') as hashed,self.assertRaisesRegex(ValueError,'ordinary-node'):
            a.tree_nodes('/tree',a.identity(directory),a.Budget(time.monotonic()+5))
        self.assertEqual(opened,[('data',os.O_PATH|os.O_NOFOLLOW)]);self.assertEqual(closed,[51]);hashed.assert_not_called()
    def test_stale_identity_no_readable_open(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file';p.write_bytes(b'x');bad=a.identity(p.stat());bad[1]+=1;op=os.open;seen=[]
            def tracked(name,flags,*args,**kw):seen.append(str(name));return op(name,flags,*args,**kw)
            with patch.object(a.os,'open',side_effect=tracked),patch.object(a.os,'read') as rd,self.assertRaisesRegex(ValueError,'reference-identity'):
                with a.opened(p,a.Budget(time.monotonic()+5),bad):pass
            self.assertFalse(any(n.startswith('/proc/self/fd/') for n in seen));rd.assert_not_called()
    def test_name_replaced_before_readable_open_never_redirects_reads(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file';p.write_bytes(b'x');before=a.identity(p.stat());op=os.open;seen=[]
            def replaced(name,flags,*args,**kw):
                if str(name).startswith('/proc/self/fd/'):p.unlink();p.symlink_to('/etc/shadow')
                return op(name,flags,*args,**kw)
            with patch.object(a.os,'open',side_effect=replaced),patch.object(a.os,'read') as rd,self.assertRaisesRegex(ValueError,'reference-identity'):
                with a.opened(p,a.Budget(time.monotonic()+5),before):pass
            rd.assert_not_called()
    def hardlinks(self,count):
        digest=hashlib.sha256(b'x').hexdigest();expected={};actual={}
        for i in range(count):
            name=str(i);base=dict(mode=0o644,uid=0,gid=0)
            expected[name]=dict(base,type='file',bytes=1,sha256=digest) if i==0 else dict(base,type='hardlink',target=str(i-1))
            actual[name]=dict(base,type='file',bytes=1,sha256=digest,device=1,inode=1,nlink=count)
        return {'p':expected},actual,{'p':list(expected)}
    def test_shared_cutoff_checked_inside_both_hardlink_hops_and_group_names(self):
        import ast,sys
        tree=ast.parse(P.read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='compare')
        loops=[n for n in ast.walk(fn) if isinstance(n,ast.While) or isinstance(n,ast.For) and ast.unparse(n.iter)=='names']
        for loop in loops:
            clock=[0];hits=[]
            def trace(frame,event,arg):
                if event=='line' and frame.f_code.co_name=='compare' and frame.f_lineno==loop.lineno:clock[0]=3;hits.append(1)
                return trace
            with patch.object(a.time,'monotonic',side_effect=lambda:clock[0]):
                budget=a.Budget(2);sys.settrace(trace)
                try:
                    with self.subTest(line=loop.lineno),self.assertRaisesRegex(ValueError,'deadline'):a.compare(*self.hardlinks(32),budget)
                finally:sys.settrace(None)
                self.assertTrue(hits);self.assertEqual(budget.end,2)
    def test_matching_root_targets_resolve_without_waiving_escape(self):
        base=dict(mode=0o777,uid=0,gid=0)
        for target in ('/','..'):
            nodes={'usr':dict(type='directory',mode=0o755,uid=0,gid=0),'usr/link':dict(base,type='symlink',target=target)}
            actual={n:dict(row,device=1,inode=i+1,nlink=1) for i,(n,row) in enumerate(nodes.items())}
            r=a.compare({'p':nodes},actual,{'p':list(nodes)});self.assertEqual(r['status'],'PASS-inert-tree-correspondence');self.assertFalse(r['installed_payload_verified'])
        self.assertEqual(a.resolve_link('link','..',{}),(None,'ESCAPE'))
    def test_repeated_symlink_with_consumed_suffix_is_finite(self):
        rows={'d':dict(type='directory'),'x':dict(type='symlink',target='d')}
        self.assertEqual(a.resolve_link('alias','x/../x',rows),('d','RESOLVED'))
        self.assertEqual(a.resolve_link('alias','x/../x/../x',rows),('d','RESOLVED'))
    def test_true_cycles_and_hop_bound_are_distinct(self):
        rows={'x':dict(type='symlink',target='y'),'y':dict(type='symlink',target='x')}
        self.assertEqual(a.resolve_link('alias','x',rows)[1],'CYCLE')
        expanding={'x':dict(type='symlink',target='x/d')}
        self.assertEqual(a.resolve_link('alias','x',expanding)[1],'HOP_LIMIT')
        chain={str(i):dict(type='symlink',target=str(i+1)) for i in range(40)};chain['40']=dict(type='directory')
        self.assertEqual(a.resolve_link('alias','0',chain),('40','RESOLVED'));chain['40']=dict(type='symlink',target='41');chain['41']=dict(type='directory')
        self.assertEqual(a.resolve_link('alias','0',chain)[1],'HOP_LIMIT')
    def test_link_work_uses_same_caller_cutoff(self):
        clock=[0];budget=a.Budget(time.monotonic()+5)
        def check():clock[0]+=1;a.need(clock[0]<3,'deadline')
        budget.check=check
        with self.assertRaisesRegex(ValueError,'deadline'):a.resolve_link('link','a/b/c',{'a':dict(type='directory'),'a/b':dict(type='directory'),'a/b/c':dict(type='file')},budget)


class CleanupTests(unittest.TestCase):
    def test_archive_decode_counts_prior_tree_bytes_and_keeps_overshoot_debt(self):
        for payload,refused in ((b'x',False),(b'xx',True)):
            budget=a.Budget(time.monotonic()+5);budget.decoded=a.TOTAL_DECODED-3;budget.tree_bytes=2
            stream=types.SimpleNamespace(read=lambda n:payload)
            with patch.object(stream,'read',return_value=payload) as read,self.subTest(payload=payload):
                counted=a.Counted(stream,budget)
                if refused:
                    with self.assertRaisesRegex(ValueError,'combined-data-byte-bound'):counted.read(4)
                else:self.assertEqual(counted.read(4),payload)
                read.assert_called_once_with(2)
                self.assertEqual(counted.count,len(payload));self.assertEqual(budget.decoded,a.TOTAL_DECODED-3+len(payload));self.assertEqual(budget.tree_bytes,2)

    def test_archive_decode_refuses_existing_combined_debt_before_read(self):
        budget=a.Budget(time.monotonic()+5);budget.tree_bytes=a.TOTAL_DECODED+1
        stream=types.SimpleNamespace(read=lambda n:b'')
        with patch.object(stream,'read') as read,self.assertRaisesRegex(ValueError,'combined-data-byte-bound'):a.Counted(stream,budget).read(1)
        read.assert_not_called();self.assertEqual(budget.tree_bytes,a.TOTAL_DECODED+1);self.assertEqual(budget.decoded,0)

    def readable(self):
        info=types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o600,
            st_nlink=1,st_uid=1000,st_gid=1000,st_size=1,st_mtime_ns=1,st_ctime_ns=1)
        opened=[]
        def opening(*args,**kwargs):opened.append(args);return 100+len(opened)
        return info,opened,opening

    def test_cancel_after_readable_close_still_disposes_binding(self):
        info,opened,opening=self.readable();closed=[];cancel=KeyboardInterrupt('after-close')
        def closing(fd):
            closed.append(fd)
            if fd==102:raise cancel
        with patch.object(a.os,'open',side_effect=opening),patch.object(a.os,'fstat',return_value=info),patch.object(a.os,'stat',return_value=info),patch.object(a.os,'close',side_effect=closing),patch.object(a.signal,'pthread_sigmask',return_value=set()),self.assertRaises(KeyboardInterrupt) as caught:
            with a.readable_at(50,'file',a.Budget(time.monotonic()+5),a.identity(info)):pass
        self.assertIs(caught.exception,cancel);self.assertEqual(closed,[102,101]);self.assertEqual(len(opened),2)

    def test_business_cause_survives_cleanup_cancel_and_close_fault(self):
        info,opened,opening=self.readable();closed=[];original=ValueError('original-business')
        def closing(fd):
            closed.append(fd)
            if fd==102:raise KeyboardInterrupt('cleanup-cancel')
            raise OSError('binding-close-fault')
        with patch.object(a.os,'open',side_effect=opening),patch.object(a.os,'fstat',return_value=info),patch.object(a.os,'close',side_effect=closing),patch.object(a.signal,'pthread_sigmask',return_value=set()),self.assertRaises(ValueError) as caught:
            with a.readable_at(50,'file',a.Budget(time.monotonic()+5),a.identity(info)):raise original
        self.assertIs(caught.exception,original);self.assertEqual(closed,[102,101])

    def test_first_cleanup_fault_survives_mask_restoration_cancel(self):
        original=OSError('first-close');closed=[];previous={signal.SIGUSR1}
        def closing(fd):
            closed.append(fd)
            if fd==2:raise original
        def masking(how,values):
            if how==signal.SIG_SETMASK:
                self.assertEqual(values,previous);raise KeyboardInterrupt('restoration-cancel')
            self.assertEqual(values,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM});return previous
        with patch.object(a.os,'close',side_effect=closing),patch.object(a.signal,'pthread_sigmask',side_effect=masking),self.assertRaises(OSError) as caught:a.close_owned((2,1))
        self.assertIs(caught.exception,original);self.assertEqual(closed,[2,1])

    def test_ancestor_close_cancel_still_attempts_all_owned_handles(self):
        info,opened,opening=self.readable();directory=types.SimpleNamespace(**dict(vars(info),st_mode=stat.S_IFDIR|0o700));closed=[];cancel=KeyboardInterrupt('ancestor-close')
        def closing(fd):
            closed.append(fd)
            if fd==103:raise cancel
        with patch.object(a.os,'open',side_effect=opening),patch.object(a.os,'fstat',side_effect=lambda fd:info if fd>=104 else directory),patch.object(a.os,'stat',side_effect=lambda name,**kw:info if name=='file' else directory),patch.object(a.os,'close',side_effect=closing),patch.object(a.signal,'pthread_sigmask',return_value=set()),self.assertRaises(KeyboardInterrupt) as caught:
            with a.opened('/one/two/file',a.Budget(time.monotonic()+5),a.identity(info)):pass
        self.assertIs(caught.exception,cancel);self.assertEqual(closed,[105,104,103,102,101])

    def test_known_signals_deliver_only_after_two_fd_cleanup(self):
        real_close=os.close
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM):
            closed=[];delivered=[];cancel=KeyboardInterrupt('queued-signal')
            def handler(number,frame):delivered.append((number,list(closed)));raise cancel
            def closing(fd):
                real_close(fd);closed.append(fd)
                if len(closed)==1:
                    signal.raise_signal(sig)
                    self.assertFalse(delivered)
            previous_handler=signal.signal(sig,handler)
            previous_mask=signal.pthread_sigmask(signal.SIG_UNBLOCK,{sig})
            try:
                with self.subTest(signal=sig),tempfile.TemporaryDirectory() as temp:
                    file=Path(temp)/'file';file.write_bytes(b'x');parent=os.open(temp,os.O_RDONLY|os.O_DIRECTORY)
                    try:
                        with patch.object(a.os,'close',side_effect=closing),self.assertRaises(KeyboardInterrupt) as caught:
                            with a.readable_at(parent,'file',a.Budget(time.monotonic()+5),a.identity(file.stat())):pass
                        self.assertIs(caught.exception,cancel);self.assertEqual(len(closed),2);self.assertEqual(delivered,[(sig,closed)])
                        for fd in closed:
                            with self.assertRaises(OSError):os.fstat(fd)
                    finally:real_close(parent)
            finally:
                signal.signal(sig,previous_handler);signal.pthread_sigmask(signal.SIG_SETMASK,previous_mask)


if __name__=='__main__':unittest.main()
