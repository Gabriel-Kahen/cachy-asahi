# SPDX-License-Identifier: MIT
import hashlib
import io
import os
from pathlib import Path
import signal
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import installed_payload_image_reader as r

CORE_PATH=Path(__file__).with_name('installed_payload_correspondence.py').absolute()
CORE=r.load_core(CORE_PATH)


def work(core=CORE,end=None):
    end=time.monotonic()+60 if end is None else end
    with patch.object(r,'load_core',return_value=core):return r.WorkLedger(CORE_PATH,end)


def stat_output(inode,kind='regular',mode=0o644,uid=0,gid=0,size=1,links=1,target=None):
    s=f'Inode: {inode}   Type: {kind}    Mode:  0{mode:03o}   Flags: 0x0\nGeneration: 1    Version: 0x00000000:00000000\nUser:     {uid}   Group:     {gid}   Project:     0   Size: {size}\nLinks: {links}   Blockcount: 0\n'
    if target is not None:s+=f'Fast link dest: "{target}"\n'
    return s.encode()


def ls(entries):
    return ''.join(f'/{inode}/{mode:o}/0/0/{name}/{size}/\n' for name,inode,mode,size in entries).encode()


class Model:
    def __init__(self):
        self.core=CORE;self.budget=CORE.Budget(time.monotonic()+60);self.calls=[];self.changed=None
        self.stats={2:stat_output(2,'directory',0o755,size=1024,links=2),11:stat_output(11,size=1,links=2),12:stat_output(12,'symlink',0o777,size=1,target='a'),13:stat_output(13,'symlink',0o777,size=1)}
        self.listing=ls([('.',2,0o40755,''),('..',2,0o40755,''),('a',11,0o100644,1),('b',11,0o100644,1),('c',12,0o120777,1),('long',13,0o120777,1)])
    def call(self,kind,inode,size=0,link=False):
        self.calls.append((kind,inode,size,link));r.request(kind,inode)
        if self.changed:self.changed(self,kind,inode)
        if kind=='stat':return dict(data=self.stats[inode])
        if kind=='ls':return dict(data=self.listing)
        return dict(data=b'',bytes=size,sha256=hashlib.sha256(b'a').hexdigest(),**({'link_data':b'a'} if link else {}))


class Stream:
    def __init__(self,chunks):self.chunks=list(chunks);self.closed=False
    def read1(self,n):return self.chunks.pop(0) if self.chunks else b''
    def close(self):self.closed=True


class Process:
    pid=987654321
    def __init__(self,chunks=(),errors=(b'debugfs 1.47.4 (29-Mar-2025)\n',),code=0):
        self.stdout=Stream(chunks);self.stderr=Stream(errors);self.code=code;self.waited=0;self.running=False
    def wait(self,timeout):self.waited+=1;self.running=False;return self.code
    def poll(self):return None if self.running else self.code


class Selector:
    def __init__(self):self.items={}
    def register(self,stream,event,label):self.items[stream]=types.SimpleNamespace(fileobj=stream,data=label)
    def unregister(self,stream):del self.items[stream]
    def get_map(self):return self.items
    def select(self,timeout):return [(k,1) for k in list(self.items.values())]
    def __enter__(self):return self
    def __exit__(self,*args):pass


class ReaderTests(unittest.TestCase):
    def process(self,p,kind='cat',size=1,ledger=None,**kwargs):
        ledger=work() if ledger is None else ledger;owner=object();ledger.acquire(owner)
        try:
            with patch.object(r.selectors,'DefaultSelector',Selector):
                return r.checked_process(('mock',),'/mock',(9,10),kind,size,ledger.end,popen=lambda *a,**k:p,ledger=ledger,owner=owner,**kwargs)
        finally:r.dispose((lambda:ledger.release(owner),))
    def test_held_source_loader(self):
        self.assertEqual(r.load_core(CORE_PATH).FILE,512*1024**2)
    def test_wrong_source_same_mode_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'core.py';p.write_bytes(CORE_PATH.read_bytes()+b'\n');p.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'core-source'):r.load_core(p)
    def test_source_symlink_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'core.py';p.symlink_to(CORE_PATH)
            with self.assertRaisesRegex(ValueError,'ordinary-input-before-read'):r.load_core(p)
    def test_closed_inodes_not_names(self):
        self.assertEqual(r.request('ls',11),'ls -p <11>');self.assertEqual(r.request('cat',12),'cat <12>')
        for kind,inode in [('dump',1),('cat',True),('cat',0),('stat','2;quit'),('stat',2**32)]:
            with self.subTest(kind=kind,inode=inode),self.assertRaises(ValueError):r.request(kind,inode)
    def test_spaces_commas_brackets_are_data(self):
        d=r.listing(ls([('.',2,0o40755,''),('..',2,0o40755,''),('Librem 5.conf',11,0o100644,1),('a,b',12,0o100644,1),('[',13,0o100644,1),('a";quit',14,0o100644,1)]))
        self.assertIn('a";quit',d)
    def test_unsafe_listing_delimiter_control_duplicate(self):
        good=ls([('.',2,0o40755,''),('..',2,0o40755,''),('a',11,0o100644,1)])
        for raw in [good.replace(b'/a/',b'/a/b/'),good.replace(b'/a/',b'/a\x00/'),good+good,good.replace(b'/11/',b'/-11/'),good.replace(b'/100644/',b'/888/'),good.replace(b'/1/',b'/True/'),b'']:
            with self.subTest(raw=raw[:60]),self.assertRaises((ValueError,UnicodeError)):r.listing(raw)
    def test_stat_identity_and_fast_symlink(self):
        d=r.inode_stat(stat_output(3,'symlink',0o777,size=5,target='../aa'),3);self.assertEqual(d['target'],'../aa')
    def test_stat_duplicate_missing_overflow_type_size(self):
        good=stat_output(11)
        for raw in [good+good,good.replace(b'Links: 1',b'Links: 0'),good.replace(b'User:     0',b'User:     -1'),good.replace(b'Size: 1',b'Size: 536870913'),good.replace(b'Type: regular',b'Type: unknown'),good.replace(b'Inode: 11',b'Inode: 12'),good+b'\0']:
            with self.subTest(raw=raw[:40]),self.assertRaises(ValueError):r.inode_stat(raw,11)
    def test_ambiguous_link_print_refuses(self):
        for target in ['a"b','a\\b','']:
            with self.subTest(target=target),self.assertRaises(ValueError):r.inode_stat(stat_output(3,'symlink',0o777,size=len(target),target=target),3)
    def test_observe_complete_hardlinks_both_symlink_forms(self):
        m=Model();rows=r.observe(m);self.assertEqual(rows['a']['inode'],rows['b']['inode']);self.assertEqual(rows['long']['target'],'a')
        self.assertTrue(all(type(i) is int for _,i,_,_ in m.calls));self.assertFalse(any(n in str(m.calls) for n in ('long','quit')))
        expected={'package':{n:{k:v for k,v in row.items() if k not in ('device','inode','nlink')} for n,row in rows.items()}}
        expected['package']['b']={'type':'hardlink','mode':0o644,'uid':0,'gid':0,'target':'a'}
        out=r.compare_image(Model(),expected,{'package':list(rows)})
        self.assertEqual(out['status'],'PASS-inert-tree-correspondence');self.assertIs(out['installed_payload_verified'],False);self.assertIs(out['hardware_accepted'],False)
    def test_missing_listing_stat_binding_refuses(self):
        for raw in [stat_output(11,uid=2),stat_output(11,size=2),stat_output(11,'directory',0o644,size=1)]:
            m=Model();m.stats[11]=raw
            with self.subTest(raw=raw[:60]),self.assertRaisesRegex(ValueError,'image-listing-stat'):r.observe(m)
    def test_in_place_inode_after_cat_refuses(self):
        m=Model()
        def change(m,k,i):
            if k=='cat' and i==11:m.stats[11]=stat_output(11,uid=1)
        m.changed=change
        with self.assertRaisesRegex(ValueError,'image-inode-drift'):r.observe(m)
    def test_directory_listing_drift_refuses(self):
        m=Model()
        def change(m,k,i):
            if k=='ls' and sum(c[0]=='ls' for c in m.calls)>1:m.listing=m.listing.replace(b'/a/',b'/z/')
        m.changed=change
        with self.assertRaisesRegex(ValueError,'image-directory-drift'):r.observe(m)
    def test_cycles_root_parent_link(self):
        for raw in [ls([('.',2,0o40755,''),('..',3,0o40755,'')]),ls([('.',2,0o40755,''),('..',2,0o40755,''),('cycle',2,0o40755,'')])]:
            m=Model();m.listing=raw
            with self.subTest(raw=raw),self.assertRaises(ValueError):r.observe(m)
    def test_special_node_not_opened(self):
        m=Model();m.listing=ls([('.',2,0o40755,''),('..',2,0o40755,''),('fifo',14,0o10600,0)]);m.stats[14]=stat_output(14,'FIFO',0o600,size=0)
        self.assertEqual(r.observe(m)['fifo']['type'],'fifo');self.assertFalse(any(k=='cat' for k,*_ in m.calls))
    def test_long_link_missing_bytes_refuses(self):
        m=Model();call=m.call
        def broken(k,i,size=0,link=False):
            result=call(k,i,size,link);result.pop('link_data',None);return result
        m.call=broken
        with self.assertRaisesRegex(ValueError,'image-long-symlink-unobserved'):r.observe(m)
    def test_bad_fastlink_or_content_size_not_promoted(self):
        m=Model();call=m.call
        def broken(k,i,size=0,link=False):
            result=call(k,i,size,link)
            if k=='cat' and i==11:result['bytes']=0
            return result
        m.call=broken
        with self.assertRaisesRegex(ValueError,'image-content-size'):r.observe(m)
    def test_large_file_hash_not_retained(self):
        p=Process([b'x'*r.MIB]*9);d=self.process(p,size=9*r.MIB)
        self.assertEqual(d['bytes'],9*r.MIB);self.assertEqual(d['data'],b'');self.assertNotIn('link_data',d)
        self.assertEqual(d['sha256'],hashlib.sha256(b'x'*(9*r.MIB)).hexdigest());self.assertTrue(p.stdout.closed and p.stderr.closed)
    def test_link_bytes_only_bounded(self):
        p=Process([b'hello']);self.assertEqual(self.process(p,size=5,retain_link=True)['link_data'],b'hello')
        with self.assertRaises(ValueError):self.process(Process(),size=4097,retain_link=True)
    def test_partial_and_overlong_content_fail_closed(self):
        for chunks in [[b''],[b'aa']]:
            p=Process(chunks)
            with self.subTest(chunks=chunks),self.assertRaises(ValueError):self.process(p)
            self.assertTrue(p.stdout.closed and p.stderr.closed)
    def test_diagnostic_and_actual_return_refuse(self):
        for p in [Process([b'a'],errors=(b'wrong\n',)),Process([b'a'],code=1),Process([b'a'],errors=(b'e'*(r.STDERR+1),))]:
            with self.assertRaises(ValueError):self.process(p)
    def test_metadata_and_remaining_output_bounds(self):
        with self.assertRaisesRegex(ValueError,'stdout-bound'):self.process(Process([b'aa']),kind='stat',output_budget=1)
        with self.assertRaisesRegex(ValueError,'process-output-budget'):self.process(Process(),size=2,output_budget=1)
    def test_expired_and_cleanup_reserve_no_spawn(self):
        for deadline in [time.monotonic()-1,time.monotonic()+1,float('nan'),True,time.monotonic()+1201]:
            ledger=work();owner=object();ledger.acquire(owner)
            with patch.object(r,'subprocess') as sub,self.subTest(deadline=deadline),self.assertRaises(ValueError):
                r.checked_process(('mock',),'/mock',(), 'cat',1,deadline,popen=sub.Popen,ledger=ledger,owner=owner)
            sub.Popen.assert_not_called()
            ledger.release(owner)
    def test_cancel_during_spawn_restoration_reaps_mock(self):
        p=Process([b'a']);p.running=True;old=signal.getsignal(signal.SIGTERM);ledger=work();owner=object();ledger.acquire(owner)
        def stop(*_):raise KeyboardInterrupt()
        def launch(*args,**kwargs):signal.raise_signal(signal.SIGTERM);return p
        try:
            signal.signal(signal.SIGTERM,stop)
            with patch.object(r.os,'killpg') as kill,self.assertRaises(KeyboardInterrupt):
                r.checked_process(('mock',),'/mock',(), 'cat',1,ledger.end,popen=launch,ledger=ledger,owner=owner)
            kill.assert_called_once_with(p.pid,signal.SIGTERM);self.assertGreater(p.waited,0);self.assertTrue(p.stdout.closed and p.stderr.closed)
        finally:signal.signal(signal.SIGTERM,old);ledger.release(owner)
    def test_actor_selection_refuses_before_inputs(self):
        with patch.object(CORE,'read_reference') as rd,self.assertRaisesRegex(ValueError,'image-actor-not-selected'):
            r.Tool(CORE,{}, {}, time.monotonic()+60)
        rd.assert_not_called()
    def test_time_node_bound_no_actor(self):
        m=Model();m.budget.end=time.monotonic()-1
        with self.assertRaisesRegex(ValueError,'deadline'):r.observe(m)
        self.assertEqual(m.calls,[])
        m=Model();m.budget.nodes=r.NODES
        with self.assertRaisesRegex(ValueError,'node-bound'):r.observe(m)
    def test_tool_prechecks_and_total_cap_without_actor(self):
        t=object.__new__(r.Tool);t.ledger=work();t.ledger.acquire(t);t.core=CORE;t.budget=t.ledger.budget;t.calls=t.bytes=t.output_bytes=0;t.executable_fd=9;t.image_fd=10;t.check_pins=lambda:None
        def observed(*args,**kwargs):
            kwargs['ledger'].claim_call(kwargs['owner']);kwargs['ledger'].charge(1,kwargs['owner']);return dict(data=b'',bytes=1,sha256='0'*64,returncode=0)
        with patch.object(r,'checked_process',side_effect=observed) as p:
            t.call('cat',11,1);self.assertEqual(p.call_args.args[0],('/usr/bin/debugfs','-R','cat <11>','/proc/self/fd/10'))
            t.budget.decoded=r.TOTAL-1
            with self.assertRaisesRegex(ValueError,'image-content-total'):t.call('cat',11,1)
            self.assertEqual(p.call_count,1)
        t.ledger.release(t)

    def test_source_absolute_expired_refuses_before_read(self):
        with patch.object(r.os,'open') as op,self.assertRaisesRegex(ValueError,'source-deadline'):
            r.load_core(CORE_PATH,time.monotonic()-1)
        op.assert_not_called()
    def test_production_entry_explicit_selection(self):
        with patch.object(r,'load_core') as load,self.assertRaisesRegex(ValueError,'image-actor-not-selected'):
            r.open_selected(CORE_PATH,{}, {},time.monotonic()+60)
        load.assert_not_called()
    def test_same_absolute_cutoff_loader(self):
        ledger=work();end=ledger.end
        with patch.object(r,'load_core') as load,patch.object(r,'Tool') as tool:
            r.open_selected(CORE_PATH,{}, {},end,True,ledger=ledger)
            load.assert_not_called();self.assertEqual(tool.call_args.args[-1],end)
            self.assertIs(tool.call_args.args[0],ledger.core);self.assertIs(tool.call_args.kwargs['ledger'],ledger)
    def test_snapshot_complete_return_only_after_close(self):
        ledger=work()
        class Holder:
            def __enter__(self):return object()
            def __exit__(self,*args):raise ValueError('final drift')
        with patch.object(r,'open_selected',return_value=Holder()),patch.object(r,'compare_image',return_value={'status':'PASS'}) as cp,self.assertRaisesRegex(ValueError,'final drift'):
            r.run_selected(CORE_PATH,{}, {'sha256':r.IMAGE_SHA},{},{},ledger.end,True,ledger=ledger)
        cp.assert_called_once()
    def test_guarded_process_fixed_args_clean_environment(self):
        p=Process([b'a']);factory=unittest.mock.Mock(return_value=p);ledger=work();owner=object();ledger.acquire(owner)
        with patch.object(r.selectors,'DefaultSelector',Selector):
            r.checked_process(('mock',),'/mock',(9,10),'cat',1,ledger.end,popen=factory,ledger=ledger,owner=owner)
        ledger.release(owner)
        k=factory.call_args.kwargs
        self.assertEqual(k['env'],{'LC_ALL':'C','TZ':'UTC'});self.assertTrue(k['close_fds'] and k['start_new_session']);self.assertNotIn('shell',k)
        self.assertEqual(k['pass_fds'],(9,10));self.assertEqual(k['executable'],'/mock')
    def test_constructor_wrong_contract_refuses_before_read(self):
        ledger=work()
        with patch.object(CORE,'read_reference') as rd,self.assertRaisesRegex(ValueError,'tool-contract'):
            r.Tool(CORE,{'sha256':'0'*64},{},ledger.end,True,ledger=ledger)
        rd.assert_not_called()
    def test_close_always_disposes_even_final_hash_failure(self):
        t=object.__new__(r.Tool);t.ledger=work();t.ledger.acquire(t);t.check_pins=lambda:None;t.fds={};t.image_fd=9;t.budget=t.ledger.budget;t.core=CORE;t.stack=unittest.mock.Mock()
        with patch.object(r.os,'lseek'),patch.object(CORE,'hashed',return_value='0'*64),self.assertRaisesRegex(ValueError,'image-final-digest'):t.close()
        t.stack.close.assert_called_once()
    def test_zero_and_large_sizes_finite_no_allocation(self):
        self.assertEqual(self.process(Process(),size=0)['bytes'],0)
        for size in [True,-1,512*r.MIB+1,1.1]:
            with self.subTest(size=size),self.assertRaises(ValueError):self.process(Process(),size=size)
        with self.assertRaisesRegex(ValueError,'cat-size'):self.process(Process(),size=512*r.MIB)
    def test_optional_project_field_and_device(self):
        d=r.inode_stat(stat_output(1).replace(b'   Project:     0',b''),1);self.assertEqual(d['uid'],0)
        raw=stat_output(3,'character special',size=0)+b'Device major/minor number: 01:03 (hex 01:03)\n'
        self.assertEqual(r.inode_stat(raw,3)['rdev'],os.makedev(1,3))
    def test_poststat_generation_and_metadata_drift(self):
        m=Model()
        def change(m,k,i):
            if k=='cat' and i==11:m.stats[11]=m.stats[11].replace(b'Generation: 1',b'Generation: 2')
        m.changed=change
        with self.assertRaisesRegex(ValueError,'image-inode-drift'):r.observe(m)

    def test_tool_constructor_finalization_private_mock_handles(self):
        from contextlib import contextmanager
        import json
        ident=[1,1,0o100644,1,0,0,1,1,1]
        ref=dict(path='/MODELED/tool',size=1,sha256='1'*64,identity=ident)
        contract=dict(schema_version=2,approved=False,actors='NOT RUN',binary_and_recursive_DT_NEEDED={'/usr/bin/debugfs':dict(reference=ref,links=[])},interpreter_links=[])
        active=[];closed=[];fds={}
        @contextmanager
        def opened(path,budget,expected):
            fd=len(fds)+100;fds[fd]=path;active.append(path)
            try:yield fd,None
            finally:closed.append(path)
        core=types.SimpleNamespace(Budget=CORE.Budget,decode=CORE.decode,read_reference=lambda *a:json.dumps(contract).encode(),reference=CORE.reference,opened=opened,
            hashed=lambda fd,size,budget:r.IMAGE_SHA if fds[fd]=='/MODELED/image' else '1'*64)
        image=dict(path='/MODELED/image',size=r.IMAGE_SIZE,sha256=r.IMAGE_SHA,identity=[1,2,0o100644,1,0,0,r.IMAGE_SIZE,1,1])
        ledger=work(core)
        with patch.object(r.os,'lseek'),patch.object(r,'held_regular',side_effect=opened),patch.object(r,'read_reference',side_effect=core.read_reference):
            t=r.Tool(core,{'sha256':r.TOOL_CONTRACT_SHA},image,ledger.end,True,ledger=ledger)
            self.assertEqual(closed,[]);t.close()
        self.assertEqual(sorted(active),sorted(closed));self.assertEqual(len(closed),3)
    def test_final_deadline_never_promotes(self):
        clock=[0]
        class Holder:
            def __enter__(self):return object()
            def __exit__(self,*args):clock[0]=61
        with patch.object(r.time,'monotonic',side_effect=lambda:clock[0]):
            ledger=work(end=60)
            with patch.object(r,'open_selected',return_value=Holder()),patch.object(r,'compare_image',return_value={}),self.assertRaisesRegex(ValueError,'final-deadline'):
                r.run_selected(CORE_PATH,{}, {},{},{},60,True,ledger=ledger)
    def test_process_read_refusal_reaps_and_closes(self):
        p=Process([b'aa']);p.running=True
        with patch.object(r.os,'killpg') as kill,self.assertRaisesRegex(ValueError,'stdout-bound'):self.process(p)
        kill.assert_called_once_with(p.pid,signal.SIGTERM);self.assertTrue(p.stdout.closed and p.stderr.closed)
    def test_deadline_during_output_reaps_not_return(self):
        p=Process([b'a']);p.running=True;clock=[0];read=p.stdout.read1
        def advance(n):clock[0]=19;return read(n)
        p.stdout.read1=advance
        with patch.object(r.time,'monotonic',side_effect=lambda:clock[0]),patch.object(r.os,'killpg') as kill,self.assertRaisesRegex(ValueError,'process-deadline'):
            self.process(p)
        kill.assert_called_once_with(p.pid,signal.SIGTERM);self.assertTrue(p.stdout.closed and p.stderr.closed)

    def test_fifo_or_symlink_never_readable_open(self):
        with tempfile.TemporaryDirectory() as t:
            for name in ('fifo','link'):
                p=Path(t)/name
                if name=='fifo':os.mkfifo(p)
                else:p.symlink_to('/etc/shadow')
                op=r.os.open;seen=[]
                def tracked(path,flags,*a,**kw):seen.append((str(path),flags));return op(path,flags,*a,**kw)
                with patch.object(r.os,'open',side_effect=tracked),self.subTest(name=name),self.assertRaisesRegex(ValueError,'ordinary-input-before-read'):
                    with r.held_regular(p,CORE.Budget(time.monotonic()+60)):pass
                self.assertFalse(any(p.startswith('/proc/self/fd/') for p,_ in seen))
    def test_pinned_file_replaced_device_model_no_readable_open(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file';p.write_bytes(b'x');original=os.fstat;seen=[];op=os.open
            def stat_fd(fd):
                s=original(fd)
                if s.st_ino==p.stat().st_ino:return types.SimpleNamespace(st_mode=stat.S_IFCHR,st_nlink=1)
                return s
            def tracked(path,flags,*a,**kw):seen.append(str(path));return op(path,flags,*a,**kw)
            with patch.object(r.os,'fstat',side_effect=stat_fd),patch.object(r.os,'open',side_effect=tracked),self.assertRaisesRegex(ValueError,'ordinary-input-before-read'):
                with r.held_regular(p,CORE.Budget(time.monotonic()+60)):pass
            self.assertFalse(any(p.startswith('/proc/self/fd/') for p in seen))
    def test_pinned_read_survives_name_replacement_then_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file';p.write_bytes(b'x');before=CORE.identity(p.stat());op=os.open;observed=[]
            def replace(path,flags,*a,**kw):
                if str(path).startswith('/proc/self/fd/'):
                    p.unlink();p.symlink_to('/etc/shadow')
                return op(path,flags,*a,**kw)
            with patch.object(r.os,'open',side_effect=replace),self.assertRaisesRegex(ValueError,'input-readable-binding'):
                with r.held_regular(p,CORE.Budget(time.monotonic()+60),before) as (fd,_):observed.append(os.read(fd,1))
            self.assertEqual(observed,[])
    def test_bound_reference_hash_and_stale_refuse(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file';p.write_bytes(b'x');ref=dict(path=str(p),size=1,sha256=hashlib.sha256(b'x').hexdigest(),identity=CORE.identity(p.stat()))
            self.assertEqual(r.read_reference(CORE,ref,10,CORE.Budget(time.monotonic()+60)),b'x')
            ref['identity'][1]+=1
            with patch.object(r.os,'read') as rd,self.assertRaisesRegex(ValueError,'input-identity-before-read'):r.read_reference(CORE,ref,10,CORE.Budget(time.monotonic()+60))
            rd.assert_not_called()

    def test_hardlink_preflight_deadline_checks_each_hop(self):
        clock=types.SimpleNamespace(count=0)
        def check():
            clock.count+=1
            if clock.count>8:raise ValueError('deadline')
        core=types.SimpleNamespace(compare=unittest.mock.Mock());t=types.SimpleNamespace(core=core,budget=types.SimpleNamespace(check=check))
        expected={'p':{str(i):dict(type='hardlink',target=str(i+1)) for i in range(5)}}
        with patch.object(r,'observe',return_value={}),self.assertRaisesRegex(ValueError,'deadline'):r.compare_image(t,expected,{})
        core.compare.assert_not_called()
    def test_cross_package_cycle_preflight_refuses(self):
        core=types.SimpleNamespace(compare=unittest.mock.Mock());t=types.SimpleNamespace(core=core,budget=CORE.Budget(time.monotonic()+60))
        with patch.object(r,'observe',return_value={}),self.assertRaisesRegex(ValueError,'hardlink-cycle'):
            r.compare_image(t,{'p':{'a':dict(type='hardlink',target='b')},'q':{'b':dict(type='hardlink',target='a')}},{})
        core.compare.assert_not_called()

    def test_first_pipe_close_fault_preserves_failure_and_attempts_both_pipes(self):
        for error in (KeyboardInterrupt('close cancel'),OSError(5,'close failed')):
            p=Process([b'aa']);p.running=True;ledger=work();attempts=[]
            stdout=p.stdout.close;stderr=p.stderr.close
            def first():attempts.append('stdout');stdout();raise error
            def second():attempts.append('stderr');stderr()
            p.stdout.close=first;p.stderr.close=second
            with self.subTest(error=type(error).__name__),patch.object(r.os,'killpg') as kill,self.assertRaisesRegex(ValueError,'stdout-bound') as caught:
                self.process(p,ledger=ledger)
            self.assertEqual(attempts,['stdout','stderr']);self.assertTrue(p.stdout.closed and p.stderr.closed)
            self.assertGreater(p.waited,0);kill.assert_called_once_with(p.pid,signal.SIGTERM)
            self.assertTrue(any(type(error).__name__ in note for note in caught.exception.__notes__))
            self.assertEqual(ledger.budget.tree_bytes,2)

    def test_second_cancel_at_killpg_still_reaps_and_closes_both_pipes(self):
        p=Process();p.running=True
        def cancelled(_):raise KeyboardInterrupt('primary read cancellation')
        p.stdout.read1=cancelled
        with patch.object(r.os,'killpg',side_effect=KeyboardInterrupt('second cancellation')) as kill,self.assertRaisesRegex(KeyboardInterrupt,'primary read cancellation') as caught:
            self.process(p)
        self.assertGreater(p.waited,0);self.assertFalse(p.running);self.assertTrue(p.stdout.closed and p.stderr.closed)
        kill.assert_called_once_with(p.pid,signal.SIGTERM)
        self.assertTrue(any('KeyboardInterrupt' in note for note in caught.exception.__notes__))

    def test_pending_real_owned_signal_delivered_only_after_fake_pipe_cleanup(self):
        for pending in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM):
            p=Process([b'a']);events=[];stdout=p.stdout.close;stderr=p.stderr.close
            old_handler=signal.getsignal(pending);old_mask=signal.pthread_sigmask(signal.SIG_UNBLOCK,{pending})
            def first():events.append('stdout');stdout();signal.raise_signal(pending)
            def second():events.append('stderr');stderr()
            def delivered(*_):events.append('delivered');raise KeyboardInterrupt('pending owned signal')
            p.stdout.close=first;p.stderr.close=second
            try:
                signal.signal(pending,delivered)
                with self.subTest(signal=pending.name),self.assertRaisesRegex(KeyboardInterrupt,'pending owned signal'):self.process(p)
                self.assertEqual(events,['stdout','stderr','delivered'])
                self.assertTrue(p.stdout.closed and p.stderr.closed);self.assertGreater(p.waited,0)
            finally:
                signal.signal(pending,old_handler);signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)

    def test_prior_archive_total_minus_one_exact_and_overlong_chunk_charged(self):
        ledger=work();ledger.budget.decoded=r.TOTAL-1;ledger.budget.nodes=23
        self.assertEqual(self.process(Process([b'a']),ledger=ledger)['bytes'],1)
        self.assertEqual((ledger.budget.decoded,ledger.budget.tree_bytes,ledger.budget.nodes),(r.TOTAL-1,1,23))
        owner=object();ledger.acquire(owner);actor=unittest.mock.Mock()
        with self.assertRaisesRegex(ValueError,'process-output-budget'):
            r.checked_process(('mock',),'/mock',(),'cat',1,ledger.end,popen=actor,ledger=ledger,owner=owner)
        actor.assert_not_called();ledger.release(owner)
        other=work();other.budget.decoded=r.TOTAL-1
        with self.assertRaisesRegex(ValueError,'image-content-total'):self.process(Process([b'aa']),ledger=other)
        self.assertEqual(other.budget.tree_bytes,2)
        other.budget.tree_bytes=1
        with self.assertRaisesRegex(ValueError,'ledger-custody'):other.check()

    def test_failed_diagnostic_and_return_keep_stdout_spend_across_retries(self):
        ledger=work()
        for process,reason in [(Process([b'a'],errors=(b'wrong\n',)),'debugfs-diagnostic'),(Process([b'b'],code=1),'process-return')]:
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):self.process(process,ledger=ledger)
        self.assertEqual((ledger.budget.tree_bytes,ledger.calls),(2,2))
        self.process(Process([b'c']),ledger=ledger);self.assertEqual((ledger.budget.tree_bytes,ledger.calls),(3,3))

    def test_archive_lease_blocks_nested_archive_and_tool_and_carries_budget(self):
        ledger=work();ledger.budget.decoded=r.TOTAL-1;ledger.budget.nodes=23
        def archive(ref,expected,budget):
            self.assertIs(budget,ledger.budget)
            with self.assertRaisesRegex(ValueError,'ledger-lease'):ledger.archive_nodes({}, {})
            with patch.object(r,'read_reference') as read,self.assertRaisesRegex(ValueError,'ledger-lease'):
                r.Tool(CORE,{}, {},ledger.end,True,ledger=ledger)
            read.assert_not_called();budget.decoded+=1;return {}
        with patch.object(CORE,'archive_nodes',side_effect=archive):ledger.archive_nodes({}, {})
        self.assertEqual((ledger.budget.decoded,ledger.budget.tree_bytes,ledger.budget.nodes),(r.TOTAL,0,23))
        with self.assertRaisesRegex(ValueError,'process-output-budget'):self.process(Process([b'a']),ledger=ledger)

    def test_selected_tools_exclude_concurrent_lease_and_serial_reuse_spend(self):
        from contextlib import contextmanager
        import json
        ref=dict(path='/MODELED/tool',size=1,sha256='1'*64,identity=[1,1,0o100644,1,0,0,1,1,1])
        contract=dict(schema_version=2,approved=False,actors='NOT RUN',binary_and_recursive_DT_NEEDED={'/usr/bin/debugfs':dict(reference=ref,links=[])},interpreter_links=[])
        handles={};closed=[]
        @contextmanager
        def opened(path,budget,expected):
            fd=100+len(handles);handles[fd]=path
            try:yield fd,None
            finally:closed.append(fd)
        core=types.SimpleNamespace(Budget=CORE.Budget,decode=CORE.decode,reference=CORE.reference,
            hashed=lambda fd,size,budget:r.IMAGE_SHA if handles[fd]=='/MODELED/image' else '1'*64)
        ledger=work(core);ledger.budget.decoded=r.TOTAL-1;ledger.budget.nodes=23
        image=dict(path='/MODELED/image',size=r.IMAGE_SIZE,sha256=r.IMAGE_SHA,identity=[1,2,0o100644,1,0,0,r.IMAGE_SIZE,1,1])
        def captured(*args,**kwargs):
            kwargs['ledger'].claim_call(kwargs['owner']);kwargs['ledger'].charge(1,kwargs['owner']);return dict(data=b'',bytes=1,sha256='a'*64,returncode=0)
        with patch.object(r.os,'lseek'),patch.object(r,'held_regular',side_effect=opened),patch.object(r,'read_reference',return_value=json.dumps(contract).encode()) as read,patch.object(r,'checked_process',side_effect=captured) as process:
            first=r.Tool(core,{'sha256':r.TOOL_CONTRACT_SHA},image,ledger.end,True,ledger=ledger)
            count=read.call_count
            with self.assertRaisesRegex(ValueError,'ledger-lease'):r.Tool(core,{}, {},ledger.end,True,ledger=ledger)
            self.assertEqual(read.call_count,count)
            first.call('cat',11,1);first.close()
            second=r.Tool(core,{'sha256':r.TOOL_CONTRACT_SHA},image,ledger.end,True,ledger=ledger)
            self.assertIs(first.budget,second.budget)
            self.assertEqual((second.budget.decoded,second.budget.tree_bytes,second.budget.nodes),(r.TOTAL-1,1,23))
            with self.assertRaisesRegex(ValueError,'image-content-total'):second.call('cat',11,1)
            self.assertEqual((process.call_count,ledger.calls),(1,1));second.close()
            with self.assertRaisesRegex(ValueError,'ledger-lease'):first.call('cat',11,0)
        self.assertEqual(set(handles),set(closed))

    def test_missing_wrong_ledger_and_binding_refuse_before_actor(self):
        ledger=work();owner=object();ledger.acquire(owner)
        for bad in (None,{},object(),CORE.Budget(ledger.end)):
            actor=unittest.mock.Mock()
            with self.subTest(ledger_type=type(bad).__name__),self.assertRaisesRegex(ValueError,'ledger-required'):
                r.checked_process(('mock',),'/mock',(),'cat',1,ledger.end,popen=actor,ledger=bad,owner=owner)
            actor.assert_not_called()
        ledger.release(owner)
        for source,end in [(CORE_PATH,ledger.end+1),(CORE_PATH,True),(Path('/MODELED/substitute'),ledger.end)]:
            with self.subTest(source=source,end=end),patch.object(r,'Tool') as tool,self.assertRaisesRegex(ValueError,'ledger-binding'):
                r.open_selected(source,{}, {},end,True,ledger=ledger)
            tool.assert_not_called()
        with patch.object(r,'load_core') as load,patch.object(r,'Tool') as tool,self.assertRaisesRegex(ValueError,'ledger-required'):
            r.open_selected(CORE_PATH,{}, {},ledger.end,True)
        load.assert_not_called();tool.assert_not_called()

    def test_ledger_counter_regression_strict_types_and_joint_cutoff_poison(self):
        for field in ('decoded','nodes','tree_bytes','calls'):
            ledger=work();target=ledger if field=='calls' else ledger.budget;setattr(target,field,1);ledger.check();setattr(target,field,0)
            with self.subTest(regressed=field),self.assertRaisesRegex(ValueError,'ledger-custody'):ledger.check()
            setattr(target,field,1)
            with self.assertRaisesRegex(ValueError,'ledger-custody'):ledger.check()
            for value in (False,-1,0.0,None):
                fresh=work();setattr(fresh if field=='calls' else fresh.budget,field,value)
                with self.subTest(field=field,value=value),self.assertRaisesRegex(ValueError,'ledger-custody'):fresh.check()
        for change in ('budget','joint-cutoff','source','pin'):
            ledger=work()
            if change=='budget':ledger.budget=CORE.Budget(ledger.end)
            elif change=='joint-cutoff':ledger.end+=1;ledger.budget.end=ledger.end
            elif change=='source':ledger.source=Path('/MODELED/substitute')
            else:ledger.pin='0'*64
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'ledger-custody'):ledger.check()

    def test_retired_owner_and_finite_lease_count_reject_reacquire(self):
        ledger=work();owner=object();ledger.acquire(owner);ledger.release(owner)
        with self.assertRaisesRegex(ValueError,'ledger-retired-or-lease-bound'):ledger.acquire(owner)
        with patch.object(r,'NODES',2):
            limited=work()
            for _ in range(2):
                current=object();limited.acquire(current);limited.release(current)
            with self.assertRaisesRegex(ValueError,'ledger-retired-or-lease-bound'):limited.acquire(object())

    def test_expired_tool_close_disposes_and_releases_without_new_cutoff(self):
        clock=[0]
        with patch.object(r.time,'monotonic',side_effect=lambda:clock[0]):
            ledger=work(end=60);t=object.__new__(r.Tool);ledger.acquire(t);t.ledger=ledger;t.core=CORE;t.budget=ledger.budget;t.stack=unittest.mock.Mock();t.check_pins=unittest.mock.Mock()
            clock[0]=61
            with self.assertRaisesRegex(ValueError,'deadline'):t.close()
            t.stack.close.assert_called_once();t.check_pins.assert_not_called()
            self.assertEqual(ledger.end,60)
            with self.assertRaisesRegex(ValueError,'deadline'):ledger.acquire(object())

    def test_tool_context_cleanup_does_not_replace_incoming_failure(self):
        t=object.__new__(r.Tool);t.close=unittest.mock.Mock(side_effect=KeyboardInterrupt('close cancellation'))
        with self.assertRaisesRegex(ValueError,'primary comparison refusal') as caught:
            with t:raise ValueError('primary comparison refusal')
        t.close.assert_called_once();self.assertTrue(any('KeyboardInterrupt' in note for note in caught.exception.__notes__))

    def test_fresh_lease_cannot_renew_global_zero_output_call_bound(self):
        ledger=work();bound=3*r.NODES+2;ledger.calls=bound-1
        self.process(Process(),size=0,ledger=ledger)
        self.assertEqual((ledger.calls,ledger.budget.tree_bytes,ledger.budget.nodes),(bound,0,0))
        for _ in range(2):
            owner=object();ledger.acquire(owner);actor=unittest.mock.Mock()
            with self.assertRaisesRegex(ValueError,'call-bound'):
                r.checked_process(('mock',),'/mock',(),'cat',0,ledger.end,popen=actor,ledger=ledger,owner=owner)
            actor.assert_not_called();ledger.release(owner)
        self.assertEqual(ledger.calls,bound)


if __name__=='__main__':unittest.main()
