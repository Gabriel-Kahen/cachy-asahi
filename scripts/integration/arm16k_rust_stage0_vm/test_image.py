# SPDX-License-Identifier: MIT
"""FENCED mocked ext4 reader and tiny DATA controls; no operational inputs."""
import base64
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location('fenced_image_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


I,O,K=(load(name) for name in ('image','ownership','contracts'))


def corpus(count=1):
    rows={'.':dict(type='directory',mode=0o755,inode=2,size=4096)};bodies={};index=3
    def directory(path):
        nonlocal index
        rows[path]=dict(type='directory',mode=0o755,inode=index,size=4096);index+=1
    def file(path,body):
        nonlocal index
        rows[path]=dict(type='file',mode=0o644,inode=index,size=len(body),sha256=hashlib.sha256(body).hexdigest());bodies[index]=body;index+=1
    for path in ('var','var/lib','var/lib/pacman','var/lib/pacman/local','usr','usr/lib'):directory(path)
    for n in range(count):
        prefix='var/lib/pacman/local/fenced'+str(n)+'-1';directory(prefix)
        file(prefix+'/desc',('%NAME%\nfenced'+str(n)+'\n\n%VERSION%\n1\n').encode())
        file(prefix+'/files',('%FILES%\nusr/lib/fenced'+str(n)+'\n').encode())
        file('usr/lib/fenced'+str(n),b'FENCED_DATA')
    rows['lib']=dict(type='symlink',mode=0o777,inode=index,size=8,target_b64=base64.b64encode(b'/usr/lib').decode())
    return rows,bodies


def fake_reader(rows,bodies,change=None):
    instances=[]
    class FakeReader:
        def __init__(self,path,max_nodes,max_file_bytes):
            self.fd=os.open(path,os.O_RDONLY);self.closed=False;self.size=os.fstat(self.fd).st_size
            self.blocksize=4096;self.incompat=0x22c2;self.rocompat=0x46b;self.inode_size=256
            self.max_nodes=max_nodes;self.max_file_bytes=max_file_bytes;self.read_budget=2*1024**3
            instances.append(self);self.read(0,1)
        def read(self,offset,length):
            self.read_budget-=length
            if self.read_budget<0:raise ValueError('read budget exhausted')
            return os.pread(self.fd,length,offset)
        def inventory(self):
            if change is not None:change(self)
            self.read(0,1);return dict(reader='FENCED_MOCK',nodes=copy.deepcopy(rows))
        def inode(self,number):
            row=next(row for row in rows.values() if row['inode']==number)
            return {k:v for k,v in row.items() if k!='sha256'},bodies.get(number,b'')
        def chunks(self,fields,data):
            self.read(0,1)
            if data:yield data
        def close(self):
            if not self.closed:os.close(self.fd);self.closed=True
        def __enter__(self):return self
        def __exit__(self,*_):self.close()
    return FakeReader,instances


class ImageControls(unittest.TestCase):
    def scan(self,raw,rows,bodies,guard=None,change=None):
        reader,instances=fake_reader(rows,bodies,change)
        contract=SimpleNamespace(need=K.need,ordinary=K.ordinary,helper=Mock(return_value=SimpleNamespace(Ext4Reader=reader)))
        with patch.object(I,'module',side_effect=lambda name:contract if name=='contracts' else O):
            try:return I.scan(raw,time.monotonic()+30,guard)
            finally:
                self.assertTrue(all(item.closed for item in instances))
                self.assertTrue(all(item.max_nodes==150000 and item.max_file_bytes==256*I.MIB for item in instances))

    def test_scan_normalizes_and_captures_only_bounded_ALPM_text(self):
        rows,bodies=corpus();guard=Mock()
        with tempfile.TemporaryDirectory() as tmp:
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
            result=self.scan(raw,rows,bodies,guard)
            self.assertEqual(set(Path(tmp).iterdir()),{raw})
        self.assertEqual(result['nodes']['lib'],dict(kind='link',mode=0o777,target='/usr/lib'))
        self.assertNotIn('.',result['nodes']);self.assertEqual(set(result['records']),{'fenced0-1'})
        self.assertIn('%NAME%',result['records']['fenced0-1']['desc'])
        self.assertEqual(result['profile']['block_bytes'],4096);self.assertGreater(result['profile']['read_calls'],0)
        self.assertEqual(guard.call_count,2)

    def test_metadata_hash_mismatch_refuses_and_closes(self):
        rows,bodies=corpus();number=rows['var/lib/pacman/local/fenced0-1/desc']['inode'];bodies[number]=b'wrong'
        with tempfile.TemporaryDirectory() as tmp:
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
            with self.assertRaisesRegex(ValueError,'differs from inventory'):self.scan(raw,rows,bodies)

    def test_missing_or_oversized_metadata_refuses(self):
        for alteration in ('missing','oversize'):
            rows,bodies=corpus();path='var/lib/pacman/local/fenced0-1/desc'
            if alteration=='missing':rows.pop(path)
            else:rows[path]['size']=4*1024**2+1
            with self.subTest(alteration=alteration),tempfile.TemporaryDirectory() as tmp:
                raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
                with self.assertRaisesRegex(ValueError,'ALPM record'):self.scan(raw,rows,bodies)

    def test_aggregate_metadata_bound(self):
        rows,bodies=corpus(5)
        for path,row in rows.items():
            if path.endswith('/desc') or path.endswith('/files'):
                body=b'x'*16 if path.endswith('/desc') else b'';bodies[row['inode']]=body;row.update(size=len(body),sha256=hashlib.sha256(body).hexdigest())
        with tempfile.TemporaryDirectory() as tmp,patch.object(I,'MIB',4):
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
            with self.assertRaisesRegex(ValueError,'aggregate ALPM'):self.scan(raw,rows,bodies)

    def test_identity_drift_and_unsupported_profile_fail_closed(self):
        rows,bodies=corpus()
        with tempfile.TemporaryDirectory() as tmp:
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
            with self.assertRaisesRegex(ValueError,'raw identity changed'):self.scan(raw,rows,bodies,change=lambda _:raw.write_bytes(b'y'*4096))
            def refuse(_):raise ValueError('unsupported profile FENCED')
            with self.assertRaisesRegex(ValueError,'unsupported profile'):self.scan(raw,rows,bodies,change=refuse)

    def test_final_guard_failure_closes_reader(self):
        rows,bodies=corpus();guard=Mock(side_effect=[None,ValueError('FENCED reserve')])
        with tempfile.TemporaryDirectory() as tmp:
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
            with self.assertRaisesRegex(ValueError,'FENCED reserve'):self.scan(raw,rows,bodies,guard)

    def test_guard_is_periodic_not_per_read(self):
        rows,bodies=corpus();guard=Mock();clock=[10.0]
        def advance(_):clock[0]=10.6
        with tempfile.TemporaryDirectory() as tmp,patch.object(I.time,'monotonic',side_effect=lambda:clock[0]):
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
            self.scan(raw,rows,bodies,guard,change=advance)
        self.assertEqual(guard.call_count,3)

    def test_deadline_during_scan_closes_reader(self):
        rows,bodies=corpus();clock=[10.0]
        def expire(_):clock[0]=41.0
        with tempfile.TemporaryDirectory() as tmp,patch.object(I.time,'monotonic',side_effect=lambda:clock[0]):
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096)
            with self.assertRaisesRegex(TimeoutError,'deadline'):self.scan(raw,rows,bodies,change=expire)

    def test_expired_deadline_opens_no_raw_or_frozen_reader(self):
        contract=SimpleNamespace(need=K.need)
        with patch.object(I,'module',return_value=contract),patch.object(I.os,'open') as opened:
            with self.assertRaisesRegex(ValueError,'deadline'):I.scan(Path('/FENCED_NOT_PRESENT'),time.monotonic()-1)
            opened.assert_not_called()

    def test_all111_records_and_ownership_join(self):
        rows,bodies=corpus(111)
        with tempfile.TemporaryDirectory() as tmp:
            raw=Path(tmp)/'FENCED_DATA';raw.write_bytes(b'x'*4096);result=self.scan(raw,rows,bodies)
        expected={'fenced'+str(n):'1' for n in range(111)}
        owned=O.all_owned_records(result['records'],expected,result['nodes']);self.assertEqual(len(owned),111)
        bad=copy.deepcopy(result['records']);bad.pop('fenced0-1')
        with self.assertRaisesRegex(ValueError,'complete captured'):O.all_owned_records(bad,expected,result['nodes'])
        bad=copy.deepcopy(result['records']);bad['fenced0-1']['desc']+='changed'
        with self.assertRaisesRegex(ValueError,'differs from namespace'):O.all_owned_records(bad,expected,result['nodes'])

    def test_nodes_resolver_qualifies_bytes_owner_and_linker_choice(self):
        node=dict(kind='file',mode=0o644,bytes=1,sha256='a'*64)
        nodes={'lib':dict(kind='link',mode=0o777,target='/usr/lib'),'usr':dict(kind='dir',mode=0o755),'usr/lib':dict(kind='dir',mode=0o755),'usr/lib/model':node,'usr/lib/libc.so':node}
        row=dict(bytes=1,sha256='a'*64,resolved='/usr/lib/model',owner='fenced')
        cert=dict(files={'/lib/model':row},link_inputs={'c':'/usr/lib/libc.so'})
        self.assertEqual(O.resolve_nodes(nodes,'/lib/model'),('/usr/lib/model',node))
        self.assertEqual(O.qualify_nodes(cert,{'usr/lib/model':dict(owners=['fenced'])},nodes),cert['files'])
        with self.assertRaisesRegex(ValueError,'ownership'):O.qualify_nodes(cert,{},nodes)
        nodes['lib']['target']='/lib'
        with self.assertRaisesRegex(ValueError,'cycle'):O.resolve_nodes(nodes,'/lib/model')

    def test_preservation_nodes_keeps_independent_gates(self):
        original={'usr/bin/fenced':dict(kind='file',mode=0o755,bytes=1,sha256='a'*64)}
        protected={'etc/nonce':dict(kind='file',mode=0o644,bytes=1,sha256='b'*64)}
        payload={'bin/rustc':dict(kind='file',mode=0o755,bytes=1,sha256='c'*64)}
        nodes={**original,**protected,'opt/fenced/bin/rustc':payload['bin/rustc']}
        baseline=dict(packages={'FENCED':'1'},owned=original,protected=protected)
        with patch.object(O,'all_owned_records',return_value=original):
            self.assertTrue(O.preservation_nodes(nodes,{},baseline,payload,'/opt/fenced')['all111_unchanged'])
            for path in ('etc/nonce','opt/fenced/bin/rustc'):
                bad=dict(nodes);bad.pop(path)
                with self.assertRaises(ValueError):O.preservation_nodes(bad,{},baseline,payload,'/opt/fenced')
        with patch.object(O,'all_owned_records',return_value={}),self.assertRaisesRegex(ValueError,'all111'):O.preservation_nodes(nodes,{},baseline,payload,'/opt/fenced')


if __name__=='__main__':unittest.main()
