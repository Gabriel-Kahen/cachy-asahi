# SPDX-License-Identifier: MIT
"""Inert responses/tiny ZIP compatibility: no network, real stage0 or provider role."""
import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import zipfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('FENCED_stage0_collector',HERE/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
REAL_FILES=copy.deepcopy(c.FILES)


class Clock:
    def __init__(self):self.now=100.0
    def __call__(self):return self.now


class Response:
    def __init__(self,body,headers,status=200,on_read=None):self.body=body;self.headers=headers;self.status=status;self.position=0;self.length=len(body);self.on_read=on_read;self.read_sizes=[];self.closed=False
    def getheaders(self):return list(self.headers)
    def getheader(self,name,default=None):
        values=[v for k,v in self.headers if k.lower()==name.lower()];return ', '.join(values)if values else default
    def read(self,size):
        assert type(size)is int and size>0
        self.read_sizes.append(size)
        if self.on_read:self.on_read()
        result=self.body[self.position:self.position+size];self.position+=len(result);self.length-=len(result);return result
    def read1(self,size):return self.read(size)
    def close(self):self.closed=True


class Connection:
    def __init__(self,factory):self.factory=factory;self.sock=self;self.timeouts=[];self.closed=False;self.path=None
    def settimeout(self,value):assert 0<value<=c.SOCKET_SECONDS;self.timeouts.append(value)
    def request(self,method,path,body=None,headers=None):assert method=='GET'and body is None;self.path=path
    def getresponse(self):
        if self.factory.timeout:raise socket.timeout('FENCED socket timeout')
        if self.factory.on_headers:self.factory.on_headers()
        name=self.factory.paths[self.path];body=self.factory.bodies[name];headers=[('Content-Length',str(c.FILES[name]['bytes']))]
        if self.factory.headers is not None:headers=self.factory.headers(headers)
        if self.factory.bad_hash:body=b'X'*len(body)
        if self.factory.short:body=body[:-1]
        if self.factory.extra:body+=b'X'
        row=Response(body,headers,self.factory.status,self.factory.on_read);self.factory.responses.append(row)
        if self.factory.detach:self.sock=None
        return row
    def close(self):self.closed=True
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


class HTTPS:
    def __init__(self,bodies,**options):
        self.bodies=bodies;self.paths={urlsplit(c.FILES[n]['url']).path:n for n in bodies};self.connections=[];self.responses=[]
        self.status=200;self.headers=None;self.bad_hash=False;self.short=False;self.extra=False;self.timeout=False;self.on_read=None;self.on_headers=None;self.detach=False
        self.__dict__.update(options)
    def __call__(self,host,timeout):
        assert host==c.HOST and 0<timeout<=c.SOCKET_SECONDS
        connection=Connection(self);self.connections.append(connection);return connection


def env():
    return dict(GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF='refs/heads/main',GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/retained-rust-stage0-provider.yml@refs/heads/main',GITHUB_RUN_ID='101',GITHUB_RUN_ATTEMPT='1',GITHUB_JOB='stage0')


class Controls(unittest.TestCase):
    def tiny(self):
        bodies={name:('FENCED-INERT-DATA-'+str(n)).encode()for n,name in enumerate(REAL_FILES)}
        files={name:dict(bytes=len(bodies[name]),sha256=hashlib.sha256(bodies[name]).hexdigest(),url=REAL_FILES[name]['url'])for name in bodies}
        return bodies,files
    def run_collect(self,parent,files,bodies,**options):
        clock=options.pop('clock',Clock())
        with patch.object(c,'FILES',files):
            client=HTTPS(bodies,**options);result=c.collect(parent,c.pin(c.encode(c.profile()))['sha256'],c.provider_binding(env()),connect=client,clock=clock)
            return result,client
    def test_real_pins_and_flat_zip_members_match_maintained_consumer(self):
        path=HERE.parent/'rust199-source-reference-native/successor_v5/payload/hosted/materials.py';tree=ast.parse(path.read_bytes())
        node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='STAGE0'for t in n.targets));consumer=ast.literal_eval(node.value)
        self.assertEqual({name:(row['bytes'],row['sha256'])for name,row in REAL_FILES.items()},consumer)
        rows=c.members();self.assertEqual(len(rows),3)
        for row in rows:self.assertEqual(row,dict(member=row['name'],role='stage0:'+row['name'],name=row['name'],bytes=consumer[row['name']][0],sha256=consumer[row['name']][1],container='ZIP',outer_member=None))
        self.assertEqual((c.SECONDS,c.FILE_SECONDS,c.SOCKET_SECONDS,c.HOST),(300,120,15,'static.rust-lang.org'))
        self.assertEqual(c.pin(c.encode(c.profile()))['sha256'],'3b247bbaa5cdb547a6d6a0e6291e10ed17898785e83b6274b3f6044f72ffc6ee')
    def test_provider_guards_keep_future_artifact_job_and_authority_unissued(self):
        provider=c.provider_binding(env());raw=c.encode(provider)
        self.assertNotIn(b'ROOT_ADMITTED',raw)
        for key in ('job','artifact','Root_acceptance','runtime_qualification'):self.assertIsNone(provider[key])
        for key,value in [('GITHUB_REPOSITORY','OTHER/repo'),('GITHUB_EVENT_NAME','push'),('GITHUB_REF','refs/heads/other'),('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_JOB','other'),('GITHUB_WORKFLOW_REF','OTHER'),('GITHUB_RUN_ID','')]:
            with self.subTest(key=key),self.assertRaises(ValueError):c.provider_binding(dict(env(),**{key:value}))
    def test_three_exact_inert_files_and_report_outside_uploaded_directory(self):
        bodies,files=self.tiny()
        with tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary:
            with patch.object(c,'FILES',files):
                result,client=self.run_collect(Path(temporary),files,bodies);directory=Path(result['directory']);c.validate_namespace(directory)
                self.assertEqual({p.name for p in directory.iterdir()},set(files))
                for name in files:self.assertEqual((directory/name).read_bytes(),bodies[name]);self.assertEqual((directory/name).stat().st_mode&0o777,0o644)
                self.assertEqual(len(client.connections),3);self.assertTrue(all(connection.closed for connection in client.connections))
                self.assertTrue(all(response.closed for response in client.responses))
                self.assertTrue(Path(result['report_path']).is_file())
                self.assertFalse(Path(result['report_path']).is_relative_to(directory));self.assertEqual(result['report']['status'],'THREE_PINNED_STAGE0_ARCHIVES_DATA_ONLY')
                self.assertEqual(result['report']['body_bytes'],sum(row['bytes']for row in files.values()))
    def test_http_status_headers_and_incomplete_or_wrong_bodies_refuse_without_retry(self):
        bodies,files=self.tiny()
        cases=[dict(status=302),dict(status=404),dict(headers=lambda h:[]),dict(headers=lambda h:h+[('content-length',h[0][1])]),dict(headers=lambda h:[('Content-Length','999')]),dict(headers=lambda h:h+[('Transfer-Encoding','chunked')]),dict(headers=lambda h:h+[('Content-Encoding','gzip')]),dict(bad_hash=True),dict(short=True),dict(extra=True),dict(timeout=True)]
        for options in cases:
            with self.subTest(options=list(options)),tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary,patch.object(c,'FILES',files):
                client=HTTPS(bodies,**options)
                with self.assertRaises((ValueError,OSError,TimeoutError)):c.collect(Path(temporary),c.pin(c.encode(c.profile()))['sha256'],c.provider_binding(env()),connect=client,clock=Clock())
                self.assertEqual(len(client.connections),1);self.assertTrue(all(connection.closed for connection in client.connections))
                self.assertTrue(all(response.closed for response in client.responses))
                for name in files:self.assertFalse(list(Path(temporary).rglob(name)))
    def test_wrong_profile_and_namespace_tamper_refuse(self):
        bodies,files=self.tiny()
        with tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary,patch.object(c,'FILES',files):
            client=HTTPS(bodies)
            with self.assertRaises(ValueError):c.collect(Path(temporary),'0'*64,c.provider_binding(env()),connect=client,clock=Clock())
            self.assertFalse(client.connections)
            result,_=self.run_collect(Path(temporary),files,bodies);directory=Path(result['directory'])
            extra=directory/'FENCED-extra';extra.write_bytes(b'not an archive')
            with self.assertRaises(ValueError):c.validate_namespace(directory)
            extra.unlink();name=next(iter(files));(directory/name).write_bytes(b'X'*len(bodies[name]))
            with self.assertRaises(ValueError):c.validate_namespace(directory)
    def test_namespace_rejects_aliases_special_modes_and_nested_entries(self):
        bodies,files=self.tiny()
        for mode in ('symlink','hardlink','executable','nested'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary,patch.object(c,'FILES',files):
                result,_=self.run_collect(Path(temporary),files,bodies);directory=Path(result['directory']);name=next(iter(files));path=directory/name
                if mode=='symlink':path.unlink();target=Path(temporary)/'FENCED-inert';target.write_bytes(bodies[name]);path.symlink_to(target)
                elif mode=='hardlink':(Path(temporary)/'FENCED-link').hardlink_to(path)
                elif mode=='executable':path.chmod(0o755)
                else:(directory/'FENCED-nested').mkdir()
                with self.assertRaises(ValueError):c.validate_namespace(directory)
    def test_file_and_overall_deadlines_refuse_inert_stalled_reads(self):
        bodies,files=self.tiny()
        for increment in (c.FILE_SECONDS+1,110):
            with self.subTest(increment=increment),tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary,patch.object(c,'FILES',files):
                clock=Clock();client=HTTPS(bodies,on_read=lambda:setattr(clock,'now',clock.now+increment))
                with self.assertRaises((ValueError,TimeoutError)):c.collect(Path(temporary),c.pin(c.encode(c.profile()))['sha256'],c.provider_binding(env()),connect=client,clock=clock)
                self.assertLessEqual(len(client.connections),3);self.assertTrue(all(connection.closed for connection in client.connections))
                self.assertTrue(all(response.closed for response in client.responses))
    def test_slow_headers_expire_file_budget_before_any_body_read(self):
        bodies,files=self.tiny();clock=Clock()
        with tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary,patch.object(c,'FILES',files):
            client=HTTPS(bodies,on_headers=lambda:setattr(clock,'now',clock.now+c.FILE_SECONDS+1))
            with self.assertRaises((ValueError,TimeoutError)):c.collect(Path(temporary),c.pin(c.encode(c.profile()))['sha256'],c.provider_binding(env()),connect=client,clock=clock)
            self.assertEqual(len(client.connections),1);self.assertTrue(all(row.closed for row in client.connections));self.assertFalse(any(row.read_sizes for row in client.responses))
            self.assertTrue(all(row.closed for row in client.responses))
    def test_detached_response_socket_is_still_bounded_and_alarm_state_restored(self):
        bodies,files=self.tiny();handler=c.signal.getsignal(c.signal.SIGALRM)
        with tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary:
            _,client=self.run_collect(Path(temporary),files,bodies,detach=True)
            self.assertTrue(all(row.sock is None and row.timeouts and row.closed for row in client.connections));self.assertTrue(all(row.closed for row in client.responses))
            self.assertEqual(c.signal.getsignal(c.signal.SIGALRM),handler);self.assertEqual(c.signal.getitimer(c.signal.ITIMER_REAL),(0.0,0.0))
    def test_initial_receipt_io_failure_restores_handler_before_any_connection(self):
        bodies,files=self.tiny();handler=c.signal.getsignal(c.signal.SIGALRM)
        with tempfile.TemporaryDirectory(prefix='FENCED-stage0-')as temporary,patch.object(c,'FILES',files):
            client=HTTPS(bodies)
            with patch.object(Path,'write_bytes',side_effect=OSError('FENCED receipt write failure')):
                with self.assertRaises(OSError):c.collect(Path(temporary),c.pin(c.encode(c.profile()))['sha256'],c.provider_binding(env()),connect=client,clock=Clock())
            self.assertFalse(client.connections);self.assertEqual(c.signal.getsignal(c.signal.SIGALRM),handler);self.assertEqual(c.signal.getitimer(c.signal.ITIMER_REAL),(0.0,0.0))
    def test_flat_inert_zip_is_accepted_by_maintained_consumer_extractor(self):
        path=HERE.parent/'rust199-source-reference-native/successor_v5/payload/hosted/materials.py'
        spec=importlib.util.spec_from_file_location('FENCED_maintained_materials',path);consumer=importlib.util.module_from_spec(spec);spec.loader.exec_module(consumer)
        bodies,files=self.tiny()
        with tempfile.TemporaryDirectory(prefix='FENCED-stage0-ZIP-')as temporary,patch.object(c,'FILES',files):
            root=Path(temporary);result,_=self.run_collect(root,files,bodies);directory=Path(result['directory']);archive=root/'FENCED-inert.zip'
            with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED)as output:
                for name in files:output.write(directory/name,arcname=name)
            target=root/'extracted-DATA';target.mkdir();budget=SimpleNamespace(cancelled=False,tick=lambda:None)
            extracted=consumer.extract_zip(archive,c.members(),target,budget)
            self.assertEqual(set(extracted),{'stage0:'+name for name in files});self.assertEqual({p.name for p in target.iterdir()},set(files))
            for name,expected in files.items():
                row=extracted['stage0:'+name];actual=(target/name).read_bytes()
                self.assertEqual(actual,bodies[name]);self.assertEqual({k:row[k]for k in ('bytes','sha256')},c.pin(actual));self.assertEqual(len(actual),expected['bytes'])
                self.assertEqual((target/name).stat().st_mode&0o777,0o444)


if __name__=='__main__':unittest.main()
