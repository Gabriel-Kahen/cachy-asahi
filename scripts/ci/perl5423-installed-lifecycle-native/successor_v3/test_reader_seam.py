# SPDX-License-Identifier: MIT
"""One unmodified Reader predicate seam over synthetic DATA, never a Reader role."""
import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(body):return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())


class ReaderSeam(unittest.TestCase):
    def test_exact_unchanged_result_reader_accepts_new_field_and_paths_but_rejects_bad_tar(self):
        # Compile ONLY the original status/channel/TAR/report/command predicates.
        # Whole review(), Source admission, bootstrap, GPG and removal proof do NOT run.
        raw=(HERE/'data/parent-read_result.py.txt').read_bytes()
        self.assertEqual(pin(raw),dict(bytes=10990,sha256='2dff5d7be09239bfede23acc5d04d29b6eb67dafacfe26df10140d2757079086'))
        function=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='review')
        start=next(i for i,n in enumerate(function.body)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)
                   and len(n.value.args)>1 and isinstance(n.value.args[-1],ast.Constant)
                   and n.value.args[-1].value=='complete naturally retired original producer')
        stop=next(i for i,n in enumerate(function.body)if isinstance(n,ast.Assign)
                  and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='expected')
        seam=compile(ast.Module(body=function.body[start:stop],type_ignores=[]),'<unchanged-reader-DATA-seam>','exec')
        common=(HERE/'data/parent-common.py.txt').read_bytes()
        natural=next(n for n in ast.parse(common).body if isinstance(n,ast.FunctionDef)and n.name=='natural')
        scope={};exec(compile(ast.Module(body=[natural],type_ignores=[]),'<unchanged-natural-predicate>','exec'),scope)
        life=dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,
                  exit_observed_via_waitpid=True,ownership_lost=False,forced_cleanup=False,retirement='REAPED',exit=0)
        required=['unknown-test-key','tampered-signature','dependency-protected-removal','trusted-upgrade','trusted-repeat','trusted-noop','trusted-rollback']
        commands=[dict(step=name,argv=['/usr/bin/pacman','--config','/work/pacman.conf'],success=True,
                       returncode=0,expected=0,lifecycle=life,stdout=pin(b''),stderr=pin(b''))for name in required]
        actor=dict(status='PASS_FINITE_NATIVE_ARM4K_PERL_INSTALLED_LIFECYCLE',source_map_sha256='a'*64,
                   admission_sha256='b'*64,first_failure=None,cleanup=dict(failures=[],user_fixture_absent=True),
                   stages=['baseline','upgrade','repeat','noop','rollback'],commands=commands,
                   retained_output=dict(path='/cachy-asahi-perl-lifecycle/result',parent='/cachy-asahi-perl-lifecycle',
                                        uid=0,gid=0,mode=0o700,storage='OWNED_CONTAINER_WRITABLE_LAYER',
                                        parent_absent_before_entry=True,same_filesystem_as_parent_root=True))
        actor_bytes=json.dumps(actor,sort_keys=True).encode()
        def archive(prefix='result',size=None):
            if size is not None:
                item=tarfile.TarInfo(prefix+'/report.json');item.size=size
                return item.tobuf()+bytes(1024)
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:')as out:
                for name,body in [('report.json',actor_bytes),*[(r['step']+'.'+channel,b'')for r in commands for channel in ['stdout','stderr']]]:
                    item=tarfile.TarInfo(prefix+'/'+name);item.size=len(body)if size is None else size
                    out.addfile(item,io.BytesIO(body)if size is None else None)
            return stream.getvalue()
        def run(exported):
            steps=['image','daemon-architecture','daemon-storage','create','inspect-before','run','inspect-after','export','cleanup-inspect','remove-owned']
            producer_commands=[dict(step=name,argv=['/usr/bin/docker','cp','TEST:/cachy-asahi-perl-lifecycle/result','-']
                                    if name=='export'else ['/usr/bin/docker',name],success=True,returncode=0,
                                    lifecycle=life,stdout=pin(exported if name=='export'else b''),stderr=pin(b''))for name in steps]
            producer=dict(status='PASS_PRODUCED_PERL_INSTALLED_LIFECYCLE_DATA_REQUIRES_INDEPENDENT_ROOT_REVIEW',
                          source_map_sha256='a'*64,admission_sha256='b'*64,first_failure=None,
                          cleanup=dict(status='OWNED_CONTAINER_REMOVED',natural=True),commands=producer_commands,actor_report=pin(actor_bytes))
            data={'export.stdout':exported,'data/report.json':actor_bytes}
            def read(path,cap):
                body=data[path.as_posix().removeprefix('/SYNTHETIC-EVIDENCE/')]
                need(len(body)<=cap,'synthetic DATA byte cap');return body
            context=dict(producer=producer,C=SimpleNamespace(need=need,natural=scope['natural'],pin=pin,read=read,decode=json.loads),
                         args=SimpleNamespace(source_map_sha256='a'*64),evidence=Path('/SYNTHETIC-EVIDENCE'),Path=Path,tarfile=tarfile,io=io)
            exec(seam,context)
            return context
        with contextlib.ExitStack()as stack:
            for name in ['subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open']:
                stack.enter_context(patch(name,side_effect=AssertionError('Reader seam DATA only'),create=name=='os.pidfd_open'))
            self.assertEqual(run(archive())['actor']['retained_output'],actor['retained_output'])
            for exported in [archive('wrong'),archive('result/../escape'),archive(size=16*1024**2+1)]:
                with self.assertRaises(ValueError):run(exported)
        hosted=(HERE/'data/parent-hosted-reader.py.txt').read_text()
        self.assertIn("reader.review(SimpleNamespace(evidence=str(evidence/'installed'),inputs=str(capsule)",hosted)
        self.assertNotIn('/work/result',hosted)
        self.assertNotIn('retained_output',hosted)
