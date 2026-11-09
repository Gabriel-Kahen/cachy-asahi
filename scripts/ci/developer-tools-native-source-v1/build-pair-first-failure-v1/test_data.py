#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced real-transcript parser and modeled build-slot exception controls."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import tarfile
import unittest

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
N=HERE/'payload/native'
REPO=BASE.parents[2]
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def need(ok,why):
    if not ok:raise ValueError(why)
def extracted(path,name,extra=None):
    node=next(n for n in ast.parse(Path(path).read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name==name)
    env=dict(need=need,re=re,json=json,Path=Path,**(extra or {}));exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),env);return env[name]
CHECK=extracted(N/'developer_tools_alpm_v1.py','check_result')
READER_CHECK=extracted(N/'developer_tools_reader_v1.py','developer_tools_check_result')
PROVENANCE=json.loads((HERE/'fixtures/provenance.json').read_bytes())

def transcript(label='python312'):
    # Only the boundary marker is MODELED; all unittest bytes are actual local DATA.
    return b'==> Starting check()\n'+(HERE/'fixtures'/(label+'-package-controls.log')).read_bytes()

@contextlib.contextmanager
def model(check=CHECK,run_error=None,rename_error=None):
    with tempfile.TemporaryDirectory()as tmp:
        root=Path(tmp);prefix=root/'prefix';prefix.mkdir();recipes=root/'recipes';recipes.mkdir()
        for name in('a','b'):
            (recipes/name).mkdir();(recipes/name/'PKGBUILD').write_bytes(b'MODELED inert recipe\n')
        source=root/'source';source.mkdir();archive='modeled-0.1.0-1-any.pkg.tar.zst'
        policy=dict(makepkg_config=dict(path='native/makepkg.conf'),recipe=dict(source_files=dict(PKGBUILD=dict(sha256='c'*64)),archive=archive),build_pair=dict(source_date_epoch='1793145600',packager='cachy-asahi native TEST builder'))
        report=dict(builds={},stages=[]);events=[];calls=[];slot=prefix/'build-current';original_rename=Path.rename
        def rename(path,target):
            events.append((path.name,Path(target).name))
            if path==slot and rename_error is not None:raise rename_error
            return original_rename(path,target)
        Path.rename=rename
        try:
            def run(step,argv,cwd):
                calls.append(step);need(Path(cwd)==slot and slot.is_dir(),'fixed model build slot')
                if run_error is not None:raise run_error
                (slot/archive).write_bytes(b'MODELED inert archive')
                return transcript()
            tool=SimpleNamespace(VERSION='0.1.0-1',data_pin=pin,encoded=encoded,pin=lambda p:pin(Path(p).read_bytes()))
            fn=extracted(N/'developer_tools_alpm_v1.py','build_pair',dict(PREFIX=prefix,T=tool,os=SimpleNamespace(path=os.path,chown=lambda *args:None),check_result=check))
            yield SimpleNamespace(fn=lambda:fn(run,source,recipes,policy,SimpleNamespace(pw_uid=1,pw_gid=1),report),root=root,recipes=recipes,slot=slot,events=events,calls=calls,report=report)
        finally:Path.rename=original_rename

def object_tree(rows):
    nodes={}
    for name,row in rows.items():
        target=nodes
        for part in Path(name).parts[:-1]:target=target.setdefault(part,{})
        target[Path(name).name]=(row['mode'],row['blob'])
    def branch(node):
        raw=b''
        for name,value in sorted(node.items(),key=lambda r:r[0].encode()+(b'/'if type(r[1])is dict else b'')):
            mode,digest=(b'40000',branch(value))if type(value)is dict else(b'100755'if value[0]==0o755 else b'100644',bytes.fromhex(value[1]))
            raw+=mode+b' '+name.encode()+b'\0'+digest
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
    return branch(nodes).hex()

class BuildPairFailureTests(unittest.TestCase):
    def test01_real_local_transcripts_match_unchanged_package_class_and13_methods(self):
        row=PROVENANCE['package_test_source'];source=REPO/row['path'];raw=source.read_bytes();self.assertEqual(pin(raw),{k:row[k]for k in('bytes','sha256')})
        classes=[n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef)and any(isinstance(b,ast.Attribute)and b.attr=='TestCase'for b in n.bases)];self.assertEqual(len(classes),1)
        cls=classes[0];names=sorted(n.name for n in cls.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_'))
        self.assertEqual(cls.name,'PackageControls');self.assertEqual(cls.name,PROVENANCE['actual_test_class']);self.assertEqual(names,PROVENANCE['actual_methods']);self.assertEqual(len(names),13)
        package=REPO/'packages/tools/cachy-asahi-developer-tools/cachy-asahi-developer-tools-0.1.0.tar.gz'
        with tarfile.open(package,mode='r:gz')as archive:self.assertEqual(archive.extractfile('cachy-asahi-developer-tools-0.1.0/test_package.py').read(),raw)
        for label in('python312','python314'):
            fixture=(HERE/'fixtures'/(label+'-package-controls.log')).read_bytes();self.assertEqual(pin(fixture),{k:PROVENANCE['logs'][label+'-package-controls.log'][k]for k in('bytes','sha256')})
            expected=[f'{name} (__main__.{cls.name}.{name}) ... ok'for name in names]
            self.assertEqual(fixture.decode().splitlines()[:13],expected)
            self.assertEqual(CHECK(transcript(label)),READER_CHECK(transcript(label)));self.assertEqual(CHECK(transcript(label))['names'],names)
    def test02_old_wrong_class_method_renames_order_skip_errors_and_summary_refuse(self):
        raw=transcript();lines=raw.splitlines(keepends=True);swapped=list(lines);swapped[1],swapped[2]=swapped[2],swapped[1]
        cases=[raw.replace(b'PackageControls',b'PackageTests'),raw.replace(b'test_alias_and_live_destinations_refused',b'test_renamed'),b''.join(swapped),raw.replace(b'... ok',b'... skipped MODELED',1),raw+b'ERROR: modeled\n',raw.replace(b'Ran 13 tests',b'Ran 12 tests'),raw.replace(b'\nOK\n',b'\nOK (skipped=1)\n'),raw+raw,raw.replace(b'Starting check()',b'check disabled')]
        for value in cases:
            for parser in(CHECK,READER_CHECK):
                with self.subTest(parser=parser.__name__,body=pin(value)),self.assertRaises(ValueError):parser(value)
    def test03_validation_exception_restores_first_slot_before_same_object_escapes(self):
        error=ValueError('MODELED original package validation failure')
        def fail(raw):raise error
        with model(check=fail)as m:
            with self.assertRaises(ValueError)as caught:m.fn()
            self.assertIs(caught.exception,error);self.assertEqual(m.calls,['build-a']);self.assertEqual(m.events,[('a','build-current'),('build-current','a')]);self.assertTrue((m.recipes/'a').is_dir());self.assertFalse(m.slot.exists());self.assertEqual(m.report['stages'],[]);self.assertNotIn('b',m.report['builds'])
    def test04_command_exception_also_stops_pair_and_restores_slot(self):
        error=KeyboardInterrupt('MODELED interrupted owned command')
        with model(run_error=error)as m:
            try:m.fn()
            except BaseException as caught:self.assertIs(caught,error)
            else:self.fail('original BaseException was discarded')
            self.assertEqual(m.calls,['build-a']);self.assertEqual(m.events,[('a','build-current'),('build-current','a')]);self.assertFalse(m.slot.exists());self.assertTrue((m.recipes/'a').is_dir())
    def test05_slot_cleanup_failure_is_recorded_without_overriding_primary(self):
        primary=ValueError('MODELED first validation failure');later=OSError('MODELED rename failure')
        def fail(raw):raise primary
        with model(check=fail,rename_error=later)as m:
            with self.assertRaises(ValueError)as caught:m.fn()
            self.assertIs(caught.exception,primary);self.assertEqual(m.calls,['build-a']);self.assertEqual(m.events,[('a','build-current'),('build-current','a')]);self.assertEqual(m.report['builds']['a']['source_retirement_failure'],'OSError');self.assertNotIn('b',m.report['builds'])
    def test06_slot_cleanup_failure_without_primary_propagates_itself(self):
        later=OSError('MODELED rename failure after successful validation')
        with model(rename_error=later)as m:
            with self.assertRaises(OSError)as caught:m.fn()
            self.assertIs(caught.exception,later);self.assertEqual(m.calls,['build-a']);self.assertEqual(m.events,[('a','build-current'),('build-current','a')]);self.assertEqual(m.report['builds']['a']['source_retirement_failure'],'OSError')
    def test07_successful_pair_still_builds_twice_and_restores_both_slots(self):
        with model()as m:
            value=m.fn();self.assertEqual(set(value),{'a','b'});self.assertEqual(m.calls,['build-a','build-b']);self.assertEqual(m.events,[('a','build-current'),('build-current','a'),('b','build-current'),('build-current','b')]);self.assertFalse(m.slot.exists());self.assertTrue(all(p.is_file()for p in value.values()));self.assertEqual(m.report['stages'],['build-a','build-b'])
    def test08_only_proven_producer_reader_and_pin_edits(self):
        old=(BASE/'payload/native/developer_tools_alpm_v1.py').read_text();new=(N/'developer_tools_alpm_v1.py').read_text()
        expected=old.replace('PackageTests','PackageControls').replace('  except BaseException as error:\n   primary=error\n\n  finally:','  except BaseException as error:\n   primary=error\n   raise\n\n  finally:')
        self.assertEqual(new,expected)
        oldpin=pin((BASE/'payload/native/developer_tools_alpm_v1.py').read_bytes())['sha256'];newpin=pin(new.encode())['sha256']
        projection=(N/'developer_tools_projection_v1.py').read_text();self.assertEqual(projection,(BASE/'payload/native/developer_tools_projection_v1.py').read_text().replace(oldpin,newpin))
        reader=(N/'developer_tools_reader_v1.py').read_text();parent=(BASE/'safe-failure-v1/payload/native/developer_tools_reader_v1.py').read_text();self.assertEqual(reader,parent.replace('PackageTests','PackageControls').replace(oldpin,newpin))
    def test09_exact_virtual_dc36_parent_and_new200_tree_map_inverse(self):
        profile=json.loads((HERE/'profile.json').read_bytes());rows=json.loads((BASE/'parent-git-objects.json').read_bytes())
        baseprofile=json.loads((BASE/'profile.json').read_bytes())
        for name in baseprofile['removed']:rows.pop(name)
        def apply(root,over):
            for name,row in over.items():
                body=(root/'payload'/name).read_bytes();rows[name]=dict(mode=row['mode'],blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest())
        apply(BASE,baseprofile['overlay']);safe=json.loads((BASE/'safe-failure-v1/profile.json').read_bytes());apply(BASE/'safe-failure-v1',safe['overlay']);self.assertEqual(object_tree(rows),profile['parent_tree'])
        before=dict(rows);apply(HERE,profile['overlay']);self.assertEqual(len(rows),200);self.assertEqual(object_tree(rows),profile['source_tree']);self.assertEqual((profile['changed'],profile['held']),(4,196))
        manifest=json.loads((N/'source-map.json').read_bytes());self.assertEqual(len(manifest['files']),199);self.assertEqual(manifest['actual'],dict(source=None,ref=None,run=None));self.assertEqual(profile['source_map'],pin((N/'source-map.json').read_bytes()))
        for name,row in profile['overlay'].items():self.assertEqual(pin((HERE/'payload'/name).read_bytes()),{k:row[k]for k in('bytes','sha256')})
        for name in profile['overlay']:rows[name]=before[name]
        self.assertEqual(rows,before)

if __name__=='__main__':unittest.main(verbosity=2)
