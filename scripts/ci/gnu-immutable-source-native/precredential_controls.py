#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact Source-owned test views; physical runtime and production guards stay held."""
import argparse,ast,hashlib,json,os,stat,sys,types,unittest
from pathlib import Path
LANE='scripts/ci/gnu-immutable-source-native'
PINS={
 'runtime/immutable/test_controls.py':dict(bytes=10193,sha256='7e2cda89fd12e03fbb37bffafa4e946b5e2d4689a7bfb6bd185595d83038c3f8'),
 LANE+'/test_interruption.py':dict(bytes=9210,sha256='4d7b7e5fbab50f7f3002fb84e571d2b6763724256e41f5c374f426ead5458ad2'),
 LANE+'/test_candidate_extraction.py':dict(bytes=18060,sha256='593adac24462c9ac178d913e21f65508880a98742fd7bfdfe5b342e94da3c583'),
 LANE+'/test_recovery_database.py':dict(bytes=3625,sha256='ff8e224fc008971c4266331ef936ae666d6d8b035efd3488ec72529ef091e726')}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(path):
 path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary test-view path');return path
def read(path):
 path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=128*1024,'bounded ordinary singlelink original test');raw=bytearray()
  while len(raw)<=before.st_size:
   part=os.read(fd,min(65536,before.st_size-len(raw)+1))
   if not part:break
   raw.extend(part)
  need(len(raw)==before.st_size and key(before)==key(os.fstat(fd))==key(path.lstat()),'complete stable original test FD/path');return bytes(raw)
 finally:os.close(fd)
def methods(raw):
 text=raw.decode();return{c.name+'.'+n.name:ast.get_source_segment(text,n)for c in ast.parse(text).body if isinstance(c,ast.ClassDef)for n in c.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')}
def one(text,before,after,ledger):
 need(before and text.count(before)==1,'one complete original fixture seam');ledger.append(dict(before=before,after=after,count=1));return text.replace(before,after,1)
def invert(view,ledger):
 text=view.decode()
 for e in reversed(ledger):need(type(e)is dict and set(e)=={'before','after','count'}and type(e['count'])is int and e['count']==1 and text.count(e['after'])==1,'one complete test-view inverse seam');text=text.replace(e['after'],e['before'],1)
 return text.encode()
CLOCK_HELPER='''
from contextlib import contextmanager as _fixture_contextmanager
@_fixture_contextmanager
def _precredential_owned_clock_fixture():
 # Test selection/nonce only: workflow identities are labels, never native authority.
 keys=('SOURCE_SHA','WORKFLOW_SHA','GITHUB_REF_NAME','GITHUB_RUN_ID');provided={key:os.environ.get(key)for key in keys}
 if any(provided.values()):
  source=provided['SOURCE_SHA'];ref=provided['GITHUB_REF_NAME'];run=provided['GITHUB_RUN_ID']
  assert type(source)is str and __import__('re').fullmatch('[a-f0-9]{40}',source)and source==provided['WORKFLOW_SHA'],'same actual workflow source fixture'
  assert type(ref)is str and __import__('re').fullmatch('codex/[a-z0-9-]+',ref)and type(run)is str and run.isdecimal()and 0<int(run)<2**63,'same actual workflow ref/run fixture'
 else:source='8b311a97ba77c426a362d99bee8b60b2de78e7c9';ref='codex/gnu782-composed-controls-native-v1';run='40556751424'
 with tempfile.TemporaryDirectory()as td:
  owner=Path(td).resolve()/'owner';(owner/'disks').mkdir(parents=True);volume=owner/'disks/volume.raw';selection=owner/'selection.json';nonce='1'*32;selected=dict(source_sha=source,nonce=nonce)
  selection.write_text(json.dumps(selected,sort_keys=True,separators=(',',':')));selection.chmod(0o600)
  with patch.dict(os.environ,dict(SOURCE_SHA=source,WORKFLOW_SHA=source,GITHUB_REF_NAME=ref,GITHUB_RUN_ID=run)):
   yield volume,selection,selected,dict(source_sha=source,ref=ref,run_id=int(run),nonce=nonce)
'''
WRONG_OWNER=''' def test_precredential_clock_wrong_owner_selection_refuses(self):
  run=inputs.original('_precredential_owned_qemu_negative','scripts/ci/glibc-debian-maintained-installed16k/run.py')
  with _precredential_owned_clock_fixture()as(volume,selection,selected,identity):
   with patch.object(disk_adapter._ORIGINAL_CLOCK.time,'time_ns',side_effect=AssertionError('NO_CLOCK_FOR_FOREIGN_OWNER')),patch.object(disk_adapter._ORIGINAL_CLOCK.time,'monotonic_ns',side_effect=AssertionError('NO_CLOCK_FOR_FOREIGN_OWNER')):
    with self.assertRaisesRegex(ValueError,'same native owner selection'):disk_adapter.qemu(run.qemu,'Image','boot','work','source','hash')
    foreign='b5a9ef238ab025a7594d7aeb3b581de7c212939d'if selected['source_sha']!='b5a9ef238ab025a7594d7aeb3b581de7c212939d'else'8b311a97ba77c426a362d99bee8b60b2de78e7c9'
    selection.write_text(json.dumps(dict(selected,source_sha=foreign),sort_keys=True,separators=(',',':')))
    with self.assertRaisesRegex(ValueError,'native source/workflow clock identity'):disk_adapter.qemu(run.qemu,'Image','boot',volume,'source','hash')
'''
def immutable_view(text,ledger):
 text=one(text,'class Controls(unittest.TestCase):',CLOCK_HELPER+'\nclass Controls(unittest.TestCase):',ledger)
 before="run=inputs.original('_inert_qemu','scripts/ci/glibc-debian-maintained-installed16k/run.py');argv=disk_adapter.qemu(run.qemu,'Image','boot','work','source','hash');self.assertEqual(sum(x=='-drive'for x in argv),4);self.assertIn('if=none,id=source,format=raw,readonly=on,file=source',argv);self.assertIn('if=none,id=hash,format=raw,readonly=on,file=hash',argv)"
 after="""run=inputs.original('_inert_qemu','scripts/ci/glibc-debian-maintained-installed16k/run.py')
  with _precredential_owned_clock_fixture()as(volume,selection,selected,identity):
   argv=disk_adapter.qemu(run.qemu,'Image','boot',volume,'source','hash');self.assertEqual(sum(x=='-drive'for x in argv),4);self.assertIn('if=none,id=source,format=raw,readonly=on,file=source',argv);self.assertIn('if=none,id=hash,format=raw,readonly=on,file=hash',argv)
   clock=disk_adapter._ORIGINAL_CLOCK;append=argv[argv.index('-append')+1];tokens=[word[len(clock.MARKER):]for word in append.split()if word.startswith(clock.MARKER)];self.assertEqual(len(tokens),1)
   import base64
   raw=base64.b64decode(tokens[0],altchars=b'-_',validate=True);self.assertEqual(base64.urlsafe_b64encode(raw).decode(),tokens[0]);record=clock.identity(clock.decode(raw));self.assertEqual(clock.encode(record),raw);self.assertEqual({key:record[key]for key in identity},identity)"""
 text=one(text,before,after,ledger);return one(text,' def test_composed_source_native_controller_bootstrap_stage_and_default(self):',WRONG_OWNER+'\n def test_composed_source_native_controller_bootstrap_stage_and_default(self):',ledger)
def interruption_view(text,ledger):
 before="values={p.relative_to(ROOT).as_posix():p.read_bytes()for p in(ROOT/'runtime').rglob('*')if p.is_file()};assert{n:I.pin(b)for n,b in values.items()}=={n:w for n,w in POLICY['source'].items()if n.startswith('runtime/')};return{n[8:]:b for n,b in values.items()}"
 after="""values={p.relative_to(ROOT).as_posix():p.read_bytes()for p in(ROOT/'runtime').rglob('*')if p.is_file()}
 import original_signature_source as G
 current={n[8:]:b for n,b in values.items()};profile=G.profile();assert{n:I.pin(b)for n,b in current.items()}==profile['raw_after'];parent=G.normalize(current);assert G.apply(parent,profile['runtime_edits'])==current
 values={'runtime/'+n:b for n,b in parent.items()};assert{n:I.pin(b)for n,b in values.items()}=={n:w for n,w in POLICY['source'].items()if n.startswith('runtime/')};return{n[8:]:b for n,b in values.items()}"""
 return one(text,before,after,ledger)
def recovery_view(text,ledger):
 before="self.assertEqual(X.render(base,case,F,'normal'),F.render(base,case))"
 after="""import original_signature_source as G
    profile=G.profile();normalized=G.normalize(base);self.assertEqual(G.apply(normalized,profile['runtime_edits']),base);oldnormal,oldledger=F.render(normalized,case);expected=G.apply(oldnormal,profile['selected_edits']);expectedledger={name:list(rows)for name,rows in oldledger.items()}
    for name,rows in profile['selected_edits'].items():expectedledger.setdefault(name,[]).extend(dict(row,trust_operation='normal')for row in rows)
    self.assertEqual(G.undo(expected,profile['selected_edits']),oldnormal);self.assertEqual(X.render(base,case,F,'normal'),(expected,expectedledger))"""
 return one(text,before,after,ledger)
def build_view(test,source=None):
 here=Path(__file__).resolve();source=ordinary(source or(here.parents[3]if here.parent.name=='gnu-immutable-source-native'else here.parent/'SOURCE_NOT_SUPPLIED'));test=ordinary(test);need(here.parent.name!='gnu-immutable-source-native'or source==here.parents[3],'explicit source equals wrapper own Source root');need(source.is_dir()and test.is_relative_to(source),'test belongs to exact current Source root');role=test.relative_to(source).as_posix();need(role in PINS,'closed exact original precredential test path');raw=read(test);need(pin(raw)==PINS[role],'whole genuine8b original control body hardpin');ledger=[];text=raw.decode();changed=set();added=set()
 if role=='runtime/immutable/test_controls.py':text=immutable_view(text,ledger);changed={'Controls.test_preparer_init_and_four_disk_QEMU_source_controls'};added={'Controls.test_precredential_clock_wrong_owner_selection_refuses'}
 elif role==LANE+'/test_interruption.py':text=interruption_view(text,ledger)
 elif role==LANE+'/test_recovery_database.py':text=recovery_view(text,ledger);changed={'Controls.test_source_owned_derivation_wrapper_is_required'}
 view=text.encode();need(invert(view,ledger)==raw,'EVERY original test module byte inverse');old_methods,new_methods=methods(raw),methods(view);need(set(new_methods)==set(old_methods)|added and all(new_methods[name]==body for name,body in old_methods.items()if name not in changed),'every other original method name/body held');compile(view,str(test),'exec');return view,ledger,dict(role=role,original=pin(raw),view=pin(view),original_methods=len(old_methods),methods=len(new_methods),changed_methods=sorted(changed),added_methods=sorted(added),whole_inverse='PASS_BYTES_ONLY',physical_source='BYTE_HELD',actual=None,Root_acceptance=None)
def load_view(test,source=None):
 test=ordinary(test);view,ledger,summary=build_view(test,source);name='_source_owned_precredential_controls';module=types.ModuleType(name);module.__file__=str(test);module.__package__=None;source=ordinary(source or Path(__file__).resolve().parents[3]);argv=[str(test)]if summary['role']=='runtime/immutable/test_controls.py'else[str(test),'--source',str(source)];saved_path,saved_argv=sys.path[:],sys.argv[:];old=sys.modules.get(name)
 try:
  sys.argv=argv;sys.modules[name]=module;exec(compile(view,str(test),'exec'),vars(module))
 finally:
  sys.path[:]=saved_path;sys.argv=saved_argv
  if old is None:sys.modules.pop(name,None)
  else:sys.modules[name]=old
 return module,summary
def run(test,source=None):
 test=ordinary(test);saved_path,saved_argv=sys.path[:],sys.argv[:];name='_source_owned_precredential_controls';old=sys.modules.get(name)
 try:
  sys.path.insert(0,str(test.parent));sys.argv=[str(test)];module,summary=load_view(test,source);sys.modules[name]=module;suite=unittest.defaultTestLoader.loadTestsFromModule(module);need(suite.countTestCases()==summary['methods'],'all exact original/new control methods selected');result=unittest.TextTestRunner(verbosity=2).run(suite);view,ledger,late=build_view(test,source);need(late==summary and read(test)==invert(view,ledger),'late original test body held');return(0 if result.wasSuccessful()else 1),dict(summary,status='PASS_SOURCE_OWNED_PRE_CREDENTIAL_TEST_VIEW'if result.wasSuccessful()else'FAIL_SOURCE_OWNED_PRE_CREDENTIAL_TEST_VIEW',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),native='NOT_RUN')
 finally:
  sys.path[:]=saved_path;sys.argv=saved_argv
  if old is None:sys.modules.pop(name,None)
  else:sys.modules[name]=old

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--test',type=Path,required=True);parser.add_argument('--source',type=Path);args=parser.parse_args();code,summary=run(args.test,args.source);print(json.dumps(summary,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
