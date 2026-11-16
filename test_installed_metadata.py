# SPDX-License-Identifier: MIT
"""Actual Bash/filesystem parity; optional readonly private libalpm, never host DB.

--actual-pacman /usr/bin/pacman adds real -Dk/-Ql/-Qlq/-Qoq queries using only
synthetic private database/root/config. No package installation or guest actor.
Fixture Python wrappers are test Source, not new certified guest requirements.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
PACMAN=None
# Exact Source49 post-verify_paths seam; kept as an immutable test oracle when
# root.sh later adopts the helper. Caller still retains SHA/runtime/-Dk gates.
LEGACY=r'''while IFS=$'\t' read -r kind mode uid gid path target extra; do
 [[ -z $extra && $mode =~ ^[0-7]{3,4}$ && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]]
 [[ ( $path == /usr/* || ( $path == /usr && $kind == d ) ) && $path != /usr/local/* ]]
 [[ $(stat -c '%a:%u:%g' -- "$path") == "$mode:$uid:$gid" ]]
 case "$kind" in f) [[ -f $path && ! -L $path && $target == - ]];;d) [[ -d $path && ! -L $path && $target == - ]];;l) [[ -L $path && $(readlink -- "$path") == "$target" && $(readlink -f -- "$path") == /usr/* ]];;*) false;;esac
 pacman -Qoq -- "$path" | grep -qx perl
done < "$D/payload-metadata.tsv"
while IFS=$'\t' read -r path target extra;do
 [[ -z $extra && -f $path && ! -L $path && -f $target && ! -L $target ]]
 [[ $(stat -c '%d:%i' -- "$path") == "$(stat -c '%d:%i' -- "$target")" && $(stat -c '%h' -- "$path") -ge 2 ]]
done < "$D/hardlinks.tsv"
pacman -Qlq "$PACKAGE" | sed 's:/$::' | sort -u > "$S/added.paths"
same_bytes "$D/expected-payload.paths" "$S/added.paths"
'''
WRAPPER=r'''import json,os,pathlib,subprocess,sys
name=pathlib.Path(sys.argv[0]).name;args=sys.argv[1:]
with open(os.environ['TRACE'],'a')as stream:stream.write(json.dumps([name,*args])+'\n')
if name=='pacman':
 if os.environ.get('ACTUAL_PACMAN'):
  os.execv(os.environ['ACTUAL_PACMAN'],[os.environ['ACTUAL_PACMAN'],'--config',os.environ['PRIVATE_CONFIG'],'--root',os.environ['PRIVATE_ROOT'],*args])
 rows=pathlib.Path(os.environ['GLOBAL_ROWS']).read_text().splitlines()
 if args==['-Dk']:sys.exit(0)
 if args==['-Ql']:print('\n'.join(rows));sys.exit(0)
 if args==['-Qlq','perl']:
  sys.stdout.write(pathlib.Path(os.environ['PERL_ROWS']).read_text());sys.exit(0)
 if args[:2]==['-Qoq','--']and len(args)==3:
  p=args[2];canonical=os.path.realpath(os.path.dirname(p)).rstrip('/')+'/'+os.path.basename(p);owners=[]
  for row in rows:
   owner,path=row.split(' ',1)
   if path.rstrip('/')==canonical and owner not in owners:owners.append(owner)
  if owners:print('\n'.join(owners));sys.exit(0)
  sys.exit(1)
 sys.exit(90)
if name=='stat'and args and args[0].startswith('--printf=')and os.environ.get('CHANGE_AFTER_STAT')and not pathlib.Path(os.environ['CHANGE_MARKER']).exists():
 r=subprocess.run(['/usr/bin/stat',*args],capture_output=True);pathlib.Path(os.environ['CHANGE_NODE']).chmod(0o600);pathlib.Path(os.environ['CHANGE_MARKER']).write_text('fiction changed');sys.stdout.buffer.write(r.stdout);sys.exit(r.returncode)
if name=='stat'and args and args[0].startswith('--printf=')and os.environ.get('SURPLUS_STAT'):
 r=subprocess.run(['/usr/bin/stat',*args],capture_output=True);sys.stdout.buffer.write(r.stdout+b'\0');sys.exit(r.returncode)
os.execv('/usr/bin/'+name,[name,*args])
'''


def db_snapshot(root):
 result={}
 for p in (root,*sorted(root.rglob('*'))):
  s=p.lstat();result[str(p.relative_to(root))]=(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns,hashlib.sha256(p.read_bytes()).hexdigest()if p.is_file()else None)
 return result


class Fixture:
 def __init__(self,actual=False,count=0,alias_counterfeit=False,absolute_link=False,chain=False,long_names=False):
  self.temp=tempfile.TemporaryDirectory(prefix='perl-installed-metadata-DATA-');self.top=Path(self.temp.name);self.root=self.top/'root';self.usr=self.root/'usr';self.packet=self.top/'packet';self.bin=self.top/'bin';self.db=self.top/'db'
  for p in(self.packet,self.bin,self.db):p.mkdir(mode=0o700)
  for name in ['','bin','lib','lib/perl','share','share/man']:(self.usr/name).mkdir(parents=True,exist_ok=True);(self.usr/name).chmod(0o755)
  (self.usr/'lib/perl/a').write_bytes(b'Fiction candidate bytes\n');os.link(self.usr/'lib/perl/a',self.usr/'lib/perl/b')
  (self.usr/'share/man/a').write_bytes(b'Fiction manual\n');os.link(self.usr/'share/man/a',self.usr/'share/man/b')
  (self.usr/'bin/tool').symlink_to(str(self.usr/'lib/perl/a')if absolute_link else'../lib/perl/a')
  if chain:(self.usr/'bin/chain').symlink_to('tool')
  for i in range(count):(self.usr/('lib/perl/'+('p'*120 if long_names else'')+f'n{i:05}')).write_bytes(b'Fiction DATA\n')
  if alias_counterfeit:
   (self.usr/'real').mkdir();(self.usr/'real/file').write_bytes(b'Foreign-owned DATA\n');(self.usr/'alias').symlink_to('real')
  self.paths=[p for p in(self.usr,*sorted(self.usr.rglob('*')))if not(alias_counterfeit and p==self.usr/'real/file')]
  if alias_counterfeit:self.paths.append(self.usr/'alias/file')
  self.paths=sorted(self.paths)
  self.lines=[]
  for p in self.paths:
   s=p.lstat();kind='l'if p.is_symlink()else'd'if p.is_dir()else'f';target=os.readlink(p)if kind=='l'else'-';self.lines.append('\t'.join([kind,format(s.st_mode&0o7777,'o'),str(s.st_uid),str(s.st_gid),str(p),target]))
  (self.packet/'payload-metadata.tsv').write_text('\n'.join(self.lines)+'\n');(self.packet/'expected-payload.paths').write_text(''.join(str(p)+'\n'for p in self.paths));(self.packet/'hardlinks.tsv').write_text(str(self.usr/'lib/perl/b')+'\t'+str(self.usr/'lib/perl/a')+'\n'+str(self.usr/'share/man/b')+'\t'+str(self.usr/'share/man/a')+'\n')
  self.perl_files=[str(p.relative_to(self.root))+('/'if p.is_dir()and not p.is_symlink()else'')for p in self.paths];self.aaa_files=['usr/','usr/bin/']+(['usr/real/file']if alias_counterfeit else[])
  (self.top/'perl.rows').write_text(''.join(str(self.root)+'/'+n+'\n'for n in sorted(self.perl_files)));self.global_rows=self.top/'global.rows';self.global_rows.write_text(''.join(owner+' '+str(self.root)+'/'+n+'\n'for owner,names in [('aaa',self.aaa_files),('perl',self.perl_files)]for n in sorted(names)))
  local=self.db/'local';local.mkdir();(local/'ALPM_DB_VERSION').write_text('9\n')
  for name,version,files in [('aaa','1-1',self.aaa_files),('perl','5.42.3-1.3',self.perl_files)]:
   q=local/(name+'-'+version);q.mkdir();(q/'desc').write_text('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n%DESC%\nFiction readonly ownership fixture\n\n%ARCH%\naarch64\n\n');(q/'files').write_text('%FILES%\n'+'\n'.join(sorted(files))+'\n\n')
  self.config=self.top/'pacman.conf';self.config.write_text('[options]\nArchitecture = aarch64\nDBPath = '+str(self.db)+'\nLogFile = '+str(self.top/'UNUSED.log')+'\nCacheDir = '+str(self.top/'UNUSED-cache')+'\nGPGDir = '+str(self.top/'UNUSED-trust')+'\n')
  for name in ['UNUSED-cache','UNUSED-trust']:(self.top/name).mkdir(mode=0o500)
  for p in self.db.rglob('*'):p.chmod(0o500 if p.is_dir()else 0o400)
  self.db.chmod(0o500);self.before=db_snapshot(self.db);self.actual=actual
  for command in ['pacman','stat','readlink']:
   p=self.bin/command;p.write_text('#!'+sys.executable+' -I\n'+WRAPPER);p.chmod(0o755)
 def close(self):
  assert db_snapshot(self.db)==self.before,'readonly private ALPM DB changed'
  assert not(self.top/'UNUSED.log').exists()
  for name in ['UNUSED-cache','UNUSED-trust']:assert not list((self.top/name).iterdir())
  self.db.chmod(0o700)
  for p in self.db.rglob('*'):p.chmod(0o700 if p.is_dir()else 0o600)
  self.temp.cleanup()
 def run(self,legacy=False,surplus=False,change=False):
  out=self.top/('legacy'if legacy else'new');out.mkdir(mode=0o700);trace=out/'trace.jsonl';helper=out/'helper.sh'
  source=(HERE/'guest/installed-metadata.sh').read_text();assert source.count('local prefix=/usr')==1;source=source.replace('local prefix=/usr','local prefix='+shlex.quote(str(self.usr)));helper.write_text(source)
  body=LEGACY.replace('/usr',str(self.usr))if legacy else'. '+shlex.quote(str(helper))+'\nverify_installed_metadata "$D" "$S"\n'
  script='set -Eeuo pipefail\n. '+shlex.quote(str(HERE/'guest/case.sh'))+'\nD='+shlex.quote(str(self.packet))+'\nS='+shlex.quote(str(out))+'\nPACKAGE=perl\npacman -Dk > "$S/Dk.log"\n'+body+'printf REACHED\n'
  env=dict(PATH=str(self.bin)+':/usr/bin:/bin',HOME=str(self.top),LC_ALL='C',TZ='UTC',TRACE=str(trace),PRIVATE_ROOT=str(self.root),PRIVATE_CONFIG=str(self.config),GLOBAL_ROWS=str(self.global_rows),PERL_ROWS=str(self.top/'perl.rows'))
  if self.actual:env['ACTUAL_PACMAN']=PACMAN
  if surplus:env['SURPLUS_STAT']='1'
  if change:env.update(CHANGE_AFTER_STAT='1',CHANGE_NODE=str(self.usr/'lib/perl/a'),CHANGE_MARKER=str(out/'changed'))
  r=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',script],cwd=self.top,env=env,capture_output=True,timeout=90)
  calls=[json.loads(l)for l in trace.read_text().splitlines()]if trace.exists()else[]
  return r,calls


class PortableControls(unittest.TestCase):
 ACTUAL=False
 def fixture(self,**kwargs):
  f=Fixture(actual=self.ACTUAL,**kwargs);self.addCleanup(f.close);return f
 def parity(self,mutate=None,pass_expected=True,**kwargs):
  f=self.fixture(**kwargs)
  if mutate:mutate(f)
  old,_=f.run(True);new,_=f.run();self.assertEqual(old.returncode==0,pass_expected,old.stderr.decode());self.assertEqual(new.returncode==0,pass_expected,new.stderr.decode());return f
 def test_regular_directory_symlink_hardlink_and_shared_directory_parity(self):self.parity()
 def test_absolute_and_chained_leaf_aliases_preserve_ownership(self):self.parity(absolute_link=True,chain=True)
 def test_canonical_parent_counterfeit_membership_refuses(self):self.parity(alias_counterfeit=True,pass_expected=False)
 def test_missing_changed_kind_mode_UID_and_GID_refuse(self):
  cases=[lambda f:(f.usr/'bin/tool').unlink(),lambda f:(f.usr/'lib/perl/a').chmod(0o600),lambda f:((f.usr/'lib/perl/a').unlink(),(f.usr/'lib/perl/a').mkdir()),lambda f:self.change_uid(f,2),lambda f:self.change_uid(f,3)]
  for mutation in cases:
   with self.subTest(mutation=mutation):self.parity(mutation,False)
 def change_uid(self,f,index):
  rows=[line.split('\t')for line in f.lines];rows[-1][index]=str(int(rows[-1][index])+1);(f.packet/'payload-metadata.tsv').write_text(''.join('\t'.join(r)+'\n'for r in rows))
 def test_changed_link_target_outside_target_and_cycle_refuse(self):
  for target in ['../lib/perl/b','../../outside','tool']:
   def mutation(f,target=target):p=f.usr/'bin/tool';p.unlink();p.symlink_to(target)
   with self.subTest(target=target):self.parity(mutation,False)
 def test_broken_hardlink_association_refuses(self):
  def mutation(f):p=f.usr/'lib/perl/b';p.unlink();p.write_bytes(b'Fiction candidate bytes\n')
  self.parity(mutation,False)
 def test_missing_and_extra_inventory_refuse(self):
  for extra in [False,True]:
   def mutation(f,extra=extra):
    if self.ACTUAL:
     names=f.perl_files+['usr/MISSING-FOREIGN']if extra else f.perl_files[1:];p=f.db/'local/perl-5.42.3-1.3/files';p.chmod(0o600);p.write_text('%FILES%\n'+'\n'.join(sorted(names))+'\n\n');p.chmod(0o400);f.before=db_snapshot(f.db)
    else:
     p=f.top/'perl.rows';lines=p.read_text().splitlines(keepends=True);p.write_text(''.join(lines+['/MISSING/FOREIGN\n']if extra else lines[1:]))
   with self.subTest(extra=extra):self.parity(mutation,False)
 def test_node_changed_during_batched_collection_refuses(self):
  f=self.fixture();new,_=f.run(change=True);self.assertNotEqual(new.returncode,0)
 def test_batched_stat_stream_surplus_refuses(self):
  f=self.fixture();new,_=f.run(surplus=True);self.assertNotEqual(new.returncode,0)
 def test_complete_metadata_paths_and_duplicate_rows_refuse(self):
  for duplicate in [False,True]:
   f=self.fixture();rows=f.lines[:-1]if not duplicate else f.lines+[f.lines[-1]];(f.packet/'payload-metadata.tsv').write_text('\n'.join(rows)+'\n');new,_=f.run();self.assertNotEqual(new.returncode,0)
 def test_global_projection_and_bounded_exec_4352_file_scale(self):
  f=self.fixture(count=4352);new,calls=f.run();self.assertEqual(new.returncode,0,new.stderr.decode());queries=[c[1:]for c in calls if c[0]=='pacman'];self.assertEqual(queries,[['-Dk'],['-Ql'],['-Qlq','perl']]);self.assertNotIn(['-Qoq'],queries)
  batches=[c[2:]for c in calls if c[0]=='stat'and c[1].startswith('--printf=')]
  self.assertGreater(len(batches),1)
  for argv in batches:
   self.assertEqual(argv[0],'--');self.assertLessEqual(len(argv)-1,128);self.assertLessEqual(sum(len(p)+1 for p in argv[1:]),16384)
  self.assertEqual(sum(len(a)-1 for a in batches),2*len(f.paths))
 def test_long_path_batches_obey_byte_bound(self):
  f=self.fixture(count=150,long_names=True);new,calls=f.run();self.assertEqual(new.returncode,0,new.stderr.decode());batches=[c[3:]for c in calls if c[0]=='stat'and c[1].startswith('--printf=')]
  self.assertTrue(any(len(a)<128 for a in batches[:-1]));self.assertTrue(all(sum(len(p)+1 for p in a)<=16384 for a in batches))
 def test_certified_runtime_tools_only_and_readonly_query_surface(self):
  source=(HERE/'guest/installed-metadata.sh').read_text();self.assertNotRegex(source,r'\b(?:awk|python[0-9.]*|perl|join|dirname)\s+-')
  self.assertNotIn('pacman -Qoq',source);self.assertNotIn('pacman -Qo ',source);self.assertNotRegex(source,r'pacman\s+-(?:S|U|R|D[^k])');self.assertIn('pacman -Qlq perl',source);self.assertIn('pacman -Ql >',source)
  result=subprocess.run(['/usr/bin/bash','-n',str(HERE/'guest/installed-metadata.sh')],capture_output=True,timeout=5);self.assertEqual(result.returncode,0,result.stderr)


class ActualPrivateALPMControls(PortableControls):
 ACTUAL=True
 def test_multiple_regular_or_symlink_owners_Dk_refuse_before_helper(self):
  for names in [['usr/','usr/bin/','usr/lib/','usr/lib/perl/','usr/lib/perl/a'],['usr/','usr/bin/','usr/bin/tool']]:
   f=self.fixture();p=f.db/'local/aaa-1-1/files';p.chmod(0o600);p.write_text('%FILES%\n'+'\n'.join(names)+'\n\n');p.chmod(0o400);f.before=db_snapshot(f.db)
   for legacy in [True,False]:
    result,calls=f.run(legacy);self.assertNotEqual(result.returncode,0);self.assertEqual([c[1:]for c in calls if c[0]=='pacman'],[['-Dk']])
 def test_duplicate_package_record_Dk_refuses_before_helper(self):
  f=self.fixture();f.db.chmod(0o700);(f.db/'local').chmod(0o700);q=f.db/'local/counterfeit-1-1';q.mkdir();original=f.db/'local/perl-5.42.3-1.3'
  for name in ['desc','files']:(q/name).write_bytes((original/name).read_bytes());(q/name).chmod(0o400)
  q.chmod(0o500);(f.db/'local').chmod(0o500);f.db.chmod(0o500);f.before=db_snapshot(f.db);new,calls=f.run();self.assertNotEqual(new.returncode,0);self.assertEqual([c[1:]for c in calls if c[0]=='pacman'],[['-Dk']])


def main():
 global PACMAN
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--actual-pacman',type=Path);a=p.parse_args()
 if a.actual_pacman:
  if not a.actual_pacman.is_absolute()or not a.actual_pacman.is_file():p.error('explicit absolute host pacman path')
  PACMAN=str(a.actual_pacman)
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(PortableControls)
 if PACMAN:suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ActualPrivateALPMControls))
 result=unittest.TextTestRunner(verbosity=2).run(suite);return 0 if result.wasSuccessful()else 1
if __name__=='__main__':raise SystemExit(main())
