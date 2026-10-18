# SPDX-License-Identifier: MIT
"""Exact Welcome fixture derivation and bounded rooted child entry.

The original fixture's five CLI, 8/12 compiled and root-refusal assertions stay
unchanged. Its three input paths/stdin are routed and only the compiled C
fixture executable-self setup is derived for unavailable proc. No /dev node creation or proc mount is necessary inside the copy.
"""
import ctypes,hashlib,os,runpy,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
CONTEXT='/var/tmp/caa-welcome5-fixture'
ORIGINAL_SHA='2807126de1544ef4eac48b94159891a2cf0443e5fcc5b4d0c1af5831e90d7753'
ROUTES=((b'stdin=subprocess.DEVNULL',b'stdin=0'),
 (b"'/runner/input-policy.json'",repr(CONTEXT+'/input-policy.json').encode()),
 (b"'/inputs/sources'",repr(CONTEXT+'/sources').encode()),
 (b"'/inputs/products.json'",repr(CONTEXT+'/products.json').encode()))

# Explicit C fixture SETUP only, not byte-exact original C execution.
MANAGEMENT_SOURCE_SHA256=('17a23fa7fce5562c3ddeab9a2dda2aa2853c4c2b40dc532bcd3e21fe9a67f18c', 'f784eb12fcda76574fed49603ce6f276b87cd8649695e7bb63a659c70d83c1d1')
MANAGEMENT_SETUP_ROUTES=((b'#include <sys/wait.h>\n', b'#include <sys/wait.h>\n#include <sys/auxv.h>\n#include <sys/stat.h>\n'), (b'int main(int argc, char **argv)\n', b'/* Source-pinned fixture setup only; the installed product is unchanged. */\nstatic char *fixture_executable_self(const char *argument)\n{\n    GError *error = NULL;\n    char *value = g_file_read_link("/proc/self/exe", &error);\n    if (value != NULL) { g_clear_error(&error); return value; }\n    gboolean unavailable = g_error_matches(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);\n    g_clear_error(&error);\n    if (!unavailable || argument == NULL || !g_path_is_absolute(argument)) return NULL;\n    const char *executed = (const char *)getauxval(AT_EXECFN);\n    if (executed == NULL || strcmp(executed, argument) != 0) return NULL;\n    char *canonical = realpath(argument, NULL);\n    if (canonical == NULL || strcmp(canonical, argument) != 0) { free(canonical); return NULL; }\n    int fd = open(canonical, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);\n    struct stat held, named;\n    gboolean valid = fd >= 0 && fstat(fd, &held) == 0 && lstat(canonical, &named) == 0 &&\n        S_ISREG(held.st_mode) && held.st_nlink == 1 && held.st_uid == geteuid() && held.st_gid == getegid() &&\n        (held.st_mode & S_IXUSR) != 0 && (held.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) == 0 &&\n        held.st_dev == named.st_dev && held.st_ino == named.st_ino && held.st_mode == named.st_mode &&\n        held.st_uid == named.st_uid && held.st_gid == named.st_gid && held.st_nlink == named.st_nlink &&\n        held.st_size == named.st_size && held.st_mtim.tv_sec == named.st_mtim.tv_sec &&\n        held.st_mtim.tv_nsec == named.st_mtim.tv_nsec && held.st_ctim.tv_sec == named.st_ctim.tv_sec &&\n        held.st_ctim.tv_nsec == named.st_ctim.tv_nsec;\n    if (fd >= 0) close(fd);\n    value = valid ? g_strdup(canonical) : NULL;\n    free(canonical);\n    return value;\n}\n\nint main(int argc, char **argv)\n'), (b'    self = g_file_read_link("/proc/self/exe", NULL);\n', b'    self = fixture_executable_self(argv[0]);\n'))
def derive_management_fixture(raw):
 C.need(hashlib.sha256(raw).hexdigest()in MANAGEMENT_SOURCE_SHA256,'whole original Welcome C fixture required')
 for before,after in MANAGEMENT_SETUP_ROUTES:
  C.need(raw.count(before)==1,'one exact management fixture SETUP seam');raw=raw.replace(before,after)
 return raw

ROUTES=ROUTES+((b'def compile_fixture(root,work,name):', b'MANAGEMENT_SOURCE_SHA256=(\'17a23fa7fce5562c3ddeab9a2dda2aa2853c4c2b40dc532bcd3e21fe9a67f18c\', \'f784eb12fcda76574fed49603ce6f276b87cd8649695e7bb63a659c70d83c1d1\')\nMANAGEMENT_SETUP_ROUTES=((b\'#include <sys/wait.h>\\n\', b\'#include <sys/wait.h>\\n#include <sys/auxv.h>\\n#include <sys/stat.h>\\n\'), (b\'int main(int argc, char **argv)\\n\', b\'/* Source-pinned fixture setup only; the installed product is unchanged. */\\nstatic char *fixture_executable_self(const char *argument)\\n{\\n    GError *error = NULL;\\n    char *value = g_file_read_link("/proc/self/exe", &error);\\n    if (value != NULL) { g_clear_error(&error); return value; }\\n    gboolean unavailable = g_error_matches(error, G_FILE_ERROR, G_FILE_ERROR_NOENT);\\n    g_clear_error(&error);\\n    if (!unavailable || argument == NULL || !g_path_is_absolute(argument)) return NULL;\\n    const char *executed = (const char *)getauxval(AT_EXECFN);\\n    if (executed == NULL || strcmp(executed, argument) != 0) return NULL;\\n    char *canonical = realpath(argument, NULL);\\n    if (canonical == NULL || strcmp(canonical, argument) != 0) { free(canonical); return NULL; }\\n    int fd = open(canonical, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);\\n    struct stat held, named;\\n    gboolean valid = fd >= 0 && fstat(fd, &held) == 0 && lstat(canonical, &named) == 0 &&\\n        S_ISREG(held.st_mode) && held.st_nlink == 1 && held.st_uid == geteuid() && held.st_gid == getegid() &&\\n        (held.st_mode & S_IXUSR) != 0 && (held.st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) == 0 &&\\n        held.st_dev == named.st_dev && held.st_ino == named.st_ino && held.st_mode == named.st_mode &&\\n        held.st_uid == named.st_uid && held.st_gid == named.st_gid && held.st_nlink == named.st_nlink &&\\n        held.st_size == named.st_size && held.st_mtim.tv_sec == named.st_mtim.tv_sec &&\\n        held.st_mtim.tv_nsec == named.st_mtim.tv_nsec && held.st_ctim.tv_sec == named.st_ctim.tv_sec &&\\n        held.st_ctim.tv_nsec == named.st_ctim.tv_nsec;\\n    if (fd >= 0) close(fd);\\n    value = valid ? g_strdup(canonical) : NULL;\\n    free(canonical);\\n    return value;\\n}\\n\\nint main(int argc, char **argv)\\n\'), (b\'    self = g_file_read_link("/proc/self/exe", NULL);\\n\', b\'    self = fixture_executable_self(argv[0]);\\n\'))\ndef derive_management_fixture(raw):\n need(hashlib.sha256(raw).hexdigest()in MANAGEMENT_SOURCE_SHA256,\'whole original Welcome C fixture required\')\n for before,after in MANAGEMENT_SETUP_ROUTES:\n  need(raw.count(before)==1,\'one exact management fixture SETUP seam\');raw=raw.replace(before,after)\n return raw\n\ndef proc_self_fixture(root,work):\n original=(root/\'test_management.c\').read_bytes();derived=derive_management_fixture(original)\n path=work/\'root-guard-fixture.c\';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\n with os.fdopen(fd,\'wb\')as out:out.write(derived);out.flush();os.fsync(out.fileno())\n need(path.read_bytes()==derived,\'complete generated C fixture setup\')\n return path\n\ndef compile_fixture(root,work,name):'), (b"+(['-DMANAGEMENT_TEST']if name=='root-guard'else[])", b"+(['-DMANAGEMENT_TEST','-iquote',str(root)]if name=='root-guard'else[])"), (b'+[str(root/n)for n in sources]+', b"+[str(proc_self_fixture(root,work))if n=='test_management.c'else str(root/n)for n in sources]+"))

def derive(raw):
 C.need(C.pin(raw)['sha256']==ORIGINAL_SHA,'whole original Welcome fixture required')
 for before,after in ROUTES:
  C.need(raw.count(before)==1,'single exact Welcome fixture seam');raw=raw.replace(before,after)
 return raw

def zero_caps():
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 libc=ctypes.CDLL(None,use_errno=True);header=Header(0x20080522,0);data=(Data*2)()
 C.need(libc.capset(ctypes.byref(header),ctypes.byref(data))==0,'drop all capability sets')
 C.need(libc.prctl(47,4,0,0,0)==0 and libc.prctl(38,1,0,0,0)==0,'clear ambient capabilities and set NNP')

def status(fd):
 os.lseek(fd,0,os.SEEK_SET);raw=os.read(fd,65537);C.need(len(raw)<=65536,'bounded held process status')
 fields={k:v.strip()for k,v in(line.split(':',1)for line in raw.decode().splitlines()if ':'in line)}
 out={k:int(fields[k],16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')};out.update(NoNewPrivs=int(fields['NoNewPrivs']),uid=os.geteuid(),gid=os.getegid());return out

def enter(root,script,work,role,kind,uid,gid,environment):
 """Run only in a separately supervised child, never in the owning process."""
 C.need(Path(root)==Path('/work/main/root')and script==CONTEXT+'/fixture_checks.py','fixed owned copy/rooted fixture')
 C.need(role in('cachy-asahi-welcome','cachy-asahi-welcome5')and kind in('root-guard','ordinary'),'finite rooted fixture role/kind')
 C.need(type(work)is str and work.startswith(CONTEXT+'/outputs/')and Path(work).as_posix()==work and '..'not in Path(work).parts,'fixed owned fixture output')
 C.need(type(uid)is int and type(gid)is int and((kind=='ordinary'and uid>0 and gid>0)or(kind=='root-guard'and uid==gid==0)),'explicit root/ordinary fixture identity')
 C.need(type(environment)is dict and set(environment)=={'HOME','PATH','LANG','LC_ALL','PYTHONDONTWRITEBYTECODE','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME','XDG_STATE_HOME','XDG_RUNTIME_DIR','TMPDIR'},'closed no-display ordinary environment')
 C.need(environment['PATH']=='/usr/bin:/bin'and environment['PYTHONDONTWRITEBYTECODE']=='1'and all(type(v)is str and '\0'not in v for v in environment.values()),'bounded fixture environment')
 # Retained proc descriptor is opened before chroot; it observes this child after
 # UID/cap changes without mounting /proc inside the supplied ordinary tree.
 proc=os.open('/proc/self/status',os.O_RDONLY|os.O_CLOEXEC)
 try:
  C.capability_profile(status(proc));fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:os.fchdir(fd);os.chroot('.');os.chdir('/')
  finally:os.close(fd)
  if kind=='ordinary':os.setgroups([]);os.setgid(gid);os.setuid(uid);zero_caps()
  C.capability_profile(status(proc),ordinary_child=kind=='ordinary')
 finally:os.close(proc)
 C.need(os.fstat(0).st_rdev==os.makedev(1,3),'owner-inherited stdin must be /dev/null')
 os.environ.clear();os.environ.update(environment)
 sys.argv=[script,*(['--root-guard']if kind=='root-guard'else[]),work,role]
 runpy.run_path(script,run_name='__main__')

def stage(target,policy,products,sources):
 """Create only a fresh fixed context after reading/pinning all source bytes.

 Role4 products must be the ORIGINAL606 Welcome4 operand; a newly built4 pair
 is a separate comparison and is never silently substituted for that operand.
 """
 C.need(Path(target)==Path('/work/main/root')and Path(sources)==Path('/runner/inputs/sources'),'fixed copied-root fixture input boundary')
 roles=('cachy-asahi-welcome','cachy-asahi-welcome5');C.need(set(products)==set(policy['products'])==set(roles),'two actual Welcome fixture roles')
 values={};total=0
 for role,version in zip(roles,('0.1.0-4','0.1.0-5')):
  p=policy['products'][role];C.need(p['package_name']=='cachy-asahi-welcome'and p['version']==products[role]['version']==version and len(p['source_files'])==25 and len(products[role]['payload'])==9,'exact25-source/9-payload versioned fixture role')
  for name,row in p['source_files'].items():
   C.need(Path(name).name==name and name not in('.','..'),'flat source name')
   raw=C.ordinary(Path(sources)/role/name,1024**2);C.need(C.pin(raw)==row,'exact Welcome fixture source leaf');total+=len(raw);C.need(total<=16*1024**2,'aggregate fixture source bound');values['sources/'+role+'/'+name]=raw
 original=C.ordinary(ROOT_FIXTURE(),128*1024);derived=derive(original)
 values.update({'fixture_checks.py':derived,'input-policy.json':C.encoded(policy),'products.json':C.encoded(products)})
 root=Path(target)/CONTEXT.lstrip('/');C.need(not root.exists()and not root.is_symlink(),'fresh fixed fixture context only')
 C.need(not any(p.is_symlink()for p in(root.parent,*root.parent.parents)),'fixture context ancestor alias refused')
 root.mkdir(mode=0o700)
 for name,raw in sorted(values.items()):
  path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as out:out.write(raw)
  path.chmod(0o444)
 for directory in sorted((p for p in root.rglob('*')if p.is_dir()),key=lambda p:len(p.parts),reverse=True):directory.chmod(0o755)
 (root/'outputs').mkdir(mode=0o755);(root/'homes').mkdir(mode=0o755);root.chmod(0o755)
 return dict(context=CONTEXT,files={n:C.pin(raw)for n,raw in values.items()},original_fixture_sha256=ORIGINAL_SHA,derived_fixture_sha256=C.pin(derived)['sha256'],routing='EXACT_FOUR_PATH_STDIN_AND_C_PROC_SELF_SETUP_SEAMS',runtime='NOT_RUN')

def ROOT_FIXTURE():return Path(__file__).resolve().parents[3]/'held-welcome/scripts/ci/welcome5-native-upgrade/fixture_checks.py'

def _failure_data(value,spec):
 """Failure-only bounded original stream DATA; never alters the original guard."""
 try:
  import base64,json
  streams={}
  for name in('stdout','stderr'):
   raw=value[name];tail=raw[-2048:];streams[name]=dict(C.pin(raw),tail_bytes=len(tail),tail_sha256=C.pin(tail)['sha256'],tail_base64=base64.b64encode(tail).decode(),omitted_bytes=len(raw)-len(tail),truncated=len(raw)>len(tail))
  record=dict(schema_version=1,status='ROOTED_FIXTURE_FAILURE_DATA_NOT_ACCEPTANCE',spec_sha256=C.pin(C.encoded(spec))['sha256'],role=spec['role'],kind=spec['kind'],uid=spec['uid'],gid=spec['gid'],outcome={k:value[k]for k in('returncode','termination','direct_child_reaped','group_kill_sent','group_retired','descendants_reaped')},streams=streams,acceptance='NOT_GRANTED')
  raw=(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
  C.need(len(raw)<=8192 and sum(value[k].__len__()for k in('stdout','stderr'))<=128*1024,'bounded original rooted fixture failure DATA')
  sys.stderr.write('CURRENT606_ROOTED_FIXTURE_FAILURE '+raw.decode());sys.stderr.flush()
 except Exception:pass


def run(spec,*,spec_path,timeout=70):
 """Supervise one source-owned child; the enclosing worker owns target lifetime."""
 sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'held-copy/scripts/update'))
 import supervised
 C.need(type(timeout)in(int,float)and 0<timeout<=70,'bounded remaining rooted fixture deadline')
 path=Path(spec_path);C.need(path.parent==Path('/work/fixture-plans')and not path.exists()and not path.is_symlink(),'fresh owned rooted-fixture plan')
 raw=C.encoded(spec);C.need(len(raw)<=16384,'finite rooted-fixture plan')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as out:out.write(raw)
 value=supervised.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--enter',str(path)],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},cwd='/',timeout=timeout,output_limit=128*1024,grace=1,signal_uid=spec['uid'])
 if not(value['returncode']==0 and value['termination']is None and value['direct_child_reaped']is True and value['group_retired']is True):_failure_data(value,spec)
 C.need(value['returncode']==0 and value['termination']is None and value['direct_child_reaped']is True and value['group_retired']is True,'rooted Welcome fixture failed; retained disposal required')
 receipt=C.decode(value['stdout']);C.need(type(receipt)is dict and receipt.get('recipe_role')==spec['role'],'typed rooted fixture receipt')
 return dict(receipt=receipt,retirement={k:value[k]for k in('returncode','termination','direct_child_reaped','group_kill_sent','group_retired','descendants_reaped')},stdout=C.pin(value['stdout']),stderr=C.pin(value['stderr']))

def main():
 C.need(len(sys.argv)==3 and sys.argv[1]=='--enter','fixed private rooted fixture child entry')
 path=Path(sys.argv[2]);C.need(path.parent==Path('/work/fixture-plans'),'fixed owner plan directory')
 spec=C.decode(C.ordinary(path,16384));C.need(set(spec)=={'root','script','work','role','kind','uid','gid','environment','derived_fixture_sha256'},'closed rooted fixture spec')
 raw=C.ordinary(Path(spec['root'])/spec['script'].lstrip('/'),128*1024)
 original=C.ordinary(ROOT_FIXTURE(),128*1024);C.need(raw==derive(original)and C.pin(raw)['sha256']==spec['derived_fixture_sha256'],'whole actual rooted fixture derivative')
 enter(**{k:v for k,v in spec.items()if k!='derived_fixture_sha256'})
if __name__=='__main__':main()
