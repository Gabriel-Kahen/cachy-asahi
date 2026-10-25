#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unchanged39+11 suites on an owned private128MiB/16384-inode filesystem."""
import argparse,json,os,re,shutil,signal,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C
TITLE='Run unchanged installer controls and focused604 controls without actors'
SHELL="""set -euo pipefail
python3 -B -m unittest discover -s expanded604-installer/scripts/ci/expanded600-installer-vm -p 'test_*.py' -v
python3 -B -m unittest discover -s expanded604-installer/scripts/ci/expanded604-apps6-public-pair-installer -p 'test_*.py' -v
"""
MOUNT="""mount --make-rprivate /
mount -t tmpfs -o size=128m,nr_inodes=16384,mode=0700 tmpfs "$1"
trap 'umount "$1"' EXIT
TMPDIR="$1" "$2" -I -B "$3" --inside "$1" --workspace "$4"
"""
ROLES=('expanded604-installer','expanded604-legacy','expanded604-seven','expanded604-fresh600-decisions')
def original_shell(raw):
 section=raw.decode().split('      - name: '+TITLE+'\n',1)[1].split('      - name:',1)[0]
 return '\n'.join(line[10:]for line in section.split('        run: |\n',1)[1].splitlines()if line.startswith('          '))+'\n'
def counts(stderr):
 C.need([int(n)for n in re.findall(rb'Ran (\d+) tests?',stderr)]==[39,11],'exact nonzero original39+11 suites required')
def inside(mount,workspace):
 C.need(os.environ.get('TMPDIR')==str(mount)and os.path.ismount(mount),'owned private tmpfs required');v=os.statvfs(mount);C.need(v.f_blocks*v.f_frsize==128*1024**2 and v.f_files==16384,'exact private filesystem capacity')
 with tempfile.TemporaryDirectory(prefix='fresh607-controls-',dir=mount)as folder:
  work=Path(folder)
  rows=json.loads(C.read(C.HERE/'control-inputs.json'));C.need(set(rows)==set(ROLES),'closed control input roles')
  for role in ROLES:
   for name,w in rows[role].items():
    out=work/role/name;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(C.checked(workspace/role/name,w))
  C.need(not any((q/'manifests/packages.toml').is_file()for q in work.parents),'standalone source controls required')
  lib=work/ROLES[0];C.need(original_shell(C.read(lib/'.github/workflows/native-arm-expanded604-apps6-public-pair-installer.yml'))==SHELL,'entire original control shell held')
  home=work/'home';home.mkdir(mode=0o700);binpath=work/'bin';binpath.mkdir();(binpath/'python3').symlink_to(sys.executable)
  env=dict(os.environ,HOME=str(home),PATH=str(binpath)+':'+os.environ['PATH'],PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1',GITHUB_WORKSPACE=str(work),EXPANDED600_LEGACY_ROOT=str(work/ROLES[1]),EXPANDED600_SEVEN_ROOT=str(work/ROLES[2]),CURRENT604_INSTALLER_SOURCE=str(lib),PUBLIC_PAIR_INSTALLER_ROOT=str(lib),PUBLIC_PAIR_COMPOSITION_ROOT=str(lib),EXPANDED604_SOURCE=str(lib),EXPANDED604_LEGACY_ROOT=str(work/ROLES[1]),EXPANDED604_FRESH600_DECISION=str(work/ROLES[3]/'payload/fresh600.json'))
  for key in ('PYTHONPATH','PYTHONHOME','GH_TOKEN','GITHUB_TOKEN'):env.pop(key,None)
  result=subprocess.run(['bash','--noprofile','--norc','-e','-o','pipefail','-c',SHELL],cwd=work,env=env,capture_output=True,timeout=120)
  sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr);C.need(result.returncode==0,'original source suites failed');counts(result.stderr)
class OwnerSignal(RuntimeError):pass
def run(workspace):
 workspace=C.safe(workspace)
 def interrupted(number,frame):raise OwnerSignal('source-control owner signal '+str(number))
 previous={number:signal.signal(number,interrupted)for number in(signal.SIGTERM,signal.SIGHUP)}
 try:return owned(workspace)
 finally:
  for number,handler in previous.items():signal.signal(number,handler)
def owned(workspace):
 with tempfile.TemporaryDirectory(prefix='fresh607-exclusive-',dir='/tmp')as directory:
  mount=Path(directory);before=mount.stat().st_dev;ns=os.readlink('/proc/self/ns/mnt');process=None
  try:
   process=subprocess.Popen(['unshare','--user','--map-root-user','--mount','--net','--','bash','--noprofile','--norc','-euo','pipefail','-c',MOUNT,'bash',str(mount),sys.executable,str(Path(__file__).resolve()),str(workspace)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
   try:stdout,stderr=process.communicate(timeout=120)
   except BaseException:
    if process.poll()is None:os.killpg(process.pid,signal.SIGTERM)
    try:process.communicate(timeout=10)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.communicate(timeout=10)
    raise
   C.need(len(stdout)+len(stderr)<=4*1024**2,'finite source-control output');sys.stdout.buffer.write(stdout);sys.stderr.buffer.write(stderr);C.need(process.returncode==0,'isolated source-control child failed');counts(stderr)
  finally:
   C.need(process is None or process.poll()is not None,'source-control child reaped');C.need(mount.stat().st_dev==before and not os.path.ismount(mount)and os.readlink('/proc/self/ns/mnt')==ns and not list(mount.iterdir()),'host unchanged; private mount retired and directory empty')
 return dict(status='PASS_EXACT_PRIVATE_39_AND11_SOURCE_CONTROLS',python=sys.version.split()[0],capacity='TMPFS_128MiB_16384_INODES',shell=C.pin(SHELL.encode()),cleanup='CHILD_REAPED_PRIVATE_MOUNT_GONE_HOST_EMPTY',runtime='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--workspace',type=Path,required=True);p.add_argument('--inside',type=Path);a=p.parse_args()
 if a.inside:inside(a.inside,a.workspace)
 else:print(json.dumps(run(a.workspace),sort_keys=True))
