#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Trusted TEST release assembly actor; private signer never enters consumers."""
import argparse,json,os,re,shutil,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def specification(base,products,source):
 C.need(len(base['packages'])==574 and base['kind']=='complete-target-transaction' and not set(C.VERSIONS)&{p['name'] for p in base['packages']},'actual observed original574 base required')
 return dict(schema_version=1,release_id='apps-full574-test',synthetic=True,target_arch='aarch64',repo_name='apps-full574-test',source_commit=source,
  base=dict(path='base.json',snapshot_id=base['snapshot_id'],sha256=C.sha(C.encoded(base))),packages=products,
  policy=dict(supported_models=['m2-air-13','m2-air-15'],selected_packages=sorted(C.VERSIONS),protected_packages=sorted(p['name'] for p in base['packages']),coordinated_sets=[dict(name='held-original574',versions={p['name']:p['version'] for p in base['packages']})]),
  project_license=dict(path='LICENSE',sha256='',spdx='MIT'),evidence=[])

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_FIXTURE')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'dedicated trusted offline native signing actor required')
 root=Path('/source');C.source(root);directory=Path('/out/release');C.need(not directory.exists(),'fresh TEST release output');directory.mkdir(mode=0o755)
 control=C.decode(C.read(Path('/inputs/control.json')));packet=C.decode(C.read(Path('/inputs/native-index.json')))
 r=C.load('original_release',root/'scripts/release/release.py');signer_api=C.load('original_test_signer',root/'scripts/ci/full-development-composition/run.py')
 assembly=Path('/authority/assembly');assembly.mkdir(mode=0o700);repository=Path('/authority/repository');repository.mkdir(mode=0o700)
 base=C.decode(C.read(Path('/inputs/base.json'),16*1024**2));(assembly/'base.json').write_bytes(C.encoded(base));shutil.copyfile(root/'LICENSE',assembly/'LICENSE')
 products=[]
 try:
  signer=signer_api.sign(directory,Path('/authority'),[]);env=r.gpg_env(Path('/authority/test-signing'),repository)
  for name,row in packet['packages'].items():
   archive=Path('/inputs/archives')/Path(row['files']['a']['path']).name;data=C.read(archive,2*1024**2);C.need(C.sha(data)==row['files']['a']['sha256'],'accepted native archive join')
   shutil.copyfile(archive,assembly/archive.name)
   # This record labels TEST release assembly, not a new native build receipt.
   provenance=dict(schema_version=1,artifact_sha256=C.sha(data),package=dict(name=name,version=row['version'],arch='any'),source_commit=control['source_sha'],
    recipe_sha256=row['source_files']['PKGBUILD']['sha256'],licenses=['MIT'],sources=[dict(url='https://github.com/Gabriel-Kahen/cachy-asahi',commit=row['native_source'])],
    build=dict(execution='synthetic',architecture='aarch64',environment='TEST_RELEASE_ASSEMBLY_NO_REBUILD',snapshot_id='actual-native574-copied-root-test'),
    native_origin=dict(source=row['native_source'],run=row['native_run'],decision=row['decision'],comparison=row['comparison'],archive=row['files']['a'],qualification=row['qualification']))
   record=assembly/(name+'.json');record.write_bytes(C.encoded(provenance))
   products.append(dict(artifact=dict(path=archive.name,sha256=C.sha(data)),provenance=dict(path=record.name,sha256=C.sha(record.read_bytes()))))
  spec=specification(base,products,control['source_sha']);spec['project_license']['sha256']=C.sha((assembly/'LICENSE').read_bytes());(assembly/'spec.json').write_bytes(C.encoded(spec))
  result=r.stage(argparse.Namespace(spec=str(assembly/'spec.json')),repository,signer,env);bundle=Path(result['path']);r.verify_release(bundle,signer,env)
  shutil.copytree(bundle,directory/'bundle',symlinks=True)
  catalog=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',release_sha256=r.sha(directory/'bundle/release.json'),repository=spec['repo_name'],
   applications=[dict(id=role,title=role,description='Exact native candidate in TEST copied-root transaction only',packages=[name]) for role,name in [('apps','cachy-asahi-apps'),('cache','cachy-asahi-cache'),('orphans','cachy-asahi-orphans'),('runtime','cachy-asahi-repository-runtime')]])
  path=directory/'catalog.json';path.write_bytes(C.encoded(catalog));r.sign(path,signer,env)
  (directory/'public.gpg').write_bytes(r.run(['gpg','--batch','--no-options','--homedir','/authority/test-signing','--export',signer],env=env))
  (directory/'control.json').write_bytes(C.encoded(dict(signer=signer,release_sha256=catalog['release_sha256'],catalog_sha256=r.sha(path),synthetic=True,production_trust='NOT_ESTABLISHED',archive_origins='ROOT_ACCEPTED_ORIGINAL_NATIVE_PAIRS_NO_REBUILD',base='ACTUAL_ORIGINAL574_OBSERVED_LOCAL_DB_METADATA')))
 finally:
  subprocess.run(['gpgconf','--homedir','/authority/test-signing','--kill','all'],check=True,capture_output=True,timeout=20)
 for path in (directory,*directory.rglob('*')):
  if not path.is_symlink():os.chmod(path,0o755 if path.is_dir() else 0o644);os.chown(path,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
if __name__=='__main__':main()
