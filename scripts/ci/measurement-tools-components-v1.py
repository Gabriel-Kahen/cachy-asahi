#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite measurement CI fixture and explicitly scoped source/private tests."""
import argparse,ast,hashlib,importlib.util,json,os,shlex,shutil,stat,subprocess,sys,unittest
from pathlib import Path
PROFILE='manifests/measurement-tools-source-20261028.json'
PROFILE_SHA='24692e6754b466c9172343c80883733fe14b240b18d15b87b109aed397c14ec0'
RECIPE='packages/tools/cachy-asahi-measurement-tools'
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def fixture(root,work):
 body=(root/PROFILE).read_bytes();need(sha(body)==PROFILE_SHA,'exact measurement profile');profile=json.loads(body);rows=profile['files'];need(len(rows)==24,'exact finite24 source rows');out=work/'source';out.mkdir();names=set()
 for row in [*rows,dict(path=PROFILE,bytes=len(body),sha256=PROFILE_SHA,mode='0644')]:
  name=row['path'];p=Path(name);need(name not in names and not p.is_absolute()and all(x not in('','..','.')for x in p.parts),'finite unique relative source path');names.add(name);source=root/p;st=source.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and not source.is_symlink(),'ordinary fixture input');raw=source.read_bytes();need(len(raw)==row['bytes']and sha(raw)==row['sha256']and stat.S_IMODE(st.st_mode)==int(row['mode'],8),'whole fixture byte/mode pin');target=out/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(int(row['mode'],8))
 return out
def static(root):
 adapter=load('measurement_adapter',root/'scripts/checks/check_measurement_tools_v1.py');original=root/'scripts/checks/measurement_tools_package_checks_original_v1.py';need(sha(original.read_bytes())==adapter.ORIGINAL_SHA256,'adapter original checker pin');checks=load('measurement_original_checks',original);report=checks.recipe(root/RECIPE/'PKGBUILD');need(not report['errors'],str(report['errors']));need(report['metadata']['depends']==['python>=3.12'],'supported package Python minimum');print(json.dumps(dict(status='PASS_RETAINED_STATIC_ADAPTER_RECIPE_API',fresh_scope='recipe API only; no makepkg, archive inspection or workloads',makepkg_printsrcinfo='NOT_RUN_HERE_RETAINED_HOST_RECEIPT_ONLY',archive_static='NOT_RUN_HERE_RETAINED_HOST_RECEIPT_ONLY',native='NOT_RUN'),sort_keys=True))
def suite(root,kind,work):
 relative='scripts/release/test_measurement_tools_source_delivery_v1.py'if kind=='source'else RECIPE+'/test_package.py';module=load('measurement_'+kind,root/relative)
 if kind=='source':module.ROOT=root;expected=4
 else:module.RECIPE=root/RECIPE;module.EVIDENCE=work/'package-evidence';expected=8
 tests=unittest.defaultTestLoader.loadTestsFromModule(module);need(tests.countTestCases()==expected,'exact focused count');result=unittest.TextTestRunner(verbosity=2,failfast=True).run(tests);need(result.wasSuccessful()and not result.skipped and result.testsRun==expected,'focused tests failed/skipped/incomplete')
def package(root,work):
 need(shutil.which('bwrap')is not None,'BLOCKED_REQUIRED_SANDBOX: bwrap unavailable; no fallback');selected=Path(sys.executable).resolve();need(selected!=Path('/usr/bin/python3').resolve(),'BLOCKED_SELECTED_INTERPRETER: setup-python isolated prefix required for private launcher bridge');bridge=work/'python-driver';bridge.write_text('#!/bin/sh\nexec '+shlex.quote(str(selected))+' "$@"\n');bridge.chmod(0o755)
 # The fixed installed shebang and workload path select this interpreter only
 # inside a private mount namespace. No host symlink or security policy changes.
 box=['bwrap','--die-with-parent','--ro-bind','/','/','--bind',str(work),str(work),'--ro-bind',str(bridge),'/usr/bin/python3','--dev','/dev','--tmpfs','/sys','--unshare-net','--unshare-pid','--proc','/proc','--']
 check=subprocess.run([*box,'/usr/bin/true'],capture_output=True,timeout=20)
 if check.returncode:
  sys.stderr.buffer.write(check.stderr[:8192]);raise ValueError('BLOCKED_REQUIRED_SANDBOX: private PID/proc/dev/empty-sys/network prerequisite refused; eight controls NOT_RUN; no sudo/unconfined/skip fallback')
 command=[*box,str(selected),'-I','-B','-Werror::ResourceWarning',str(Path(__file__).resolve()),'package-inner','--root',str(root),'--work',str(work)];result=subprocess.run(command,timeout=180);need(result.returncode==0,'eight private package controls failed; no fallback')
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['inspect','source','package','package-inner']);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--work',type=Path,required=True);args=parser.parse_args();need(sys.version_info>=(3,12),'Python>=3.12 required');root=args.root.resolve(strict=True);work=args.work.absolute()
 if args.mode=='package-inner':
  need(os.geteuid()!=0 and Path('/proc/self').is_dir()and Path('/dev/null').exists()and not any(Path('/sys').iterdir()),'private ordinary-user proc/dev/empty-sys prerequisite');print(json.dumps(dict(driver=sys.version,installed_launcher_python=sys.executable,scope='PRIVATE_FIXTURE_ONLY_NO_HOST_SENSOR_OR_SESSION_CENSUS_NO_NATIVE_OR_PERFORMANCE'),sort_keys=True));suite(root,'package',work);return
 need(not work.exists(),'fresh private work required');work.mkdir(mode=0o700,parents=True);root=fixture(root,work);static(root)
 for rel,count in [('scripts/release/test_measurement_tools_source_delivery_v1.py',4),(RECIPE+'/test_package.py',8)]:
  node=ast.parse((root/rel).read_bytes());need(sum(isinstance(x,ast.FunctionDef)and x.name.startswith('test_')for x in ast.walk(node))==count,'static focused suite count')
 if args.mode=='source':suite(root,'source',work)
 elif args.mode=='package':package(root,work)
 else:print(json.dumps(dict(status='PASS_FINITE25_FIXTURE_AND_STATIC_WIRING_ONLY',source_controls='RETAINED_NOT_RERUN',package_controls='RETAINED_NOT_RERUN',package_bwrap_actors=0),sort_keys=True))
if __name__=='__main__':main()
