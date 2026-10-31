#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit Orphans selection + independent signed Apps removal, owned offline copy only."""
import argparse,hashlib,importlib.util,json,os,re,sys,tempfile,types
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
MAX_INPUT=32*1024**2
NAME=re.compile(r'[a-z0-9][a-z0-9+_.-]{0,127}\Z')
sha=lambda raw:hashlib.sha256(raw).hexdigest()
encoded=lambda value:(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def need(ok,reason):
 if not ok:raise ValueError(reason)


def pinned_module(name,path,expected):
 """Compile the exact checked bytes, avoiding a second unpinned import read."""
 need(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected),'explicit source SHA256 required')
 need(path.is_absolute() and path.resolve(strict=True)==path and path.is_file(),'canonical source file required')
 with path.open('rb') as stream:raw=stream.read(MAX_INPUT+1)
 need(len(raw)<=MAX_INPUT and sha(raw)==expected,'source bytes differ: '+str(path))
 value=types.ModuleType(name);value.__file__=str(path);sys.modules[name]=value
 exec(compile(raw,str(path),'exec'),value.__dict__)
 return value


def load_backend(expected_sha):
 return pinned_module('orphans_apps_backend',ROOT/'scripts/apps/transaction.py',expected_sha)


def load_orphans(directory,expected_sha):
 path=Path(directory)
 need(path.is_absolute() and path.resolve(strict=True)==path,'canonical Orphans source directory required')
 return pinned_module('orphans_exact_readonly',path/'cachy-asahi-orphans',expected_sha)


def caller_before(args):
 result={key:getattr(args,'before_'+key) for key in ('tree_sha256','database_sha256','packages_sha256','inventory_sha256')}
 need(all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in result.values()),'four explicit before pins required')
 return result


def preflight(args,T,O):
 need(args.confirm_orphan_removal is True and args.confirm_disposable_transaction is True,'both explicit removal confirmations required')
 need(args.operation=='remove','only explicit removal is supported')
 names=args.selected_names
 need(type(names) is list and 0<len(names)<=O.MAX_PACKAGES and len(set(names))==len(names) and all(type(n) is str and NAME.fullmatch(n) for n in names),'nonempty unique explicit orphan names required')
 workspace,root,owner=T.root_guard(args);app,c,r=T.app_source(args);budget=T.limits();closure=T.closure_for(args,budget)
 need(closure is not None or 'apps_full574_binding' not in owner['copy'],'full574 copy requires original explicit policy/lease')
 if closure is not None:closure.owner(owner)
 expected=caller_before(args)
 def observation():
  inventory=app.inventory_reader().collect(root/T.DB,c,lambda row:app.package(row,r))
  return inventory,T.pins(T.observe(root,budget,closure),inventory)
 with T.locked(workspace):
  inventory,before=observation();need(before==expected,'complete before snapshot differs before Orphans verification')
  orphan_path=O.absolute(args.orphan_plan);saved,record=O.json_file(orphan_path)
  need(record['sha256']==args.orphan_plan_sha256,'caller Orphans plan SHA256 differs')
  need(saved.get('operation')=='EXPLICIT_ORPHAN_REMOVAL_PLAN' and type(saved.get('selected')) is dict,'explicit Orphans removal plan required')
  need(set(saved['selected'])==set(names),'Orphans plan selection differs from exact caller names')
  assessment,assessment_record=O.json_file(O.absolute(saved['assessment']))
  need(assessment.get('root')==str(root) and assessment.get('dbpath')==str(root/T.DB),'Orphans assessment targets a different copied root/database')
  plan_raw=c.read_path(Path(args.plan).absolute(),T.MAX_PLAN)
  need(sha(plan_raw)==args.plan_sha256,'caller signed Apps plan SHA256 differs')
  with tempfile.TemporaryDirectory(prefix='orphans-auth-',dir=workspace) as temporary:
   work=Path(temporary);copied=T.snapshot_inputs(args,work,c);iv=work/'installed.json';iv.write_bytes(app.encoded(inventory))
   copied.installed=str(iv);copied.installed_sha256=sha(iv.read_bytes());copied.command='plan'
   fresh=app.execute(copied)
   need(app.encoded(fresh)==plan_raw,'independently authenticated Apps removal plan differs')
   plan=fresh['plan']
   need(plan['operation']=='remove' and not plan['additions'] and not plan['upgrades'],'Apps plan contains a non-removal operation')
   removals=plan['removals']
   need(len(removals)==len(names) and {row['name'] for row in removals}==set(names),'signed Apps removals differ from exact orphan selection')
   need(not plan['dependencies'] and not plan['conflicts'],'implicit dependency/conflict expansion refused')
   versions={row['name']:row['version'] for row in removals}
   need(all(saved['selected'][name]['version']==version for name,version in versions.items()),'signed removal version differs from Orphans plan')
  # The unchanged read-only API checks candidate reasons, protections, saved DB
  # identity, hard dependencies and currently satisfied optional dependencies.
  need(O.plan(O.absolute(saved['assessment']),names)==saved,'Orphans plan no longer verifies against current metadata')
  _,after=observation();need(after==expected==before,'copied state changed across Orphans verification')
  _,again=O.json_file(orphan_path);need(again==record,'Orphans plan changed during verification')
 return dict(scope='READONLY_ORPHAN_FACTS_BOUND_TO_APPS_COMPLETE_BEFORE_CONTENTS',
             orphan_plan_sha256=record['sha256'],assessment_sha256=assessment_record['sha256'],
             selected={name:versions[name] for name in sorted(versions)},before=before,
             orphans_source_sha256=args.orphans_source_sha256,apps_backend_sha256=args.apps_backend_sha256,
             metadata='PASS_CURRENT_METADATA_ONLY',apply_authority='INDEPENDENT_SIGNED_APPS_REMOVAL_PLAN_REQUIRED')


def apply(args):
 """Already-supervised-owner API; default CLI supplies process supervision."""
 result=dict(status='FAIL',phase='orphan-guard',commit_started=False,packages_committed=False,
             rollback='NOT_ATTEMPTED_DISPOSABLE_COPY_ONLY',hardware='NOT_RUN',release='NOT_ADMITTED',cleanup='NOT_ESTABLISHED')
 delegated=False
 try:
  need(args.confirm_orphan_removal is True and args.confirm_disposable_transaction is True,'both explicit removal confirmations required')
  T=load_backend(args.apps_backend_sha256)
  T.root_guard(args) # Refuse host/missing copy before importing the read-only tool.
  O=load_orphans(args.orphans_source,args.orphans_source_sha256)
  binding=preflight(args,T,O)
  delegated=True;result=T.apply(args)
  result['orphan_binding']=binding
  if result.get('status')=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION':
   need(result.get('prepared_add')=={} and result.get('prepared_remove')==binding['selected'],'backend committed a different selection')
  return result
 except BaseException as error:
  result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024],
                recovery='DISPOSE_OWNED_COPY_ON_COMMIT_OR_CLEANUP_UNCERTAINTY_NO_ROLLBACK_CLAIM')
  if delegated and result.get('status')!='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION':
   # An adapter error after delegation cannot establish a non-commit outcome.
   result.update(commit_started='UNKNOWN',packages_committed='UNKNOWN')
  return result


def arguments(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('apply',))
 for name in ('workspace','ownership-sha256','apps-source','apps-provenance-sha256','repository-source','apps-backend-sha256',
              'orphans-source','orphans-source-sha256','orphan-plan','orphan-plan-sha256',
              'release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','plan','plan-sha256',
              'before-tree-sha256','before-database-sha256','before-packages-sha256','before-inventory-sha256'):
  p.add_argument('--'+name,required=True)
 for name in ('full574-policy','full574-policy-sha256','full574-lease','full574-lease-sha256'):p.add_argument('--'+name)
 p.add_argument('--applications',nargs='+',required=True);p.add_argument('--selected-names',nargs='+',required=True)
 p.add_argument('--confirm-orphan-removal',action='store_true');p.add_argument('--confirm-disposable-transaction',action='store_true')
 p.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
 a=p.parse_args(argv);a.operation='remove';return a


def main(argv=None):
 a=arguments(argv);worker_started=False
 try:
  need(a.confirm_orphan_removal and a.confirm_disposable_transaction,'both explicit removal confirmations required')
  if a.worker:result=apply(a)
  else:
   T=load_backend(a.apps_backend_sha256);T.root_guard(a)
   worker_started=True
   row=T.SUP.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),*(sys.argv[1:] if argv is None else argv),'--worker'],
                 env=dict(os.environ),cwd=str(Path(a.workspace).absolute()),timeout=T.SECONDS,output_limit=1024**2)
   need(row['termination'] is None and row['direct_child_reaped'] and row['returncode'] in (0,1),'adapter worker interrupted or failed; commit outcome unknown; dispose owned copy')
   result=T.I.decode(row['stdout'])
   need(result.get('status')==('FAIL' if row['returncode'] else 'PASS_OWNED_DISPOSABLE_APPS_TRANSACTION'),'worker outcome differs')
   result['worker']={k:row[k] for k in ('returncode','termination','direct_child_reaped','group_kill_sent')}
  print(encoded(result).decode(),end='');return int(result['status']=='FAIL')
 except BaseException as error:
  print(encoded(dict(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024],
                     packages_committed='UNKNOWN' if worker_started else False,commit_started='UNKNOWN' if worker_started else False,
                     recovery='DISPOSE_OWNED_COPY_IF_COMMIT_OR_CLEANUP_UNCERTAIN',rollback='NOT_CLAIMED')).decode(),end='');return 1

if __name__=='__main__':raise SystemExit(main())
