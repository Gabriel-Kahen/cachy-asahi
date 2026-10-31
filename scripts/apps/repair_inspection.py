#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Readonly authenticated reinstall before-pins for an owned full574 disposable copy."""
import argparse,importlib.util,os,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
MAX_REPORT=512*1024

def backend():
 spec=importlib.util.spec_from_file_location('apps_readonly_repair_backend',HERE/'transaction.py');module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module

def no_pending(T,workspace,root):
 # Readonly inspection cannot reserve ALPM. Refuse any visible lock or unknown
 # prior attempt; apply still rechecks full pins under its real ALPM exclusion.
 for path in (root/T.DB/'db.lck',workspace/'apps-pending.json'):
  T.need(not os.path.lexists(path),'foreign ALPM lock or pending transaction; no deletion or waiver')

def authenticated_plan(T,args,app,c,r,inventory,work):
 raw=c.read_path(Path(args.plan).absolute(),T.MAX_PLAN);T.need(T.sha(raw)==args.plan_sha256,'caller plan SHA256 differs')
 copied=T.snapshot_inputs(args,work,c);path=work/'installed.json';path.write_bytes(app.encoded(inventory));copied.installed=str(path);copied.installed_sha256=T.sha(path.read_bytes());copied.command='plan'
 fresh=app.execute(copied);T.need(app.encoded(fresh)==raw,'authenticated plan differs from actual copied root')
 expected=T.expected_packages(app,inventory,fresh['plan'],r)
 T.need(app.indexed(inventory['packages'],r)==expected,'readonly reinstall must preserve exact inventory')
 return copied,fresh,raw

def inspect_reinstall(args):
 T=backend();result=dict(status='FAIL',scope='READONLY_AUTHENTICATED_OWNED_FULL574_REINSTALL_PREPARATION',commit_started=False,packages_committed=False,transaction='NOT_RUN',commit_fields_scope='THIS_READONLY_INSPECTION_ONLY',prior_attempt_commit_outcome='NOT_DETERMINED',installer_authority=False,repair_authority=False,hardware='NOT_RUN',release='NOT_ADMITTED')
 try:
  T.need(args.operation=='reinstall','explicit reinstall inspection only')
  workspace,root,owner=T.root_guard(args);app,c,r=T.app_source(args);budget=T.limits(args)
  with T.locked(workspace),tempfile.TemporaryDirectory(prefix='apps-repair-inspect-',dir=workspace) as temporary:
   work=Path(temporary);no_pending(T,workspace,root);closure=T.closure_for(args,budget)
   T.need(closure is not None and callable(getattr(closure,'authorize_reinstall',None)),'original explicit full574 repair policy/lease and backend required');closure.owner(owner)
   inventory=app.inventory_reader().collect(root/T.DB,c,lambda row:app.package(row,r));T.need(len(inventory['packages'])<=budget.max_packages,'full-root package bound')
   copied,fresh,plan_raw=authenticated_plan(T,args,app,c,r,inventory,work)
   T.need(fresh['synthetic'] or os.uname().machine=='aarch64','actual ARM release needs native ARM inspection')
   with app.authenticated(copied,c,r) as context:
    plan=fresh['plan'];add={row['after']['name']:row['after']['version'] for row in plan.get('reinstalls',[])}
    protected=set(context['base'])|set(context['spec']['policy']['protected_packages']);T.need(not set(add)&protected,'base/platform selection refused')
    # Same internal authorization seam as apply. No caller permission schema,
    # CLI ignore-lock flag, generic-inspect waiver or mutation path is introduced.
    closure.authorize_reinstall(plan,inventory,context,args.plan_sha256)
    current=app.inventory_reader().collect(root/T.DB,c,lambda row:app.package(row,r));T.need(current==inventory,'repair authentication inventory drift');no_pending(T,workspace,root)
    before=T.observe(root,budget,closure);closure.selection(add,{},inventory,before['nodes']);closure.capture(root,before)
    payload={};accounting=dict(bytes=0,nodes=0);archives={}
    for row in context['release']['packages']:
     if row['name'] not in add:continue
     path=Path(copied.release)/'repo'/row['filename'];nodes=T.I.archive_payload(path,accounting);members=r.archive_members(path)
     T.need('.INSTALL' not in members,'package scriptlet refused');pkginfo=r.run(['bsdtar','-xOf',path,members['.PKGINFO']]).decode();T.need(not any(line.startswith('backup = ') for line in pkginfo.splitlines()),'backup/pacsave semantics outside Apps copy scope')
     T.payload_guard(nodes,before['nodes']);closure.archive(row['name'],path,nodes)
     for name,node in nodes.items():T.need(name not in payload or node==payload[name] and node['type']=='directory','signed payload overlap');payload[name]=node
     archives[row['name']]=row['sha256']
    T.need(set(archives)==set(add),'every selected signed archive inspected')
    # Revalidate original authenticated bytes, caller plan, all nodes/DB/caps and
    # the leased source again. Readonly observations confer no future lock lease.
    fd=c.directory(copied.release)
    try:
     for name,digest in context['release']['files'].items():T.need(c.hash_member(fd,name)[0]==digest,'authenticated input drift')
    finally:os.close(fd)
    T.need(c.read_path(Path(args.plan).absolute(),T.MAX_PLAN)==plan_raw,'caller plan changed during inspection')
    after_inventory=app.inventory_reader().collect(root/T.DB,c,lambda row:app.package(row,r));after=T.observe(root,budget,closure)
    T.need(after_inventory==inventory and after['nodes']==before['nodes'],'root or inventory changed during readonly inspection')
    M=sys.modules[type(closure).__module__];auxiliary=M.unchanged(closure.baseline,M.aux.checkpoint(root,after,budget),closure.comparator)
    caps=M.capability_map(root,after,budget,closure.baseline_caps)
    no_pending(T,workspace,root);T.need(T.root_guard(args)==(workspace,root,owner),'copy ownership changed during inspection')
    result.update(status='INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL',operation='reinstall',selected=sorted(add),archives=archives,before=T.pins(before,inventory),damage=closure.repair_damage,full574_binding=closure.binding,source_tree_sha256=owner['source_tree_sha256'],source_preservation='LEASED_READONLY_SOURCE_REVALIDATED',capabilities_sha256=M.digest(caps),auxiliary_preservation=auxiliary,plan_sha256=args.plan_sha256,binding=fresh['binding'],helper_pins=fresh['helper_pins'],synthetic=fresh['synthetic'],freshness='NOT_ESTABLISHED',stable_accepted=False,root_preserved=True,lock_reservation='NONE_APPLY_MUST_REAUTHENTICATE_AND_RECHECK_COMPLETE_BEFORE_PINS',copy_retained='EXPLICIT_OWNER_MUST_DISPOSE')
  result['cleanup']='OWNED_TEMP_REMOVED_WORKSPACE_FLOCK_RELEASED'
  no_pending(T,workspace,root)
 except BaseException as error:result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024],recovery='NO_MUTATION_PERFORMED_NO_ROLLBACK_OR_LOCK_DELETION')
 T.need(len(T.encoded(result))<=MAX_REPORT,'bounded repair inspection report');return result

def parser():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('inspect-reinstall',))
 for name in ('workspace','ownership-sha256','apps-source','apps-provenance-sha256','repository-source','full574-policy','full574-policy-sha256','full574-lease','full574-lease-sha256','release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','plan','plan-sha256'):p.add_argument('--'+name,required=True)
 p.add_argument('--applications',nargs='+',required=True);p.add_argument('--worker',action='store_true',help=argparse.SUPPRESS);p.set_defaults(operation='reinstall');return p

def main(argv=None):
 import json
 argv=list(sys.argv[1:] if argv is None else argv);args=parser().parse_args(argv)
 try:
  T=backend()
  if args.worker:result=inspect_reinstall(args)
  else:
   workspace,root,owner=T.root_guard(args) # Cheap environment/owner gate before spawn.
   row=T.SUP.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),*argv,'--worker'],env=dict(os.environ),cwd=str(workspace),timeout=T.execution_seconds(args),output_limit=MAX_REPORT)
   T.need(row['termination'] is None and row['direct_child_reaped'] is True and row['group_kill_sent'] is True and type(row['returncode']) is int and row['returncode'] in (0,1),'readonly worker failed/interrupted or retirement incomplete; no before-pins usable')
   result=T.I.decode(row['stdout']);T.need(result.get('status')==('FAIL' if row['returncode'] else 'INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL'),'readonly worker exit/status disagreement')
   T.need(result.get('commit_started') is False and result.get('packages_committed') is False and result.get('transaction')=='NOT_RUN','readonly worker mutation-status disagreement')
   result['worker']={k:row[k] for k in ('returncode','termination','direct_child_reaped','group_kill_sent')}
   result['worker'].update(seconds=T.execution_seconds(args),output_limit=MAX_REPORT,retirement='ORIGINAL_SUPERVISOR_SIGNALS_GROUP_BEFORE_LEADER_REAP')
  T.need(len(T.encoded(result))<=MAX_REPORT,'bounded readonly report including supervision')
 except BaseException as error:
  result=dict(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024],commit_started=False,packages_committed=False,transaction='NOT_RUN',commit_fields_scope='THIS_READONLY_INSPECTION_ONLY',prior_attempt_commit_outcome='NOT_DETERMINED',recovery='NO_BEFORE_PINS_AUTHORIZED_NO_MUTATION_OR_ROLLBACK_CLAIM',hardware='NOT_RUN',release='NOT_ADMITTED')
 print(json.dumps(result,sort_keys=True,indent=2,allow_nan=False));return int(result['status']=='FAIL')
if __name__=='__main__':raise SystemExit(main())
