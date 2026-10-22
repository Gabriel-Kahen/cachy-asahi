#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original owned job HOME/config retirement, separated from16K kernel disposal."""
import argparse,os,shutil,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C

def cleanup(held,output,proof):
 home=output.with_name(output.name+'-job-home');config=output.with_name(output.name+'-docker-config');C.need(output.parent==Path('/tmp')and output.name=='cachy-asahi-updater604-copy4k-'+str(proof['run'])+'-1-normal','fixed same-run cleanup owner path')
 if not home.exists():C.need(not home.is_symlink()and not config.exists()and not config.is_symlink(),'retained Docker config without owned child record');return dict(status='NOT_CREATED',hardware='NOT_RUN')
 C.need(not any(p.is_symlink()for p in(home,*home.parents))and {p.name for p in home.iterdir()}=={'child.json'},'exact ordinary owned job HOME closure');info=home.lstat();C.need(info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o700,'owned job HOME mode/uid');child=C.obj(home/'child.json');C.need(child['status']=='WAIT_RETURNED'and child['source']==proof['source']and child['case']=='normal'and child['child']['group_absence_verified']is True,'retained original owner group unknown');own=C.obj(output/'owner.json');result=C.obj(output/'result.json');job=C.obj(output/'wiring-owner.json');C.need(own['purpose']=='expanded604-apps6-public-pair-updater'and own['output']==str(output)and own['case']=='normal'and result['source']==C.HELD and result['producer_cleanup']==result['outer_cleanup']==result['caller_private_cleanup']=='PASS'and job['wrapper']==proof and job['child']['group_absence_verified']is True,'whole original native consumer/producer/private retirement before config disposal');contract,W,A=C.apis(held);helper=W.load(held,C.LANE+'/kernel_job.py');lease=helper.docker_config_tree(output,child,proof['source'],'normal');C.need(lease==config and shutil.rmtree.avoids_symlink_attacks,'whole original safe owned config removal');shutil.rmtree(config);C.need(not config.exists(),'config remains');(home/'child.json').unlink();home.rmdir();return dict(status='PASS_ORIGINAL_OWNED_JOB_HOME_AND_CONFIG_REMOVED',wrapper=proof,group_absence=True,original_native_cleanup='REQUIRED_PASS',kernel='NOT_CREATED_NOT_PROJECTED',private_contents='NOT_EXPORTED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('implementation','source-output','output'):p.add_argument('--'+n,type=Path,required=True)
 for n in('source','workflow-sha'):p.add_argument('--'+n,required=True)
 p.add_argument('--case',choices=('normal',),required=True);a=p.parse_args();proof=C.authenticate(a.implementation.absolute(),a.source,a.workflow_sha,a.case);result=dict(status='FAIL_RETAINED_RETIREMENT_UNKNOWN')
 try:result=cleanup(a.implementation.absolute(),a.source_output.absolute(),proof)
 except Exception as e:result.update(error_type=type(e).__name__,reason='ORIGINAL_RETIREMENT_GUARD_REFUSED_NO_CLEANUP_AUTHORITY')
 C.need(not a.output.exists(),'fresh retirement receipt');a.output.write_bytes(C.enc(result));raise SystemExit(0 if result['status']in('NOT_CREATED','PASS_ORIGINAL_OWNED_JOB_HOME_AND_CONFIG_REMOVED')else 1)
