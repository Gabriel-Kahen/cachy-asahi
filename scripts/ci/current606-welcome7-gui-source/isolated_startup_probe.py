# SPDX-License-Identifier: MIT
"""Execute trusted deployed startup through real sibling/base loads, then stop before actors."""
import argparse,importlib.util,json,os,runpy,signal,subprocess,sys,types
from pathlib import Path
from unittest.mock import patch
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--entry',choices=('guest.py','doctor_worker.py','service_outcome.py'),required=True);p.add_argument('--expect',choices=('fixed','old-missing','file-missing','wrong-file'),required=True);p.add_argument('--preloaded-wrong',action='store_true');a=p.parse_args();root=a.root;before=sys.path[:];loads=[];real_spec=importlib.util.spec_from_file_location
class ReachedBase(BaseException):pass
def spec(name,path,*args,**kwargs):
 loads.append(dict(name=name,path=str(path)));return real_spec(name,path,*args,**kwargs)
def forbidden(*args,**kwargs):raise AssertionError('NO_ACTORS_API_GIT')
if a.preloaded_wrong:
 poison=types.ModuleType('post_session');poison.mark=forbidden;poison.__file__='/wrong/ambient/post_session.py';sys.modules['post_session']=poison
result=None
try:
 with patch.object(subprocess,'run',side_effect=forbidden),patch.object(subprocess,'Popen',side_effect=forbidden),patch.object(importlib.util,'spec_from_file_location',side_effect=spec):
  ns=runpy.run_path(str(root/a.entry),run_name='_source_only_isolated_startup');main=ns['main'];load=main.__globals__['load']
  def stop_after_base(name,filename):
   module=load(name,filename)
   if filename=='base_guest.py':
    helper=sys.modules['post_session'];assert Path(helper.__file__)==root/'post_session.py';assert module.post_session is helper;assert module.management_root is sys.modules['management_root'];assert module.management_root.post_session is helper;assert helper.STAGES==('management_restore_begin','management_restore_end','installed606_verify_begin','installed606_verify_end','manager_cleanup_begin','manager_cleanup_end','complete_boundary');assert helper._last==-1;raise ReachedBase()
   return module
  main.__globals__['load']=stop_after_base
  sys.argv=[str(root/a.entry)]
  if a.entry=='doctor_worker.py':sys.argv+=['--workspace','/not-entered','--nonce','0'*32,'--stage','minimal']
  main();raise AssertionError('startup passed base interception')
except ReachedBase:
 assert a.expect=='fixed';names=[row['name']for row in loads];assert names.count('post_session')==1;assert names.index('post_session')<names.index('management_root');assert next(i for i,row in enumerate(loads)if Path(row['path']).name=='base_guest.py')>names.index('management_root');assert all(Path(row['path']).parent==root for row in loads);result=dict(status='PASS_FRESH_ISOLATED_DEPLOYED_STARTUP_TO_REAL_BASE_BEFORE_ACTORS',helper='PINNED_SIBLING_REGISTERED_BEFORE_CONSUMERS',loaded=[dict(name=v['name'],file=Path(v['path']).name)for v in loads])
except ModuleNotFoundError as error:
 assert a.expect=='old-missing'and error.name=='post_session';result=dict(status='REPRODUCED_ORIGINAL_MODULE_NOT_FOUND',module=error.name)
except FileNotFoundError as error:
 assert a.expect=='file-missing'and Path(error.filename)==root/'post_session.py';result=dict(status='REFUSED_MISSING_EXPLICIT_HELPER_FILE')
except RuntimeError as error:
 assert a.expect=='wrong-file'and str(error)=='SOURCE_TEST_WRONG_DEPLOYED_HELPER';result=dict(status='REFUSED_WRONG_DEPLOYED_HELPER_FILE')
finally:signal.alarm(0)
assert sys.path==before;assert ''not in sys.path and str(root)not in sys.path and str(Path.cwd())not in sys.path;assert sys.flags.isolated==1
print(json.dumps(dict(result,entry=a.entry,isolated=True,sys_path='UNCHANGED',actors='NOT_RUN',preloaded_wrong=a.preloaded_wrong),sort_keys=True))
