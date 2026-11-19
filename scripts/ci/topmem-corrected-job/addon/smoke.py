"""Run the installed CLI on synthetic proc files under the actual current real UID."""
import contextlib,io,json,os
from pathlib import Path
import tempfile,types
module=types.ModuleType('installed_topmem')
exec(compile(Path('/usr/bin/cachy-asahi-topmem').read_bytes(),'/usr/bin/cachy-asahi-topmem','exec'),module.__dict__)
with tempfile.TemporaryDirectory() as temporary:
 proc=Path(temporary)
 for pid,uid,kib in ((31,os.getuid(),64),(12,os.getuid(),64),(7,os.getuid(),128),(9,os.getuid()+1,999)):
  p=proc/str(pid);p.mkdir();(p/'status').write_text(f'Name:\tfixture {pid}\nPid:\t{pid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nVmRSS:\t{kib} kB\n')
 original=module.snapshot
 module.snapshot=lambda **kwargs:original(proc,uid=os.getuid(),**kwargs)
 output=io.StringIO()
 with contextlib.redirect_stdout(output):assert module.main(['--json','--limit','3'])==0
 report=json.loads(output.getvalue());assert report['uid']==os.getuid() and [r['pid'] for r in report['processes']]==[7,12,31]
 assert report['skipped']['other_users']==1 and report['scope']=='current-real-uid'
 print(json.dumps({'status':'PASS_INSTALLED_SYNTHETIC_PROC_CLI','real_uid':os.getuid(),'host_proc_read':False}))
