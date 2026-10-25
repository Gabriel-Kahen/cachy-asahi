"""Counted original10500 supervisor seam: sole inherited channel + poll service."""
import ast,inputs

def derive(raw):
 text=raw.decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='run_command');old=ast.get_source_segment(text,node);new=old
 changes=(
 ('def run_command(argv,work,env,seconds=30,cap=LIMIT):','def run_command(argv,work,env,seconds=30,cap=LIMIT,*,service):'),
 ('stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)','stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,pass_fds=service.pass_fds())'),
 ('    try:\n        selector=selectors.DefaultSelector()','    try:\n        service.begin(proc.pid)\n        selector=selectors.DefaultSelector()\n        selector.register(service.sock,selectors.EVENT_READ,2)'),
 ('            for key,_ in selector.select(.05):\n                data=',"            for key,_ in selector.select(.05):\n                if key.data==2:\n                    if service.eof():selector.unregister(key.fileobj)\n                    else:service.once()\n                    continue\n                data="))
 for before,after in changes:inputs.need(new.count(before)==1,'one original supervisor seam');new=new.replace(before,after)
 restored=new
 for before,after in reversed(changes):restored=restored.replace(after,before)
 inputs.need(restored==old,'whole supervisor-body inverse');return text.replace(old,new),dict(changed=['run_command'],edits=len(changes),held='ALL_ORIGINAL_TIMEOUT_CAPTURE_TERM_KILL_UNREAPED_GROUP_WAIT_AND_ABSENCE_PREDICATES')

def load(service):
 module=inputs.original('_gnu_broker_supervisor','scripts/ci/glibc-owned-runtime/runner.py');raw=__import__('pathlib').Path(module.__file__).read_bytes();text,proof=derive(raw);space=dict(vars(module));exec(compile(text,module.__file__,'exec'),space);return space['run_command'],proof
