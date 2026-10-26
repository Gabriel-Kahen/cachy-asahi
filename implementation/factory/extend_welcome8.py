# SPDX-License-Identifier: MIT
"""Narrow deterministic extension after the whole current606 original emitter."""
import ast,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent

def once(s,a,b):
 if s.count(a)!=1:raise ValueError('one exact Welcome8 emission seam '+a[:100])
 return s.replace(a,b,1)

def apply(out,selected):
 # These are typed installed-version expectations, not a substitute for execution.
 for name in('gui_contract.py','dns_contract.py','doctor_worker.py'):
  p=out/name;s=p.read_text();assert '0.1.0-7'in s;s=s.replace('0.1.0-7','0.1.0-8');p.write_text(s)
 shutil.copyfile(HERE/'welcome8_stop.py',out/'welcome8_stop.py')
 p=out/'a11y_driver.c';s=p.read_text();s=once(s,'"List stored DNS profiles", "View report" };','"List stored DNS profiles", "View report", "Stop check" };');s=once(s,'check(!strcmp(wanted, "View report") &&','check((!strcmp(wanted, "View report") || (!strcmp(wanted, "Stop check") && !strcmp(argv[4], "Doctor") && !scrolling)) &&');p.write_text(s)
 p=out/'management_phase.py';s=p.read_text();a="        closing_before=stable();action(ui['labels']['orphans'],scroll=True);closing=observed('orphans',True)";b="        import welcome8_stop\n        welcome8_stop.exercise(base,stage,current,inventory,hooks,request,stable)\n"+a;p.write_text(once(s,a,b))
 # Isolated guest Python registers only independently regenerated source siblings.
 for name in('desktop574_guest.py','doctor_worker.py'):
  p=out/name;s=p.read_text();a="load('management_phase','management_phase.py')"if name=='desktop574_guest.py'else"load('management_root','management_root.py')";p.write_text(once(s,a,a+"\nload('welcome8_stop','welcome8_stop.py')"))
 p=out/'desktop574_fixture.sh';s=p.read_text();a='cp /runner/current_products.py';p.write_text(once(s,a,'cp /runner/welcome8_stop.py "$root/usr/local/share/desktop574/"\n'+a))
 p=out/'gui_contract.py';s=p.read_text();s+='''
import welcome8_stop as W8
VIEWS=VIEWS+W8.VIEWS
_welcome8_snapshot=validate_snapshot
def validate_snapshot(value,pid,view,text_sha=None):
    if view in W8.VIEWS:return W8.snapshot(value,pid,view,text_sha)
    return _welcome8_snapshot(value,pid,view,text_sha)
''';p.write_text(s)
 p=out/'contract.py';s=p.read_text();s+='''
_welcome8_full_original=verify_result
def verify_result(events,lock):
    import welcome8_stop as W8
    result=W8.validate(events,lock,C)
    held=[e for e in events if not(e.get('event')=='frame_ready'and e.get('view')in W8.VIEWS)]
    original=_welcome8_full_original(held,lock)
    return dict(original,welcome8_stop_retry=result)
''';p.write_text(s)
 p=out/'desktop574_runtime.py';s=p.read_text();old=tuple(selected+'-'+v for v in('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-dns','management-closing'));new=old+(selected+'-welcome8-stopped',selected+'-welcome8-retry');assert s.count(repr(old))==2;s=s.replace(repr(old),repr(new));p.write_text(s)
 for p in out.glob('*.py'):ast.parse(p.read_text(),filename=str(p))
