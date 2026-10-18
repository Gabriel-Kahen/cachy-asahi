# SPDX-License-Identifier: MIT
"""Narrow the original full604/16K generator to one complete unchanged profile."""
import ast
import contract as C

CLOCK_GUEST = 'def initialize_launcher_clock():\n    """Owned offline VM clock handoff; no external time or trust authority."""\n    guard(True)\n    raw=Path(\'/proc/cmdline\').read_text()\n    need(len(raw)<=65536,\'bounded guest clock command line required\')\n    prefix=\'cachy_asahi_public_pair_epoch=\'\n    rows=[word[len(prefix):] for word in raw.split() if word.startswith(prefix)]\n    need(len(rows)==1 and rows[0].isascii() and rows[0].isdecimal() and len(rows[0])==10 and str(int(rows[0]))==rows[0],\'one canonical launcher UTC epoch required\')\n    epoch=int(rows[0]);need(1700000000<=epoch<2**32,\'bounded launcher UTC epoch required\')\n    before=time.time_ns()\n    time.clock_settime(time.CLOCK_REALTIME,epoch)\n    after=time.time_ns()\n    need(epoch*10**9<=after<(epoch+2)*10**9,\'guest realtime clock handoff failed\')\n    emit(\'launcher_realtime\',source=\'OWNED_QEMU_LAUNCHER_NOT_EXTERNAL_TIME_AUTHORITY\',before_ns=before,requested_epoch_s=epoch,after_ns=after,hardware=\'NOT_RUN\')\n\n\n'

BASE=C.module('_profile604_original_adapter',C.OLD+'/adapter.py',{'contract':C},lambda text:C.one(text,"C.HERE/'installed604.py'","source/C.OLD/'installed604.py'"))

def prepare(source,output,assets,ready,selected):
 C.profile(selected);BASE.prepare(source,output,assets,ready)
 for name in ('management_contract.py','management_root.py'):
  path=output/name;text=path.read_text()
  if name=='management_contract.py':
   text=C.one(text,"for stage in ('minimal','overlay'):",'for stage in '+repr((selected,))+':')
   text=C.one(text,'def verify_result(events,lock):','def verify_result(events,lock):\n    need({e["stage"] for e in events if "stage" in e}=={'+repr(selected)+'},"foreign or missing profile event")')
   text=C.one(text,'PASS_MANAGEMENT_NATIVE_METADATA_PIXELS_PENDING_REVIEW','PASS_SINGLE_PROFILE_MANAGEMENT_METADATA_PIXELS_PENDING_REVIEW')
  else:
   text=C.one(text,"stage==('minimal' if not profiles else 'overlay') and stage not in profiles and (not profiles or retired_profiles=={'minimal'})",'stage=='+repr(selected)+' and not profiles and not retired_profiles')
   text=C.one(text,"set(profiles)==retired_profiles=={'minimal','overlay'}",'set(profiles)==retired_profiles=={'+repr(selected)+'}')
  path.write_text('INDEPENDENT_PROFILE = '+repr(selected)+'\n'+text)
 def adapt(text):
  # Reuse the exact independent-profile operations after the original604 transform.
  return C.one(text,"'PASS_INSTALLED_WELCOME_MANAGEMENT_GUI_METADATA'",repr(C.PASS))
 profiles=C.module('_profile604_existing_profile_operations','scripts/ci/welcome-independent-profile-native/profile_adapter.py',adapt=adapt)
 profiles.GUI=C.PASS;receipt=profiles.runner(output,selected)
 path=output/'desktop574_runtime.py';text=path.read_text();text=C.one(text,"workflow_scope='installed604-welcome4-management-generic16k'","workflow_scope='independent-installed-public-pairs-apps6-current604-management-generic16k-profile'");text=C.one(text,"require(len(expected)==604 and all(expected.get(n)==v for n,v in base.items()),'exact604 closed installed target required')",'context604.selection(base,expected)');text=C.one(text,"(context/'Dockerfile').write_text('FROM '+base_reference+'\\nCOPY . /tmp/managed604/\\nRUN python3 -I -B /tmp/managed604/install604.py && rm -rf /tmp/managed604\\n')","(context/'Dockerfile').write_text(context604.dockerfile(base_reference,context))")
 text=C.one(text,"        name = 'desktop574-vm-' + os.urandom(8).hex(); containers.append(name)","        report['qemu_launcher']=context604.tooling_image(source,base,image,base_reference,out,images,Path(os.environ['CACHY_ASAHI_QEMU_TOOLING_INPUTS']),execute)\n        name = 'desktop574-vm-' + os.urandom(8).hex(); containers.append(name)")
 text=C.one(text,'cmd = qemu_command(derived, name, fixture, source, runner)',"cmd = qemu_command(report['qemu_launcher']['image'], name, fixture, source, runner)")
 text=C.one(text,"    os.environ.clear()\n    os.environ.update(ENV, HOME=str(out / 'home'))","    tooling_inputs = os.environ.get('CACHY_ASAHI_QEMU_TOOLING_INPUTS')\n    require(type(tooling_inputs) is str and 0 < len(tooling_inputs) <= 4096 and '\\x00' not in tooling_inputs, 'explicit bounded tooling input path required')\n    tooling_path = Path(tooling_inputs)\n    require(tooling_path.is_absolute() and str(tooling_path) == tooling_inputs and '..' not in tooling_path.parts and tooling_path.is_dir() and not any(p.is_symlink() for p in (tooling_path, *tooling_path.parents)) and tooling_path.stat().st_uid == os.getuid(), 'ordinary owned tooling input directory required')\n    os.environ.clear()\n    os.environ.update(ENV, HOME=str(out / 'home'), CACHY_ASAHI_QEMU_TOOLING_INPUTS=tooling_inputs)")
 text=C.one(text,'    return cmd\n\n\ndef bind_local_base',"    epoch=int(time.time())\n    require(1700000000<=epoch<2**32,'bounded launcher UTC epoch required')\n    cmd[-1]=cmd[-1].replace('cachy_asahi_welcome_management=1\"','cachy_asahi_welcome_management=1 cachy_asahi_public_pair_epoch='+str(epoch)+'\"')\n    return cmd\n\n\ndef bind_local_base")
 path.write_text(text)
 # Current public TEST keys are created by the real hosted launcher. The
 # diagnostic kernel has no RTC: hand off the actual launcher clock explicitly,
 # keeping signature validity and expiry checks on the genuine guest realtime.
 path=output/'base_guest.py';guest=path.read_text()
 guest=C.one(guest,'def boot():',CLOCK_GUEST+'def boot():')
 guest=C.one(guest,'        EVENTS.chmod(0o600)','        EVENTS.chmod(0o600)\n        initialize_launcher_clock()')
 path.write_text(guest)
 proof=C.json_read(output/'runner-proof.json');proof.update(profile=selected,scope='ONE_PROFILE_NOT_FULL60416K_ACCEPTANCE',files={p.name:dict(bytes=len(C.read(p)),sha256=C.sha(C.read(p))) for p in output.iterdir() if p.is_file() and p.name not in ('runner-proof.json','candidate-lock.json')});C.save(output/'runner-proof.json',proof)
 for path in output.glob('*.py'):ast.parse(path.read_bytes())
 return output
