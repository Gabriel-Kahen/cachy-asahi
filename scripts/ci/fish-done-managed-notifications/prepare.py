#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure source/package assembly, deriving the accepted ordinary managed bar runner."""
import argparse,importlib.util,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import packet
from contract import verify_source

HERE=Path(__file__).resolve().parent


def replace(text,old,new):
    packet.need(text.count(old)==1,'Done managed adapter anchor differs: '+old[:96]);return text.replace(old,new)


def prepare(source,modules,output):
    verify_source(source)
    spec=importlib.util.spec_from_file_location('ordinary_bar_prepare',source/'scripts/ci/desktop-bar-notifications/prepare.py')
    bar=importlib.util.module_from_spec(spec);spec.loader.exec_module(bar)
    # The accepted helper imports its own contract from the controlled sibling.
    old=bar.verify_source;bar.verify_source=lambda root:old(root,json.loads((source/'scripts/ci/desktop-bar-notifications/source-pins.json').read_text()))
    bar.prepare(source,output)
    lock=packet.stage(source,modules,output/'done')
    shutil.copyfile(output/'done/done-lock.json',output/'done-lock.json')
    for name in ('desktop574_guest.py','session.py','bar_helpers.py','fish_terminal.py','monitor.py','observation.py','installed.py','contract.py','capture.py','source-pins.json','package-inputs.json','diagnostic-policy.json'):
        shutil.copyfile(HERE/name,output/name)
    fixture=(output/'desktop574_fixture.sh').read_text()
    extra=('bar_helpers.py','fish_terminal.py','monitor.py','observation.py','installed.py','done-lock.json','diagnostic-policy.json')
    fixture=replace(fixture,'cp /runner/base_guest.py /runner/session.py /runner/managed_session.py "$root/usr/local/share/desktop574/"',
        'cp /runner/base_guest.py /runner/session.py /runner/managed_session.py '+' '.join('/runner/'+n for n in extra)+' "$root/usr/local/share/desktop574/"')
    (output/'desktop574_fixture.sh').write_text(fixture)
    runtime=(output/'desktop574_runtime.py').read_text()
    runtime=replace(runtime,'    require(not out.exists()',
        '    done_root=Path(__file__).with_name("done")\n    done_lock=json.loads((done_root/"done-lock.json").read_text())\n'
        '    archive=done_root/done_lock["archive"]\n    require(archive.stat().st_size==done_lock["bytes"] and hashlib.sha256(archive.read_bytes()).hexdigest()==done_lock["sha256"],"accepted Done archive changed")\n'
        '    require(not out.exists()')
    runtime=replace(runtime,"report = {'status': 'FAIL',", "report = {'status': 'FAIL', 'done_input': done_lock, 'workflow_scope':'installed-fish-done-real-managed-notifications',")
    runtime=replace(runtime,"        expected = base |", "        shutil.copyfile(archive,context/'done.pkg.tar.xz')\n        expected = {done_lock['name']:done_lock['version']} | base |")
    runtime=replace(runtime,'COPY desktop.pkg.tar.zst /tmp/project/desktop.pkg.tar.zst\\n',
        'COPY desktop.pkg.tar.zst /tmp/project/desktop.pkg.tar.zst\\nCOPY done.pkg.tar.xz /tmp/project/done.pkg.tar.xz\\n')
    runtime=replace(runtime,'/tmp/project/desktop.pkg.tar.zst && ldconfig','/tmp/project/desktop.pkg.tar.zst /tmp/project/done.pkg.tar.xz && ldconfig')
    runtime=runtime.replace('PASS_BAR_NOTIFICATION_GENERIC_ARM_SMOKE','PASS_FISH_DONE_REAL_MANAGED_NOTIFICATION_METADATA')
    runtime=replace(runtime,'cachy_asahi_bar_notifications=1','cachy_asahi_bar_notifications=1 cachy_asahi_done_managed=1')
    runtime=replace(runtime,"stage in ('minimal', 'overlay') and stage not", "stage in ('minimal', 'overlay', 'background') and stage not")
    runtime=replace(runtime,"phases == {'minimal', 'overlay'}", "phases == {'minimal', 'overlay', 'background'}")
    runtime=replace(runtime,'from capture import capture_frame','from capture import arm_capture,capture_ready,capture_pending_failure,raise_deferred_capture_failure')
    runtime=replace(runtime,'capture_frame(event, qmp, fixture, frames, report, ppm)','arm_capture(event,fixture,frames,report)')
    runtime=replace(runtime,"                if event.get('event') == 'phase_pass':",
        "                if event.get('event') == 'frame_visibility': capture_ready(event,qmp,fixture,frames,report,ppm)\n"
        "                if event.get('event') == 'phase_pass':")
    runtime=replace(runtime,"                require(event.get('event') not in ('failed', 'failure'),",
        "                if event.get('event') in ('done_failure','failed','failure'): capture_pending_failure(qmp,fixture,frames,report,ppm)\n"
        "                require(event.get('event') not in ('failed', 'failure'),")
    runtime=replace(runtime,"        verify_result(report['events'])\n",
        "        raise_deferred_capture_failure(report)\n        verify_result(report['events'])\n")
    (output/'desktop574_runtime.py').write_text(runtime)
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','modules','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(prepare(args.source.resolve(),args.modules.resolve(),args.output.resolve()))
