# SPDX-License-Identifier: MIT
"""Metadata acceptance requires real managed delivery, owned exits and original first frames."""
import base64,hashlib,json,re
from pathlib import Path
import managed_contract
import observation as O
from capture import request_digest
from bar_helpers import owned_layer,MAKO_NAMESPACE,environment_values,SESSION_ENV


def verify_source(source,pins=None):
    if pins is None:pins=json.loads(Path(__file__).with_name('source-pins.json').read_text())
    for name,expected in pins.items():
        path=Path(source)/name
        O.need(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)) and hashlib.sha256(path.read_bytes()).hexdigest()==expected,'source dependency differs: '+name)


def verify_package_input(proposal,installed):
    expected={r['name']:r['version'] for r in proposal['closure_packages']}
    O.need(len(expected)==len(proposal['closure_packages']) and all(installed.get(n)==v for n,v in expected.items()) and not proposal['additional_packages'] and not proposal['replacement_packages'],'unchanged bar dependency inventory required')


def verify_result(events):
    result=managed_contract.verify_result(events)
    boots=[e for e in events if e.get('event')=='boot']
    O.need(len(boots)==1 and boots[0].get('architecture')=='aarch64' and boots[0].get('page_size')==4096 and
         boots[0].get('kernel')=='7.2.10-1-aarch64-ARCH','accepted generic4K boot required')
    user=next(e for e in events if e.get('event')=='managed_user_ready')
    identity={k:user[k] for k in ('address','uid','manager_pid','default_target')}
    for stage,(case,outcome) in O.CASES.items():
        def one(kind):
            rows=[r for r in events if r.get('event')==kind and r.get('stage')==stage]
            O.need(len(rows)==1,'one real Done '+kind+' required');return rows[0]
        frame=one('frame_ready');observed=one('frame_captured');transport=one('done_transport');phase=one('phase_pass')
        O.need([events.index(r) for r in (frame,observed,transport,phase)]==sorted(events.index(r) for r in (frame,observed,transport,phase)),'normal first capture/retirement order differs')
        O.need(frame['case']==transport['case']==phase['case']==case and frame['outcome']==outcome and frame['managed_identity']==identity and frame['activation']=='normal-shipped-config-no-reload' and frame['trace_waybar'] is False and frame['notification_timeout_ms']==3000 and 0<=frame['notification_age_ms']<2500 and frame['capture_after_ms']>=5000,'real normal Done phase provenance differs')
        activation=frame['activation_environment'];O.need(activation['manager_pid']==identity['manager_pid'] and activation['systemd_verified'] is True and activation['dbus_updated'] is True and environment_values(activation['values'])==activation['values'],'real managed activation evidence required')
        O.need(observed['first_capture'] is True and observed['request_sha256']==request_digest(frame) and observed['managed_identity']==identity and observed['visual_review']=='NOT_RUN' and 0<=observed['capture_ms']<=5000,'original first QMP frame required')
        for name,namespace in (('bar','waybar'),('mako',MAKO_NAMESPACE)):
            row=frame[name];O.need(owned_layer({row['monitor']:{'levels':{row['level']:[row]}}},namespace,frame['waybar_pid' if name=='bar' else 'mako_pid']) is not None,'visible owned client layer required')
        monitor=transport['monitor'];raw=base64.b64decode(monitor['raw_base64'],validate=True)
        O.need(len(raw)==monitor['bytes'] and hashlib.sha256(raw).hexdigest()==monitor['sha256'] and monitor['exit'] in (0,-2),'complete real bus observer receipt required')
        wire=O.notify(O.messages(raw),frame['wire']['recipient'],outcome,'Watched job' if stage=='background' else 'Foreground command')
        recipient=frame['recipient'];O.need(recipient['service']=='org.freedesktop.Notifications' and recipient['unique']==wire['recipient'] and recipient['pid']==frame['mako_pid'] and json.loads(recipient['owner_reply'][2:])==recipient['unique'],'actual Mako unique owner/PID evidence required')
        pids=[frame[n] for n in ('compositor_pid','waybar_pid','mako_pid','fish_pid')]
        O.need(all(type(n) is int and n>0 for n in pids) and len(set(pids))==4,'distinct owned compositor/bar/Mako/Fish identities required')
        O.need(wire==frame['wire']==transport['wire'] and O.listing([frame['notification']],wire)==frame['notification'],'real Notify/reply/Mako listing join required')
        O.need(frame['fish_pid']==frame['caller']['pid']==transport['caller']['pid'] and frame['caller']==transport['caller'] and all(frame['caller'][k]==outcome for k in ('outcome','prompt_status','caller_continuation')) and transport['fish']['exit']==0 and transport['mako_exit']==0,'normal owned Fish/Mako exit and caller status required')
        fish=transport['fish'];raw=base64.b64decode(fish['pty_base64'],validate=True)
        O.need(len(raw)==fish['pty_bytes'] and hashlib.sha256(raw).hexdigest()==fish['pty_sha256'] and ('FDM_PROMPT_2_'+str(outcome)).encode() in raw and ('FDM_CONT_'+str(outcome)).encode() in raw,'actual interactive Fish continuation bytes required')
        O.need(frame['installed']['status']=='PASS_ACTUAL_INSTALLED_DONE_PAYLOAD_METADATA' and frame['installed']['version']=='0.1.0-2' and
             frame['installed']['archive_sha256']=='9ce3c7ba89467f04660014c1b12056dce28bd0c4e69b4cab8a9c2c98e1cce54f' and len(frame['installed']['files'])==8 and
             set(frame['installed']['executables'])=={'fish','notify-send','timeout'} and
             transport['payload_preserved'] is True and transport['user_config_preserved'] is True and phase['config_preserved'] is True and phase['fish']=='PASS','installed package/user preservation evidence required')
        if stage=='background':
            from fish_terminal import BACKGROUND_COMMAND,verify_background
            O.need(frame['caller']['command']==BACKGROUND_COMMAND,'original watched job command required')
            verify_background(frame['caller']['watch'],frame['fish_pid'],raw,transport['fish'].get('watch_retirement'))
    sessions=[r for r in events if r.get('event')=='session_pass']
    O.need(len(sessions)==1 and sessions[0].get('fish_done')=='PASS_REAL_MANAGED_FOREGROUND_TWO_CASES' and sessions[0].get('watched_background')=='PASS_REAL_MANAGED_SINGLE_SUCCESS','real installed Done manager result required')
    return dict(managed=result,foreground_cases=2,watched_background='PASS_REAL_MANAGED_SINGLE_SUCCESS',background_cases=1,background_failure='NOT_RUN',background_cancellation='NOT_RUN',background_duplicate_watch='NOT_RUN',visual_review='NOT_RUN',hardware='NOT_RUN')
