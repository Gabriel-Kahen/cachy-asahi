# SPDX-License-Identifier: MIT
"""One unchanged QMP frame per normal request; visual acceptance remains manual."""
import hashlib
import json
from pathlib import Path
import shutil
import time


class PixelPresenceFailure(ValueError):
    """An original image failed pixel presence; never an acceptance result."""


def raise_deferred_capture_failure(report):
    failures=report.get('deferred_capture_failures',[])
    if failures:raise PixelPresenceFailure(failures[0]['error'])


def request_digest(event):
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def arm_capture(event,fixture,frames,report):
    """Reserve the immutable early request; no pixels before live owned readiness."""
    import observation as O
    stage=event.get('stage');pending=report.setdefault('capture_requests',{})
    O.need(stage in O.CASES and stage not in pending and stage not in report['frames'],
           'one first capture request per phase')
    O.need(event.get('activation')=='normal-shipped-config-no-reload','normal activation request required')
    for path in (Path(fixture)/(stage+'.ppm'),Path(frames)/(stage+'.ppm')):
        O.need(not path.exists() and not path.is_symlink(),'fresh capture paths required')
    timing=event['timing']
    O.need(timing==O.capture_timing_facts(event['wire'],timing['request_realtime_us'],timing['request_monotonic_ns']),
           'original request Notify timing differs')
    pending[stage]=dict(request=event,request_sha256=request_digest(event),claimed=False,
                        host_received_realtime_us=time.time_ns()//1000,host_received_monotonic_ns=time.monotonic_ns())


def capture_ready(event,qmp,fixture,frames,report,decode):
    """Take exactly one original frame after this request's fresh owned layer reply."""
    import observation as O
    from bar_helpers import owned_layer,MAKO_NAMESPACE
    stage=event['stage'];armed=report.get('capture_requests',{}).get(stage)
    O.need(type(armed) is dict and not armed['claimed'],'one armed original request before visibility')
    request=armed['request'];visibility=event.get('visibility');digest=request_digest(request)
    O.need(armed['request_sha256']==digest and event.get('capture_request_sha256')==digest and
           event.get('wire')==request['wire'] and event.get('managed_identity')==request['managed_identity'] and
           event.get('case')==request['case'] and type(visibility) is dict and
           set(visibility)=={'bar','mako','notification','request_sha256','realtime_us','monotonic_ns'} and
           visibility['request_sha256']==digest,'fresh visibility/original request differs')
    timing=request['timing']
    O.need(type(visibility['realtime_us']) is int and visibility['realtime_us']>=timing['request_realtime_us'] and
           type(visibility['monotonic_ns']) is int and visibility['monotonic_ns']>=timing['request_monotonic_ns'],
           'visibility must follow the actual Notify request')
    for name,namespace in (('bar','waybar'),('mako',MAKO_NAMESPACE)):
        row=visibility[name]
        O.need(owned_layer({row['monitor']:{'levels':{row['level']:[row]}}},namespace,
                           request['waybar_pid' if name=='bar' else 'mako_pid']) is not None,
               'actual owned fully visible layers required before first QMP')
    O.need(O.listing([visibility['notification']],request['wire'])==visibility['notification'],
           'actual live notification ID/payload before first QMP')
    armed.update(claimed=True,scheduled_visibility_sha256=request_digest(visibility),
                 host_visibility_received_realtime_us=time.time_ns()//1000,
                 host_visibility_received_monotonic_ns=time.monotonic_ns())
    capture_frame(request,qmp,fixture,frames,report,decode,armed=armed)
    try:finalize_capture(event,frames,report)
    except PixelPresenceFailure as error:
        failures=report.setdefault('deferred_capture_failures',[])
        if len(failures)>=3 or any(r['stage']==stage for r in failures):raise ValueError('one pixel rejection per original phase')
        failures.append(dict(stage=stage,error=str(error),scope='DIAGNOSTIC_DRAIN_ONLY_STILL_FAIL',
                             frame_sha256=report['frames'][stage]['sha256'],request_sha256=digest,
                             visibility_sha256=request_digest(visibility)))


def capture_pending_failure(qmp,fixture,frames,report,decode):
    """Preserve an unaccepted first diagnostic, never a replacement or pass."""
    for stage,armed in report.get('capture_requests',{}).items():
        if armed['claimed'] or stage in report['frames']:continue
        armed['claimed']=True
        try:capture_frame(armed['request'],qmp,fixture,frames,report,decode,armed=armed)
        except Exception as error:
            report.setdefault('capture_diagnostics',[]).append(dict(stage=stage,error=str(error)[:256]))


def capture_frame(event, qmp, fixture, frames, report, decode, armed=None):
    stage = event.get('stage')
    if stage not in ('minimal', 'overlay', 'background') or stage in report['frames']:
        raise ValueError('one first frame per phase required')
    if event.get('activation') != 'normal-shipped-config-no-reload':
        raise ValueError('normal activation request required')
    source = Path(fixture) / (stage + '.ppm')
    target = Path(frames) / (stage + '.ppm')
    if source.exists() or source.is_symlink() or target.exists() or target.is_symlink():
        raise ValueError('fresh capture paths required')
    started = time.monotonic();started_ns=time.monotonic_ns();started_us=time.time_ns()//1000
    import observation
    timing=event['timing'];observation.need(timing==observation.capture_timing_facts(event['wire'],timing['request_realtime_us'],timing['request_monotonic_ns']),'original request Notify timing differs')
    qmp.execute('screendump', {'filename': '/out/' + stage + '.ppm'})
    qmp_us=time.time_ns()//1000
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 8 * 1024**2:
        raise ValueError('unsafe or oversized first capture')
    # Keep even a decoder-rejected first image for bounded failure evidence.
    shutil.copyfile(source, target)
    frame = decode(target)
    elapsed = int((time.monotonic() - started) * 1000) if armed is None else (time.monotonic_ns()-armed['host_received_monotonic_ns'])//1_000_000
    if elapsed < 0 or elapsed > 5000:
        raise ValueError('first QMP capture exceeded five-second observation budget')
    observer = dict(event='frame_captured', stage=stage, request_sha256=request_digest(event),
                    first_capture=True, capture_ms=elapsed, sha256=frame['sha256'],
                    managed_identity=event['managed_identity'], visual_review='NOT_RUN',
                    host_started_realtime_us=started_us,host_qmp_returned_realtime_us=qmp_us,
                    host_finished_realtime_us=time.time_ns()//1000,host_started_monotonic_ns=started_ns)
    if armed is not None:
        observer.update({k:armed[k] for k in ('host_received_realtime_us','host_received_monotonic_ns')})
        if 'scheduled_visibility_sha256' in armed:
            observer.update({k:armed[k] for k in ('scheduled_visibility_sha256','host_visibility_received_realtime_us','host_visibility_received_monotonic_ns')})
        else:observer['diagnostic_only']='NO_ACCEPTED_FRESH_VISIBILITY'
    report['frames'][stage] = dict(frame, observer=observer)
    report['events'].append(observer)
    # Always retain the first original frame before rejecting a late request.
    observation.capture_timing(event['wire'],timing['request_realtime_us'],timing['request_monotonic_ns'])


def finalize_capture(event,frames,report):
    """Join post-request live geometry to the unchanged first image, never recapture."""
    stage=event['stage']
    requests=[r for r in report['events'] if r.get('event')=='frame_ready' and r.get('stage')==stage]
    if len(requests)!=1 or stage not in report['frames']:raise ValueError('one original request/frame before visibility required')
    request=requests[0];frame=report['frames'][stage];observer=frame['observer']
    if 'notification_pixels' in observer:raise ValueError('one visibility finalization per original frame')
    visibility=event.get('visibility')
    if not isinstance(visibility,dict) or visibility.get('request_sha256')!=request_digest(request) or event.get('capture_request_sha256')!=request_digest(request) or observer['request_sha256']!=request_digest(request) or event.get('wire')!=request['wire']:
        raise ValueError('late visibility/original request join differs')
    presence=notification_pixels(Path(frames)/(stage+'.ppm'),visibility['mako'])
    elapsed=(time.monotonic_ns()-observer.get('host_received_monotonic_ns',observer['host_started_monotonic_ns']))//1_000_000
    observer.update(notification_pixels=presence,visibility_sha256=request_digest(visibility),capture_ms=elapsed,pixels_finished_realtime_us=time.time_ns()//1000)
    if elapsed<0 or elapsed>5000:raise ValueError('first QMP capture/visibility exceeded five-second observation budget')
    verify_pixel_receipt(presence,visibility['mako'],frame['sha256'])


# Shipped mako.conf is source-pinned. This detects presence, not readable text.
STYLE_SHA256='c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504'
COLORS={'background':(32,36,44),'border':(136,192,208),'text':(236,239,244)}


def rgb_receipt(raw,box,frame_sha256):
    area=box['w']*box['h']
    if len(raw)!=area*3 or not 120<=box['w']<=1024 or not 30<=box['h']<=768:
        raise ValueError('bounded original Mako RGB rectangle required')
    counts={name:sum(all(abs(raw[i+c]-color[c])<=6 for c in range(3)) for i in range(0,len(raw),3)) for name,color in COLORS.items()}
    present=counts['background']*100>=area*45 and counts['border']*100>=area and counts['text']*1000>=area*2
    return dict(status='PASS_PIXEL_PRESENCE_PENDING_READABILITY' if present else 'FAIL_NOTIFICATION_PIXELS_ABSENT',
                frame_sha256=frame_sha256,roi={k:box[k] for k in ('x','y','w','h')},roi_sha256=hashlib.sha256(raw).hexdigest(),
                pixels=area,counts=counts,color_tolerance=6,style_sha256=STYLE_SHA256,visual_review='NOT_RUN')


def notification_pixels(path,box):
    import re
    path=Path(path)
    if path.is_symlink() or path.stat().st_size>8*1024**2:raise ValueError('bounded original frame required')
    raw=path.read_bytes();header=re.match(rb'P6\s+1024\s+768\s+255\s',raw)
    if header is None or len(raw)!=header.end()+1024*768*3:raise ValueError('original RGB frame shape differs')
    if not all(type(box.get(k)) is int for k in ('x','y','w','h')) or not (0<=box['x']<1024 and 0<=box['y']<768 and box['x']+box['w']<=1024 and box['y']+box['h']<=768):
        raise ValueError('original Mako rectangle outside frame')
    pixels=raw[header.end():]
    roi=b''.join(pixels[(y*1024+box['x'])*3:(y*1024+box['x']+box['w'])*3] for y in range(box['y'],box['y']+box['h']))
    return rgb_receipt(roi,box,hashlib.sha256(raw).hexdigest())


def verify_pixel_receipt(receipt,box,frame_sha256):
    import re
    if not isinstance(receipt,dict) or receipt.get('frame_sha256')!=frame_sha256 or receipt.get('roi')!={k:box[k] for k in ('x','y','w','h')} or receipt.get('style_sha256')!=STYLE_SHA256 or receipt.get('color_tolerance')!=6 or receipt.get('visual_review')!='NOT_RUN':
        raise ValueError('original frame/pinned Mako pixel receipt differs')
    area=box['w']*box['h'];counts=receipt.get('counts',{})
    if receipt.get('pixels')!=area or set(counts)!=set(COLORS) or not all(type(n) is int and 0<=n<=area for n in counts.values()) or re.fullmatch('[0-9a-f]{64}',receipt.get('roi_sha256','')) is None:
        raise ValueError('original pixel statistics absent')
    if receipt.get('status')!='PASS_PIXEL_PRESENCE_PENDING_READABILITY' or counts['background']*100<area*45 or counts['border']*100<area or counts['text']*1000<area*2:
        raise PixelPresenceFailure('original first frame has no shipped Mako notification pixels')
