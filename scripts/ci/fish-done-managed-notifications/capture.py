# SPDX-License-Identifier: MIT
"""One unchanged QMP frame per normal request; visual acceptance remains manual."""
import hashlib
import json
from pathlib import Path
import shutil
import time


def request_digest(event):
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def capture_frame(event, qmp, fixture, frames, report, decode):
    stage = event.get('stage')
    if stage not in ('minimal', 'overlay') or stage in report['frames']:
        raise ValueError('one first frame per phase required')
    if event.get('activation') != 'normal-shipped-config-no-reload':
        raise ValueError('normal activation request required')
    source = Path(fixture) / (stage + '.ppm')
    target = Path(frames) / (stage + '.ppm')
    if source.exists() or source.is_symlink() or target.exists() or target.is_symlink():
        raise ValueError('fresh capture paths required')
    started = time.monotonic()
    qmp.execute('screendump', {'filename': '/out/' + stage + '.ppm'})
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 8 * 1024**2:
        raise ValueError('unsafe or oversized first capture')
    # Keep even a decoder-rejected first image for bounded failure evidence.
    shutil.copyfile(source, target)
    frame = decode(target)
    elapsed = int((time.monotonic() - started) * 1000)
    if elapsed < 0 or elapsed > 5000:
        raise ValueError('first QMP capture exceeded five-second observation budget')
    observer = dict(event='frame_captured', stage=stage, request_sha256=request_digest(event),
                    first_capture=True, capture_ms=elapsed, sha256=frame['sha256'],
                    managed_identity=event['managed_identity'], visual_review='NOT_RUN')
    report['frames'][stage] = dict(frame, observer=observer)
    report['events'].append(observer)
