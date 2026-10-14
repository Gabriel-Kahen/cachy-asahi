# SPDX-License-Identifier: MIT
"""Existing metadata frame only; local completion awaits external job review.

No actors, uploads or polling run here. The selected Root job supplies live
cleanup observations. Private receipts, Source, packages and diagnostics never
enter the public frame. A complete frame alone cannot accept a remote job.
"""
from copy import deepcopy
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import time

import boundary
import owned_build
import parent_bridge

LABEL = 'development-project-libraries-metadata'
MEMBER = 'phase-public/result.json'
JSON_CAP, EXPANDED_CAP, COMPRESSED_CAP = 65536, 128*1024, 8*1024**2
FRAME_CAP = 12*1024**2
PHASE_RECEIPT = 'private-phases.json'
POLICY_PATH = 'scripts/ci/development/project_libraries.py'
POLICY_SHA256 = '7ba90b804652f2355837ab550c35b55c37e809d7fce6b4d627e56584d6b5360d'
CLEANUP_KEYS = ('schema_version','status','baseline_image_absent','producer_closed','cancelled','uncertainties')


def need(value, reason):
    if not value: raise ValueError(reason)


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')


def sha(raw): return hashlib.sha256(raw).hexdigest()


class Context:
    """Ordinary selected job context, not authority recovered from a PASS file."""
    def __init__(self, record, *, producer_root=None, state=None):
        import operations
        self.record = deepcopy(record)
        need(record['sources']['files'][POLICY_PATH]['sha256'] == POLICY_SHA256, 'PUBLICATION_FROZEN_POLICY')
        self.library = operations.SelectedOracles(record,producer_root=producer_root).modules['project_libraries']
        self.state, self.first, self.cleanup_errors = state, None, []
        if state is not None:
            need(type(state) is boundary.Boundary, 'PUBLICATION_SELECTED_BOUNDARY')
            self.first = state.first_cause
        self.last = record['clock']['issued_monotonic']
        self.used, self.cancelled, self.frame_started = False, False, False
        self.output = self.output_identity = None
        self.private_bytes = 0

    def check(self, clock):
        need(clock == self.record['clock'], 'PUBLICATION_ORIGINAL_CLOCK_JOIN')
        boundary.validate_clock(clock,self.record['identity'],parent_bridge.clock_domain())
        now = time.monotonic()
        need(self.last <= now < clock['deadline_monotonic'], 'PUBLICATION_ORIGINAL_DEADLINE')
        self.last = now
        if self.state is not None:
            if self.first is None:
                self.first = self.state.first_cause or next(iter(self.state.cleanup_errors),None)
            self.cancelled |= self.state.cancelled
        if self.output is not None:
            info = self.output.lstat();current = parent_bridge.identity(info)
            need(all(current[n] == self.output_identity[n] for n in (0,1,2,4,5)) and
                 stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
                 'PUBLICATION_OUTPUT_DRIFT')

    def healthy(self):
        return (self.first is None and not self.cancelled and not self.cleanup_errors and
            (self.state is None or self.state.first_cause is None and not self.state.cleanup_errors and not self.state.cancelled))

    def fail(self, error, *, cleanup=False):
        need(isinstance(error,BaseException), 'PUBLICATION_FAILURE_TYPE')
        if self.first is None: self.first = error
        elif self.first is not error: self.first.add_note('PUBLICATION_ADDITIONAL_FAILURE:'+type(error).__name__)
        if cleanup and len(self.cleanup_errors) < 128: self.cleanup_errors.append(error)
        self.cancelled |= isinstance(error,KeyboardInterrupt)
        if self.state is not None:
            try:self.state.fail(error,cleanup=cleanup,cancel=isinstance(error,KeyboardInterrupt))
            except BaseException as secondary:
                self.first.add_note('PUBLICATION_BOUNDARY_RECORD_UNCERTAIN:'+type(secondary).__name__)


def _close(resource, first, label):
    try: resource.close()
    except BaseException as error:
        if first is None: return error
        first.add_note(label+':'+type(error).__name__)
    return first


def bundle(context, value, clock):
    """One closed USTAR member, deterministic gzip, no filesystem selectors."""
    context.check(clock)
    context.library.validate_public_metadata(value)
    raw = encoded(value); need(len(raw) <= JSON_CAP, 'PUBLICATION_JSON_CAP')
    tar_stream = io.BytesIO(); archive = None; first = None
    try:
        archive = tarfile.TarFile(fileobj=tar_stream,mode='w',format=tarfile.USTAR_FORMAT)
        info = tarfile.TarInfo(MEMBER);info.size=len(raw);info.mode=0o644
        info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
        info.type=tarfile.REGTYPE;info.linkname='';info.pax_headers={}
        archive.addfile(info,io.BytesIO(raw));context.check(clock)
    except BaseException as error: first=error
    finally:
        if archive is not None: first=_close(archive,first,'PUBLICATION_TAR_CLOSE_UNCERTAIN')
    try:
        if first is not None: raise first
        plain=tar_stream.getvalue();need(len(plain)<=EXPANDED_CAP,'PUBLICATION_EXPANDED_CAP')
    except BaseException as error:first=error
    finally:
        first=_close(tar_stream,first,'PUBLICATION_BUFFER_CLOSE_UNCERTAIN')
    if first is not None: raise first
    target=io.BytesIO(); compressor=None;first=None
    try:
        context.check(clock)
        compressor=gzip.GzipFile(fileobj=target,mode='wb',filename='',mtime=0)
        need(compressor.write(plain)==len(plain),'PUBLICATION_GZIP_WRITE')
        context.check(clock)
    except BaseException as error:first=error
    finally:
        if compressor is not None:first=_close(compressor,first,'PUBLICATION_GZIP_CLOSE_UNCERTAIN')
    try:
        if first is not None:raise first
        compressed=target.getvalue();need(len(compressed)<=COMPRESSED_CAP,'PUBLICATION_COMPRESSED_CAP')
        context.check(clock)
    except BaseException as error:first=error
    finally:first=_close(target,first,'PUBLICATION_BUFFER_CLOSE_UNCERTAIN')
    if first is not None:raise first
    return compressed


def _private_write(context, name, raw, clock):
    """Fresh bounded private leaf; write/fsync/close uncertainty cannot disappear."""
    need(name in ('public.json','metadata.tar.gz','parent-terminal.json','finalization.json','publication-result.json'),
         'PUBLICATION_FIXED_PRIVATE_LEAF')
    need(type(raw)is bytes and len(raw)<=COMPRESSED_CAP,'PUBLICATION_PRIVATE_FILE_CAP')
    context.check(clock);context.private_bytes+=len(raw)
    need(context.private_bytes<=10*1024**2,'PUBLICATION_PRIVATE_TOTAL_CAP')
    path=context.output/name
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    first=None
    try:
        offset=0
        while offset<len(raw):
            context.check(clock);n=os.write(fd,raw[offset:offset+65536])
            need(type(n)is int and n>0,'PUBLICATION_PRIVATE_WRITE');offset+=n
        os.fsync(fd);context.check(clock)
    except BaseException as error:first=error
    finally:
        try:os.close(fd)
        except BaseException as error:
            if first is None:first=error
            else:first.add_note('PUBLICATION_PRIVATE_CLOSE_UNCERTAIN:'+type(error).__name__)
    if first is not None:raise first
    return dict(sha256=sha(raw),bytes=len(raw))


def emit(context, compressed, clock, stream, *, require_success=False):
    """Bound every stdout write; never close the borrowed workflow stream."""
    need(type(require_success)is bool,'PUBLICATION_SUCCESS_MODE')
    need(type(compressed)is bytes and len(compressed)<=COMPRESSED_CAP,'PUBLICATION_FRAME_BODY')
    lines=['CACHY_ASAHI_EVIDENCE_BEGIN '+LABEL+' sha256='+sha(compressed)+' bytes='+str(len(compressed))+'\n']
    text=base64.b64encode(compressed).decode('ascii')
    lines.extend(text[n:n+76]+'\n'for n in range(0,len(text),76))
    lines.append('CACHY_ASAHI_EVIDENCE_END '+LABEL+'\n')
    need(sum(len(line)for line in lines)<=FRAME_CAP,'PUBLICATION_FRAME_CAP')
    for line in lines:
        context.check(clock);offset=0
        while offset<len(line):
            context.check(clock)
            need(not require_success or context.healthy(),'PUBLICATION_LATE_FAILURE')
            context.frame_started=True
            written=stream.write(line[offset:])
            need(type(written)is int and 0<written<=len(line)-offset,'PUBLICATION_STREAM_WRITE')
            offset+=written
        context.check(clock)
    stream.flush();context.check(clock)
    need(not require_success or context.healthy(),'PUBLICATION_LATE_FAILURE')
    return dict(label=LABEL,sha256=sha(compressed),bytes=len(compressed))


def _cleanup(value):
    boundary.exact(value,CLEANUP_KEYS)
    need(type(value['schema_version'])is int and value['schema_version']==1 and value['status']in('PASS','FAIL') and
         all(type(value[k])is bool for k in ('baseline_image_absent','producer_closed','cancelled')) and
         type(value['uncertainties'])is int and 0<=value['uncertainties']<=128,'PUBLICATION_CLEANUP_SCHEMA')
    return (value['status']=='PASS' and value['baseline_image_absent'] and value['producer_closed'] and
            not value['cancelled'] and value['uncertainties']==0)


def _phases(context):
    """Absent actual observation means NOT RUN, never an inferred compiler error."""
    phases={name:'NOT RUN'for name in context.library.PHASES}
    path=Path(context.record['output']['path'])/PHASE_RECEIPT
    if not path.exists() and not path.is_symlink():return phases
    raw=owned_build.read_regular(path,JSON_CAP);value=boundary.decode(raw)
    boundary.exact(value,('schema_version','purpose','phases'))
    need(type(value['schema_version'])is int and value['schema_version']==1 and
         value['purpose']=='project-library-phase-observations','PUBLICATION_PHASE_SCHEMA')
    boundary.exact(value['phases'],context.library.PHASES)
    need(all(v in ('PASS','FAIL','NOT RUN','RUNNING')for v in value['phases'].values()),'PUBLICATION_PHASE_STATUS')
    return {k:('NOT RUN'if v=='RUNNING'else v)for k,v in value['phases'].items()}


def project(context, terminal, original_code, cleanup):
    need(type(original_code)is int and 0<=original_code<=255,'PUBLICATION_ORIGINAL_EXIT')
    clean=_cleanup(cleanup)
    if terminal is not None:
        boundary.validate_terminal(terminal,context.record,parent_checked=True)
        context.cancelled |= terminal['cancelled']
    positive=(terminal is not None and terminal['status']=='PRIVATE_CHECKED' and original_code==0 and clean and
              context.healthy())
    phases={name:'PASS'for name in context.library.PHASES}if positive else _phases(context)
    if not positive:
        # Actual parent closure can supply this phase; remaining unknown phases
        # stay unchanged. Producer finalization is not a compiler phase.
        phases['cleanup']='PASS'if clean else 'FAIL'
    internal=dict(stage=context.library.STAGE,status='PASS'if positive else'FAIL',
        public_promotion=False,publication_license_acceptance=False,phases=phases,
        cleanup=dict(status='PASS'if clean else'FAIL',uncertainties=0 if clean else max(1,cleanup['uncertainties'])),
        cancelled=cleanup['cancelled']or context.cancelled or terminal is not None and terminal['cancelled'])
    if positive:
        internal['artifact_sha256']={key:[terminal['attempts'][key+'-'+str(n)]['artifact_sha256']for n in(1,2)]
            for key in context.library.PACKAGES}
    failed=[name for name in context.library.PHASES if phases[name]=='FAIL']
    if failed:internal['failed_phase']=failed[0]
    result=context.library.public_metadata(internal)
    context.library.validate_public_metadata(result)
    return result


def _fallback(context, cleanup):
    # Used only after an actual local publication/prerequisite error. Invalid
    # observations add no phase authority; unfinished work stays NOT RUN.
    phases={name:'NOT RUN'for name in context.library.PHASES}
    clean=False;known=False
    try:clean=_cleanup(cleanup);known=True
    except Exception:pass
    if known:phases['cleanup']='PASS'if clean else'FAIL'
    internal=dict(stage=context.library.STAGE,status='FAIL',public_promotion=False,
        publication_license_acceptance=False,phases=phases,cancelled=context.cancelled or known and cleanup['cancelled'],
        cleanup=dict(status=('PASS'if clean else'FAIL')if known else'NOT RUN',uncertainties=0 if clean or not known else 1))
    if known and not clean:internal['failed_phase']='cleanup'
    return context.library.validate_public_metadata(context.library.public_metadata(internal))


def _failure(context):
    if context.first is None:return None
    value=boundary.failure_record(context.first)
    notes=[str(note)for note in getattr(context.first,'__notes__',())]
    raw=encoded(notes)
    value['notes']=notes if len(raw)<=65536 else None
    value['notes_sha256']=sha(raw);value['notes_bytes']=len(raw)
    return value


def publish(context, terminal, original_code, cleanup, clock, output, stream):
    """Return local metadata/exit status; remote completion is always pending.

    cleanup comes directly from selected Root supervision, not a downloaded PASS
    record. Context/producer execution/OS are ordinary trusted code. No claim of
    unforgeable Python objects or whole-job completion is made here.
    """
    need(type(context)is Context and not context.used,'PUBLICATION_CONTEXT_REPLAY')
    context.used=True
    summary=None;frame=None;frame_attempted=False;local='FAIL';exit_code=1
    try:
        context.check(clock)
        output=parent_bridge.checked_path(output)
        need(not output.exists() and not output.is_symlink(),'PUBLICATION_FRESH_OUTPUT')
        output.mkdir(mode=0o700);info=output.lstat()
        need(stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.getuid() and info.st_gid==os.getgid(),'PUBLICATION_PRIVATE_OUTPUT')
        context.output,context.output_identity=output,parent_bridge.identity(info)
        summary=project(context,terminal,original_code,cleanup)
        public_raw=encoded(summary);compressed=bundle(context,summary,clock)
        if terminal is not None:_private_write(context,'parent-terminal.json',encoded(terminal),clock)
        _private_write(context,'public.json',public_raw,clock)
        _private_write(context,'metadata.tar.gz',compressed,clock)
        prerequisite=summary['status']=='PASS'
        finalization=dict(schema_version=1,purpose='local-library-finalization-before-frame',
            status='PASS'if prerequisite else'FAIL',identity=context.record['identity'],
            original_exit_code=original_code,parent_terminal_status=terminal['status']if terminal else'NOT RUN',
            cleanup=cleanup,public_json_sha256=sha(public_raw),metadata_archive_sha256=sha(compressed),
            remote_completed_job_acceptance='PENDING_EXTERNAL_REVIEW',publication_allowed=False)
        _private_write(context,'finalization.json',encoded(finalization),clock)
        frame_attempted=True
        frame=emit(context,compressed,clock,stream,require_success=prerequisite)
        receipt=dict(schema_version=1,purpose='local-metadata-publication',status='PASS',frame=frame,
            remote_completed_job_acceptance='PENDING_EXTERNAL_REVIEW',publication_allowed=False)
        _private_write(context,'publication-result.json',encoded(receipt),clock)
        local='LOCAL_PUBLISHED_PENDING_COMPLETION'
        exit_code=0 if prerequisite else 1
    except BaseException as error:
        context.fail(error)
        try:summary=_fallback(context,cleanup)
        except BaseException as secondary:
            context.first.add_note('PUBLICATION_FAILURE_PROJECTION_UNCERTAIN:'+type(secondary).__name__)
        if not context.frame_started and summary is not None:
            try:
                # Emit a closed FAIL projection only if no frame was begun.
                # Partial/completed frames are never retried or duplicated.
                context.check(clock);compressed=bundle(context,summary,clock)
                frame_attempted=True;frame=emit(context,compressed,clock,stream)
            except BaseException as secondary:
                context.first.add_note('PUBLICATION_FAILURE_FRAME_UNCERTAIN:'+type(secondary).__name__)
                context.fail(secondary,cleanup=True)
        # Once a frame is emitted it cannot be recalled. A later failure keeps
        # exit1; external review must require completed successful job as well.
        if context.output is not None and not (context.output/'publication-result.json').exists():
            try:
                _private_write(context,'publication-result.json',encoded(dict(schema_version=1,
                    purpose='local-metadata-publication',status='FAIL',frame=frame,first_failure=_failure(context),
                    remote_completed_job_acceptance='PENDING_EXTERNAL_REVIEW',publication_allowed=False)),clock)
            except BaseException as secondary:
                context.first.add_note('PUBLICATION_FAILURE_RECEIPT_UNCERTAIN:'+type(secondary).__name__)
                context.fail(secondary,cleanup=True)
    return dict(public_summary=summary,exit_code=exit_code,local_finalization=local,
        completed_job_acceptance='PENDING_EXTERNAL_REVIEW')


def emit_failure(identity, clock, sources, cleanup, output, stream, *, child_output,
                 producer_root=None, first_error=None):
    """Failure after pinned capsule import but before any issued child record.

    Earlier bootstrap failure without the pinned policy must use generic stderr
    and exit1. This helper invents no baseline/lease/runtime observations.
    """
    record=dict(identity=deepcopy(identity),clock=deepcopy(clock),sources=deepcopy(sources),
                output={'path':str(parent_bridge.checked_path(child_output))})
    context=Context(record,producer_root=producer_root)
    if first_error is not None:context.fail(first_error)
    return publish(context,None,1,cleanup,clock,output,stream)
