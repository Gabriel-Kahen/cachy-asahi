# SPDX-License-Identifier: MIT
"""One real installed DNS discovery between held report and closing exercises."""
import base64,time
import dns_contract as D

def exercise(base,stage,env,workspace,current,hooks,request,stable,C):
    from management_phase import report_command,completed_report_state,remaining
    baseline=stable();sequence=0;opened=False;failure=None
    def action(label,scope=None,scroll=False):
        nonlocal sequence
        proof=hooks['a11y']('scroll'if scroll else'activate',label,scope=scope)
        window=hooks['window'](current.process.pid)if scroll else None
        if scroll:C.visible_control(proof,current.process.pid,label,window,report_scope=scope)
        else:C.need(proof.get('actions')==1 and proof.get('action_name')in('click','activate','press','switch'),'actual DNS action failed')
        sequence+=1;base.emit('dns_action',stage=stage,sequence=sequence,pid=current.process.pid,label=label,scope=scope,scroll=scroll,proof=proof,window=window,physical_input='NOT_RUN')
    def ready():return completed_report_state()
    try:
        request('dns-open',stage=stage);opened=True
        raw=report_command(base,'dns',workspace/'dns-actual.json',env);_,summary=D.report(raw)
        request('dns-check');action(D.LABEL,scroll=True)
        request('arm',tool='dns',welcome_pid=current.process.pid,stop=False);action(D.LABEL)
        child=hooks['wait'](lambda:request('observed')['process'],hooks['healthy'],20,'actual installed DNS helper')
        D.process(child,current.process.pid)
        until=time.monotonic()+45
        hooks['wait'](ready,hooks['healthy'],remaining(until),'DNS helper and supervisor completion')
        action('View report',D.TITLE,scroll=True)
        action('View report',D.TITLE)
        action('View report',D.TITLE,scroll=True)
        expected=dict(text=['Elapsed:',summary,raw.decode()],buttons={D.LABEL:True})
        def page():
            value=hooks['a11y']('snapshot')
            try:proof=D.snapshot(C,value,current.process.pid,expected)
            except ValueError:return None
            return dict(snapshot=value,snapshot_sha256=C.sha(C.encoded(value)),expected=expected,summary=proof)
        semantic=hooks['wait'](page,hooks['healthy'],remaining(until),'actual DNS report preview')
        hooks['capture'](D.VIEW,semantic);remaining(until)
        action('View report',D.TITLE)
        fast=request('retired');proof=request('retired-proof');C.retirement_proof(fast,proof,child,proof['inventory'])
        fixture=request('dns-close')['fixture'];opened=False;D.fixture(fixture)
        C.need(stable()==baseline and proof['inventory'].get('cachy-asahi-dns')=='0.1.0-2','DNS discovery changed database or lost installed product')
        base.emit('dns_result',stage=stage,report_base64=base64.b64encode(raw).decode(),report_sha256=D.sha(raw),report_bytes=len(raw),
            gui_process=child,retirement_observation=fast,retirement_proof=proof,inventory=proof['inventory'],fixture=fixture,
            metadata_readonly=True,live_DNS='NOT_REAPPLIED_STORED_PROFILE_ONLY',hardware='NOT_RUN')
    except BaseException as error:failure=error;raise
    finally:
        if opened:
            try:request('dns-close')
            except BaseException as error:
                base.emit('dns_fixture_cleanup_failed',stage=stage,error_type=type(error).__name__,acceptance='NOT_ISSUED')
                if failure is None:raise
