# SPDX-License-Identifier: MIT
"""Concrete Root-dispatched no-key entry; actor methods are never self-admitted.

Root binds the exact loaded modules, guard, adopter and custody class through its
existing trusted Source machinery. This entry neither loads arbitrary Source nor
issues a permission object. All callbacks below are that admitted closed graph.
"""
import math

SHIM_SHA = '7f39c6f87a76e7b77682983e577495fdd7af5ddbf08dae729c35c552aed82f7e'
C_SHA = 'f5ad7cc5d6247bfa673226c842ee9795a4619f6adfd6062b9edfd0b5872af537'
FILTER_SHA = '39f5f7faa1eb0f12635c0f015b09176f50b2570121dc6179fd3140024f0343e9'
KERNEL_PROOF_REFERENCE = 'adc218676eef25575469234709c2d87185ca223a'
ROLES = {'io', 'bootstrap', 'probe', 'session', 'witness', 'custody', 'threads'}
_QUARANTINED_TRANSFERS = []


def need(value, code):
    if not value:
        raise ValueError(code)


def endpoints(entry, outer_work_end, outer_cleanup_end):
    need(all(type(v) in (int, float) and math.isfinite(v) and v >= 0
             for v in (entry, outer_work_end, outer_cleanup_end)), 'original-frame')
    work, cleanup = min(entry + 8, outer_work_end), min(entry + 13, outer_cleanup_end)
    need(entry < work < cleanup, 'original-reservation')
    return work, cleanup


def reject_thread(*args, **kwargs):
    raise ValueError('strict-thread-variant-only')


def run(*, modules, expected_modules, custody_type, expected_custody_type,
        selection, admission, expected_admission, source_guard, adopt_runtime,
        entry, outer_work_end, outer_cleanup_end, cancelled, os_api, socket_api,
        clock):
    """Use Root's exact admitted graph, real observations and one 8/13 frame.

    adopt_runtime is Root's existing selected native-custody issuer, not a JSON
    reader or this entry's constructor. It consumes the fresh owned state and
    returns (Adoption, HandlerObservation, NativePremises, receive_review).
    The caller's trusted Source binding authenticates this callback and all the
    module/class objects before invocation; expected_modules is identity-bound.
    """
    need(type(admission) is object and admission is expected_admission,
         'external-runtime-admission')
    need(not _QUARANTINED_TRANSFERS, 'earlier-transfer-close-uncertain')
    need(type(modules) is dict and type(expected_modules) is dict
         and set(modules) == set(expected_modules) == ROLES
         and all(modules[k] is expected_modules[k] for k in ROLES)
         and custody_type is expected_custody_type, 'selected-loaded-Source')
    work_end, cleanup_end = endpoints(entry, outer_work_end, outer_cleanup_end)
    need(selection['entry'] == entry and selection['outer_work_end'] == outer_work_end
         and selection['outer_cleanup_end'] == outer_cleanup_end, 'selection-frame')
    m = modules
    selected_cancel = m['io'].Cancelled
    try:
        source_guard(work_end, cancelled)
        adapter = custody_type(os_api=os_api, socket_api=socket_api, clock=clock,
                              work_end=work_end, cleanup_end=cleanup_end,
                              selection=selection, admission=admission,
                              expected_admission=expected_admission, cancelled=cancelled,
                              held_fd_type=m['io'].HeldFD, cancel_type=selected_cancel)
    except BaseException as error:
        # The constructor is pure; no owned effects exist on this early path.
        if type(error) is selected_cancel or isinstance(error, KeyboardInterrupt):
            BaseException.__setattr__(error, 'keyless_cancelled', True)
            BaseException.__setattr__(error, 'keyless_primary_cancelled', True)
        raise
    io = None
    result = None
    primary = None
    try:
        state = adapter.allocate(work_end)
        source_guard(work_end, cancelled)
        grant, handler, premises, receive_review = adopt_runtime(adapter, state, work_end)
        need(type(grant) is m['custody'].Adoption and grant.root_token is admission
             and type(handler) is m['custody'].HandlerObservation
             and type(premises) is m['witness'].NativePremises
             and type(receive_review) is object, 'Root-runtime-custody-objects')
        ctx = grant.ctx
        need(ctx.source == selection['source_commit']
             and ctx.policy_sha256 == selection['policy_sha256']
             and ctx.nonce == selection['nonce'] and ctx.generation == selection['generation']
             and (ctx.job_uid, ctx.job_gid) == (selection['uid'], selection['gid'])
             and ctx.job_inode == state['root_inode']
             and ctx.keyhome_inode == state['home_inode']
             and ctx.socket_inode == state['socket_inode'], 'fresh-runtime-context')
        need(grant.build.binary_sha256 == SHIM_SHA
             and grant.build.source_sha256 == C_SHA
             and grant.build.filter_sha256 == FILTER_SHA, 'actual-compiled-shim-binding')
        m['custody'].admit(admission, grant, ctx,
            adapter.file_observation('compiled-shim', work_end, m['custody']),
            adapter.file_observation('agent-executable', work_end, m['custody']),
            handler, grant.build)
        source_guard(work_end, cancelled)
        io = m['io'].NativeIO(root_admission=admission,
            expected_root_admission=expected_admission, generation=ctx.generation,
            cancelled=cancelled, receive_kernel_review=receive_review)
        adapter.bind_runtime(io, m['io'].NativeIO, m['io'].HeldFD)
        shim = selection['files']['compiled-shim']['handle']
        agent = selection['files']['agent-executable']['handle']
        io.held(shim, 'compiled-shim'); io.held(agent, 'agent-executable')
        environment = dict(PATH='/usr/bin:/bin', HOME=state['home'], LANG='C', LC_ALL='C',
                           GNUPGHOME=state['home'], XDG_RUNTIME_DIR=state['runtime'])
        agent_argv = ('/usr/bin/gpg-agent', '--no-options', '--homedir', state['home'],
            '--supervised', '--disable-scdaemon', '--extra-socket', 'none',
            '--browser-socket', 'none', '--allow-loopback-pinentry', '--no-allow-external-cache')
        shim_argv = ('TEST_EXEC_WITNESS_SHIM', state['home'], ctx.nonce)

        def availability(end, cleanup):
            source_guard(end, cancelled)
            return m['bootstrap'].availability(io, compiled_shim=shim, environment=environment,
                setup=None, endpoint=end, cleanup_end=cleanup, held_fd_type=m['io'].HeldFD,
                admission=admission, expected_admission=expected_admission)

        def spawn(end):
            source_guard(end, cancelled)
            running, control, actual = m['bootstrap'].spawn(io, compiled_shim=shim,
                held_agent=agent, agent_listener=state['agent_listener'], home=state['home'],
                nonce=ctx.nonce, environment=environment, setup=None, endpoint=end,
                admission=admission, expected_admission=expected_admission)
            need(actual == shim_argv, 'observed-launch-argument-binding')
            return running, control  # Exact reviewed bootstrap triple -> session pair.

        def handoff(channel, running, end):
            first = None
            try:
                io.listener = m['io'].receive_handoff(io, channel, nonce=ctx.nonce,
                    owned_pid=running.pid, uid=ctx.job_uid, gid=ctx.job_gid, end=end)
            except BaseException as error:
                first = error
            finally:
                io.control_retired = True
                try:
                    current = os_api.fstat(channel.fileno())
                    need((current.st_dev, current.st_ino, current.st_mode,
                          current.st_uid, current.st_gid, current.st_nlink)
                         == io.control_identity, 'transfer-FD-custody')
                    channel.close()
                except BaseException as error:
                    io.close_uncertain = True
                    # Do not leave a socket destructor with a possibly reused fd.
                    try:
                        channel.detach()
                    except BaseException:
                        _QUARANTINED_TRANSFERS.append(channel)
                    if first is None:
                        first = error
            if first is not None:
                raise first
            return io.listener

        def make_witness(row):
            source_guard(work_end, cancelled)
            need(row['pid'] == row['tgid'] == io.running.pid, 'actual-original-leader')
            observation = adapter.file_observation('agent-executable', work_end, m['custody'])
            physical = observation.fd_after
            executable = (physical.dev, physical.inode, physical.size, grant.agent_sha,
                          physical.uid, physical.gid, physical.mode & 0o7777, physical.nlink)
            scope = m['witness'].Scope(ctx.source, ctx.nonce, ctx.policy_sha256, ctx.generation,
                row['pid'], row['start'], ctx.job_uid, ctx.job_gid, ctx.job_inode,
                ctx.keyhome_inode, ctx.socket_inode, executable, agent_argv, shim_argv,
                KERNEL_PROOF_REFERENCE, FILTER_SHA)
            return m['witness'].Witness(scope, premises, os_api.getpid(), work_end, cleanup_end)

        def guard(end):
            source_guard(end, cancelled)
            return adapter.custody_guard(end)

        def probe(running, listener, end, cleanup):
            return m['probe'].run(io, running, listener, make_witness=make_witness,
                notification_type=m['witness'].Notification, observed_type=m['witness'].Observed,
                thread_row_type=m['threads'].ThreadRow, thread_admission=reject_thread,
                custody_guard=guard, dispose_verified=adapter.dispose_verified,
                work_end=end, cleanup_end=cleanup, deadline_exception_type=m['io'].Refused,
                idle_exception_type=m['io'].IdleExpired, cancel_exception_type=m['io'].Cancelled,
                proof_exception_types=(m['witness'].Refused, m['threads'].Refused,
                                       m['custody'].Refusal))

        def classify(error):
            if type(error) is m['io'].Cancelled or isinstance(error, KeyboardInterrupt):
                return 'CANCELLED', True
            if isinstance(error, OSError):
                return 'IO_FAILED', False
            return 'PROOF_REFUSED', False

        result = m['session'].execute(io=io, binding=state, journal=adapter.journal,
            availability=availability, spawn=spawn, handoff=handoff, probe=probe,
            cleanup_remaining=adapter.cleanup_remaining, classify=classify,
            work_end=work_end, cleanup_end=cleanup_end)
    except BaseException as error:
        primary = error
    finally:
        if result is None:
            # Construction/adoption failure still retires registered partial effects.
            try:
                adapter.cleanup_remaining(io, {'launch_attempted': False}, cleanup_end)
            except BaseException as error:
                if primary is None:
                    primary = error
        try:
            adapter.close()
        except BaseException as error:
            if primary is None:
                primary = error
    fields = {'runtime_absent', 'keyhome_absent', 'socket_absent', 'uncertain',
              'owned_close_uncertain', 'cancelled', 'first_cause'}
    try:
        summary = adapter.summary()
        need(type(summary) is dict and set(summary) == fields
             and all(type(summary[k]) is bool for k in fields - {'first_cause'})
             and (summary['first_cause'] is None or type(summary['first_cause']) is str
                  and 0 < len(summary['first_cause']) <= 96
                  and summary['first_cause'].isascii()
                  and summary['first_cause'].isprintable()), 'custody-summary')
    except BaseException as error:
        if primary is None:
            primary = error
        summary = {k: False for k in fields - {'first_cause'}}
        summary.update(uncertain=True, owned_close_uncertain=True,
                       cancelled=isinstance(error, KeyboardInterrupt), first_cause='CUSTODY_SUMMARY_REFUSED')
    if primary is not None:
        BaseException.__setattr__(primary, 'keyless_cancelled', summary['cancelled'])
        BaseException.__setattr__(primary, 'keyless_primary_cancelled',
                                 type(primary) is m['io'].Cancelled or isinstance(primary, KeyboardInterrupt))
        BaseException.__setattr__(primary, 'keyless_cleanup_uncertain',
                                 summary['uncertain'] or summary['owned_close_uncertain'])
        raise primary
    result = dict(result)
    result.update({k: summary[k] for k in fields - {'first_cause', 'cancelled'}})
    result['cancelled'] = result['cancelled'] or summary['cancelled']
    if result['first_cause'] is None:
        result['first_cause'] = summary['first_cause']
    if (result['cancelled'] or summary['uncertain'] or summary['owned_close_uncertain']
            or not summary['runtime_absent']):
        result['status'] = 'FAIL'
        if result['first_cause'] is None:
            result['first_cause'] = 'CANCELLED' if result['cancelled'] else 'CUSTODY_CLEANUP_UNCERTAIN'
    result['full_signer_api_acceptance'] = False
    return result


def failure_record(error):
    """Closed Root caller projection; no raw exception message or private state."""
    need(isinstance(error, BaseException), 'failure-object')
    cancelled = isinstance(error, KeyboardInterrupt)
    original_cancelled = cancelled
    uncertain = False
    for name in ('keyless_cancelled', 'keyless_primary_cancelled', 'keyless_cleanup_uncertain'):
        try:
            marker = BaseException.__getattribute__(error, name)
        except AttributeError:
            marker = False
        except BaseException as secondary:
            marker = False
            uncertain = True
            cancelled = cancelled or isinstance(secondary, KeyboardInterrupt)
        if name == 'keyless_cancelled':
            cancelled = cancelled or marker is True
        elif name == 'keyless_primary_cancelled':
            original_cancelled = original_cancelled or marker is True
            cancelled = cancelled or marker is True
        else:
            uncertain = uncertain or marker is True
    cause = 'CANCELLED' if original_cancelled else 'IO_FAILED' if isinstance(error, OSError) else 'PROOF_REFUSED'
    return dict(status='FAIL', first_cause=cause, cancelled=cancelled, uncertain=uncertain,
                image_witness=False, task_absent=False, keyhome_absent=False,
                socket_absent=False, runtime_absent=False, full_signer_api_acceptance=False)


def execute_selected(**arguments):
    """Root stage caller consumes sticky sidecars while retaining closed output."""
    try:
        return run(**arguments)
    except BaseException as error:
        return failure_record(error)
