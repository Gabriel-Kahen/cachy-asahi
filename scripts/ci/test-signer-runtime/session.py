# SPDX-License-Identifier: MIT
"""Root-only phase envelope; no CLI and no issuer of native authority."""


def execute(*, io, binding, journal, availability, spawn, handoff, probe,
            cleanup_remaining, classify, work_end, cleanup_end):
    """Callbacks must belong to the Root-admitted Source graph.

    journal is the existing private custody-checked writer; held fd tokens and
    private journal/clock/argv values must never be serialized. cleanup_remaining
    checks owned state, never signals from intent or infers absence from failure.
    Endpoints are unchanged. classify uses Root's closed exception-type mapping.
    Callbacks receive copies of this result so cleanup cannot erase first cause.
    """
    result = dict(status='FAIL', first_cause=None, cancelled=False,
                  availability='NOT RUN', launch_attempted=False,
                  image_witness=False, task_absent=False, keyhome_absent=False,
                  socket_absent=False, full_signer_api_acceptance=False)

    def failure(error):
        try:
            code, cancelled = classify(error)
            if (type(code) is not str or not code or len(code) > 96 or
                    not code.isascii() or not code.isprintable() or
                    type(cancelled) is not bool):
                raise ValueError('invalid classification')
        except BaseException:
            code, cancelled = 'CLASSIFICATION_REFUSED', False
        if result['first_cause'] is None:
            result['first_cause'] = code
        result['cancelled'] = result['cancelled'] or cancelled

    def record(phase):
        journal(binding, phase, dict(result), cleanup_end)

    try:
        record('reserved')
        capability, original_error = availability(work_end, cleanup_end)
        result['availability'] = capability['status']
        if original_error is not None:
            raise original_error
        if capability['status'] != 'AVAILABLE':
            result['first_cause'] = 'KERNEL_AVAILABILITY_REFUSED'
        else:
            result['launch_attempted'] = True
            record('create-attempted')
            running, channel = spawn(work_end)
            listener = handoff(channel, running, work_end)
            outcome = probe(running, listener, work_end, cleanup_end)
            for name in ('cancelled', 'image_witness', 'task_absent',
                         'keyhome_absent', 'socket_absent'):
                if type(outcome[name]) is not bool:
                    raise ValueError('invalid probe result')
            status, cause = outcome['status'], outcome['first_cause']
            if type(status) is not str or (cause is not None and type(cause) is not str):
                raise ValueError('invalid probe status')
            result['status'] = status
            result['first_cause'] = result['first_cause'] or cause
            result['cancelled'] = result['cancelled'] or outcome['cancelled']
            for name in ('image_witness', 'task_absent', 'keyhome_absent', 'socket_absent'):
                result[name] = outcome[name]
            record('disposed' if all(result[k] for k in
                   ('task_absent', 'keyhome_absent', 'socket_absent')) else 'failed')
    except BaseException as error:
        failure(error)
        try:
            record('failed')
        except BaseException:
            pass  # Retain original first cause; final journal refusal still fails.
    finally:
        try:
            if cleanup_remaining(io, dict(result), cleanup_end) is not True:
                result['first_cause'] = result['first_cause'] or 'REMAINING_CLEANUP_UNCERTAIN'
        except BaseException as error:
            failure(error)
        complete = all(result[k] for k in
                       ('image_witness', 'task_absent', 'keyhome_absent', 'socket_absent'))
        if (result['cancelled'] or result['first_cause'] is not None or
                not complete or not result['status'].startswith('PASS_')):
            result['status'] = 'FAIL'
        try:
            record('disposed' if result['status'].startswith('PASS_') else 'failed')
        except BaseException as error:
            failure(error)
            result['status'] = 'FAIL'
    return result
