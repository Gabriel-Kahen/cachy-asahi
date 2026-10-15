"""Exact93 progressive authentication kernel. No execution CLI or actor grant."""
from common import Bound, LIMITS, SCOPE, canonical, loads, need, propagated_cancellation, sha
from helper_policy import validate_gpg, validate_observation


class Cancelled(InterruptedError):
    pass


def cancellation_error(error):
    return issubclass(type(error), (Cancelled,KeyboardInterrupt,SystemExit)) or propagated_cancellation(error)


def error_kind(error):
    return type.__dict__['__name__'].__get__(type(error))


def note(error, message):
    try:
        BaseException.add_note(error,message)
    except BaseException:
        pass  # Optional diagnostics cannot replace the original exception.


def preview(bound):
    need(type(bound) is Bound, 'BOUND_TYPE')
    rows = bound.rows()
    return {'schema':'seed93-preparation-v1', 'status':'METADATA_BOUND_ACTUAL_NOT_RUN',
            'scope':SCOPE, 'packages':len(rows), 'declared_package_signature_bytes':56462822,
            'profile_sha256':bound.profile_sha256, 'source_manifest_sha256':bound.source_manifest_sha256,
            'actor_grant':False, 'actual_authentication':'NOT_RUN', 'limits':dict(LIMITS)}


def check_acquisition(value, row):
    need(type(value) is dict and set(value) == {'archive','signature'}, 'ACQUISITION_SCHEMA')
    for key, hash_key, size_key in [('archive','sha256','size'),('signature','signature_sha256','signature_size')]:
        item = value[key]
        need(type(item) is dict and set(item) == {'sha256','bytes'} and
             type(item['bytes']) is int and item['bytes'] == row[size_key] and item['sha256'] == row[hash_key],
             'ACQUISITION_PIN:' + key)
    return loads(canonical(value))


def run93(bound, operations, publish, cancelled=None):
    """Dormant Source API. A future reviewed Root caller must own containment/ports.

    Even complete return is an actor report pending external actual-runtime peer
    and exact Root admission. Inert tests of ports are not actual execution.
    """
    need(type(bound) is Bound, 'BOUND_TYPE')
    rows = bound.rows()
    need(callable(publish) and (cancelled is None or callable(cancelled)), 'CALLER_PORT_ABI')
    record = {'schema':'seed93-authentication-report-v1', 'scope':SCOPE,
              'status':'IN_PROGRESS', 'profile_sha256':bound.profile_sha256,
              'source_manifest_sha256':bound.source_manifest_sha256,
              'archive_package_rows_canonical_sha256':bound.package_rows_sha256,
              'expected_count':93, 'verified_count':0, 'packages':[], 'failures':[],
              'cancelled':False, 'first_failure':None, 'terminal_state':'UNKNOWN',
              'producer_evidence_scope':'ACTOR_REPORTED_REQUIRES_EXTERNAL_RUNTIME_PEER_AND_ROOT_ADMISSION',
              'limits':dict(LIMITS)}
    primary, phase, name = None, 'initial_publication', None

    def observe_cancel():
        if cancelled is not None:
            value = cancelled()
            need(type(value) is bool, 'CANCELLATION_ABI')
            record['cancelled'] = record['cancelled'] or value
        if record['cancelled']:
            raise Cancelled('CANCELLED')

    def failure(error, where, package, secondary=False):
        item = {'phase':where, 'name':package, 'kind':error_kind(error),
                'diagnostic':'CANCELLED' if issubclass(type(error), Cancelled) else 'DETAIL_NOT_EXPORTED',
                'secondary':secondary}
        if record['first_failure'] is None:
            record['first_failure'] = dict(item)
        record['failures'].append(item)

    def emit():
        # Callers cannot mutate the in-memory outcome through journal arguments.
        publish(loads(canonical(record)))

    try:
        emit()
        phase = 'prepare_public_key'
        observe_cancel()
        operations.prepare()
        observe_cancel()
        for row in rows:
            name = row['name']
            phase = 'acquisition'
            observe_cancel()
            acquisition = check_acquisition(operations.acquire(loads(canonical(row))), row)
            observe_cancel()
            phase = 'signature'
            gpg = operations.verify(loads(canonical(row)))
            validate_gpg(gpg)
            gpg = loads(canonical(gpg))
            observe_cancel()
            phase = 'observation'
            observation = validate_observation(operations.observe(loads(canonical(row))), row)
            observe_cancel()
            record['packages'].append({'name':name, 'version':row['version'],
                'archive_sha256':row['sha256'], 'signature_sha256':row['signature_sha256'],
                'status':'VERIFIED_AND_OBSERVED', 'acquisition':acquisition, 'gpg':gpg,
                'observation':observation, 'observation_sha256':sha(canonical(observation))})
            record['verified_count'] = len(record['packages'])
            phase = 'progress_publication'
            emit()
        name = None
    except BaseException as error:
        primary = error
        if cancellation_error(error):
            record['cancelled'] = True
        failure(error, phase, name)
        # A cancellation observed after a body fault is sticky but does not
        # replace that fault or assert its underlying cause.
        try:
            observe_cancel()
        except Cancelled:
            pass
        except BaseException as secondary:
            if cancellation_error(secondary):
                record['cancelled'] = True
            failure(secondary, 'cancellation_observation', name, True)
    finally:
        try:
            operations.finish()
        except BaseException as error:
            failure(error, 'scoped_port_finish', None, primary is not None)
            if cancellation_error(error):
                record['cancelled'] = True
            if primary is None:
                primary = error
    if primary is None:
        try:
            observe_cancel()
        except BaseException as error:
            primary = error
            if cancellation_error(error):
                record['cancelled'] = True
            failure(error, 'post_finish_cancellation_observation', None)
    if primary is None:
        need(len(record['packages']) == 93 and record['verified_count'] == 93, 'INCOMPLETE_INTERNAL_RESULT')
        record['status'] = 'REPORTED_COMPLETE_PENDING_ROOT_ADMISSION'
        record['terminal_state'] = 'RETURNED'
    else:
        record['status'] = 'CANCELLED' if record['cancelled'] else 'INCOMPLETE'
        record['terminal_state'] = 'INTERRUPTED' if record['cancelled'] else 'UNKNOWN'
    try:
        emit()
    except BaseException as error:
        failure(error, 'final_publication', None, primary is not None)
        if cancellation_error(error):
            record['cancelled'] = True
        record['status'] = 'CANCELLED' if record['cancelled'] else 'INCOMPLETE'
        record['terminal_state'] = 'INTERRUPTED' if record['cancelled'] else 'UNKNOWN'
        if primary is None:
            primary = error
        else:
            note(primary, 'SECONDARY_PUBLICATION_FAILURE:' + error_kind(error))
        # One best-effort failure publication, never an actor retry.
        try:
            emit()
        except BaseException as secondary:
            if cancellation_error(secondary):
                record['cancelled'] = True
                record['status'] = 'CANCELLED'
                record['terminal_state'] = 'INTERRUPTED'
            note(primary, 'FAILURE_PUBLICATION_UNAVAILABLE:' + error_kind(secondary))
    if primary is not None:
        note(primary, 'SEED93_TERMINAL:' + record['status'])
        raise primary
    return loads(canonical(record))
