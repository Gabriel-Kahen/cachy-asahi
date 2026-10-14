"""Root's pure completed-job gate. Artifact/log bytes alone grant no success."""
import json
import math


def need(ok, code):
    if not ok: raise ValueError(code)


def admit(raw, job, registration, *, contract, driver_sha256, worker_sha256):
    """Root supplies its actual GitHub job observation and registered Source.

    This is result admission, not the current-runtime operation that issues
    native grants. The known registered Source enforces the final post-write/
    flush/close original-J checks; a failed job can retain a complete candidate.
    """
    need(type(raw) is bytes and len(raw) <= 1024**2, 'completed-pair-record-bound')
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'completed-pair-duplicate-json'); out[key] = value
        return out
    record = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'completed-pair-nonfinite'))
    need(type(job) is dict and set(job) == {'repository', 'source_commit', 'workflow_commit', 'ref',
         'run_id', 'run_attempt', 'workflow_path', 'status', 'conclusion', 'invoke_conclusion'}, 'completed-job-observation')
    need(job['repository'] == 'Gabriel-Kahen/cachy-asahi' and job['status'] == 'completed' and
         job['conclusion'] == job['invoke_conclusion'] == 'success' and
         job['source_commit'] == job['workflow_commit'] == registration['source_commit'] and
         job['ref'] == registration['ref'] and job['workflow_path'] == '.github/workflows/maintained-composed-installer-v1.yml',
         'completed-job-required')
    need(record['status'] == 'PAIR_CHECKED_ROOT_JOB_COMPLETION_REQUIRED' and record['publication_allowed'] is False and
         record['registered_source'] == registration and record['scope'] == 'standalone-original501-topmem-fish-zsh-pairs' and
         record['composed_acceptance'] == 'NOT RUN', 'completed-pair-scope')
    start, E, J = record['original_start'], record['original_E'], record['original_J']
    need(all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in (start, E, J)) and
         J == start + 7200 and E == J - 360, 'completed-pair-original-clock')
    result = record['pair_result']; expected = result['job']
    need(expected['source_commit'] == expected['workflow_commit'] == job['source_commit'] and
         expected['run_id'] == job['run_id'] and expected['run_attempt'] == job['run_attempt'] and
         (expected['original_entry'], expected['workflow_end']) == (start, J), 'completed-pair-job')
    need(record['worker_source']['driver_sha256'] == driver_sha256 and
         record['worker_source']['worker_sha256'] == worker_sha256, 'completed-pair-worker-Source')
    contract.validate_result(result, expected)
    retirement = record['worker_retirement']; cleanup = record['root_cleanup']
    need(retirement['pidfd_used'] is True and retirement['direct_reaped'] is True and
         retirement['direct_proc_absent'] is True and retirement['session_absent'] is True and
         cleanup['nonce_resources_absent'] is True, 'completed-pair-owned-retirement')
    # No native/mapping flags are read as authority here. Success comes from
    # completed registered Source execution plus its bounded checked evidence.
    return dict(record, status='PAIR_PASS', publication_allowed=True,
                Root_completed_job_admission=True)
