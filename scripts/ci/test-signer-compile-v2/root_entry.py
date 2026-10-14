# SPDX-License-Identifier: MIT
"""Compile-only wiring for an independently selected Root Source loader/issuer.

No CLI or grant issuer. Root supplies closed loaded-unit/factory bindings after
reviewing their exact bytes. Checking raw bytes here does not authenticate an
arbitrary caller's loaded Python callbacks or confer permission on JSON.
"""
import hashlib
import json

class Refused(ValueError):pass

def need(value, code):
    if not value:raise Refused(code)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(raw):return hashlib.sha256(raw).hexdigest()

def run(*,units,raw_sources,manifest,manifest_sha256,observation,selection,
        selection_sha256,source_admission,expected_source_admission,
        compile_admission,expected_compile_admission,workspace_factory,
        expected_workspace_factory,runner_factory,expected_runner_factory,
        reobserve_factory,expected_reobserve_factory,sample,expected_sample,
        cancel,cancel_types,entry,outer_work_end,outer_cleanup_end):
    """Factories receive the original endpoints; they cannot refresh the frame.

    Root's workspace factory owns partial acquisitions until returning a fully
    owned Workspace. Its runner factory constructs the selected group backend
    without birth. Source admission binds this literal wiring, loaded units,
    both factories, sample/cancel, runtime and physical custody to the selected
    raw Source. Factory identity is a wiring guard, not an issuer.
    """
    need(type(source_admission) is object and source_admission is expected_source_admission,
         'Root-closed-loaded-Source-grant')
    need(type(compile_admission) is object and compile_admission is expected_compile_admission,
         'Root-compile-grant')
    need(digest(canonical(manifest))==manifest_sha256 and manifest['selected'] is False
         and manifest['execution_grant_issued'] is False,'external-Root-manifest')
    need(set(raw_sources)==set(manifest['source_rows']),'exact-raw-Source-set')
    for name,raw in raw_sources.items():
        row=manifest['source_rows'][name]
        need(type(raw) is bytes and len(raw)==row['bytes'] and digest(raw)==row['sha256'],
             'exact-raw-Source-bytes')
    need(set(units)=={'lane','inspection'},'closed-loaded-unit-set')
    for value,expected in ((workspace_factory,expected_workspace_factory),
                           (runner_factory,expected_runner_factory),
                           (reobserve_factory,expected_reobserve_factory),
                           (sample,expected_sample)):
        need(callable(value) and value is expected,'Root-selected-closed-callback')
    lane,inspection=units['lane'],units['inspection']
    work_end,cleanup_end=lane.frame(entry,outer_work_end,outer_cleanup_end)
    selected=lane.selected(observation,selection,selection_sha256,manifest_sha256,
                           compile_admission,expected_compile_admission)
    # Constructor verifies the complete observation and binds the original
    # endpoint before any workspace construction or command birth.
    reobserve=reobserve_factory(selected,observation,selection_sha256,
                                manifest_sha256,work_end)
    workspace=None;runner=None;handed_to_lane=False
    try:
        workspace=workspace_factory(work_end,cleanup_end)
        table=lane.commands(workspace,selected,sample)
        runner=runner_factory(table,entry,work_end,cleanup_end)
        sources={name:raw_sources[name] for name in
                 ('witness_shim.c','exec_filter.inc','thread_filter.inc','abi_layout.c')}
        rows={name:manifest['source_rows'][name] for name in sources}
        handed_to_lane=True
        return lane.execute(workspace=workspace,runner=runner,selection=selected,
            sources=sources,source_rows=rows,inspect_outputs=inspection.inspect_outputs,
            reobserve=reobserve,cancel=cancel,cancel_types=cancel_types,
            work_end=work_end,cleanup_end=cleanup_end)
    except BaseException as error:
        # Once execute starts, its finally owns runner/workspace retirement.
        # Pre-execute acquisition failures are retired here exactly once.
        cancelled=isinstance(error,cancel_types);cleanup_errors=[];retired=False
        # An unexpected escaping exception after transfer is uncertain. Root
        # retains its actual objects; this wrapper never repeats their cleanup.
        if not handed_to_lane:
            if runner is not None:
                try:
                    closed=runner.close()
                    cancelled|=closed['cancelled']
                    need(closed['first_cause'] is None and not closed['uncertain']
                         and not closed['cancelled'],'entry-runner-retirement')
                except BaseException as problem:
                    cleanup_errors.append(type(problem).__name__)
                    cancelled|=isinstance(problem,cancel_types)
            if workspace is not None:
                try:
                    retired=workspace.retire() is True
                    cancelled|=workspace.cancelled
                except BaseException as problem:
                    cleanup_errors.append(type(problem).__name__)
                    cancelled|=isinstance(problem,cancel_types)
        try:cancel()
        except BaseException as problem:
            cleanup_errors.append(type(problem).__name__)
            cancelled|=isinstance(problem,cancel_types)
        return dict(status='FAIL',first_cause='CANCELLED' if isinstance(error,cancel_types)
                    else 'ENTRY_PREPARATION_REFUSED',cancelled=cancelled,
                    uncertain=not retired or bool(cleanup_errors),owned_FDs_retired=retired,
                    cleanup_errors=cleanup_errors,cleanup_transferred=handed_to_lane,
                    shim_executed=False,ABI_helper_executed=False,GPG_executed=False)
