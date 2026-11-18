# SPDX-License-Identifier: MIT
"""Physical controller headroom for Python's existing native349 staging path."""
MIB = 1024**2
GIB = 1024*MIB
PREDECESSOR_CONTROLLER = dict(memory_bytes=512*MIB, AS_bytes=512*MIB, cpus=1, pids=64, swap_bytes=0)
CONTROLLER_MEMORY = GIB
HOST_AVAILABLE = 11*GIB
OWNER_MEMORY = 2*GIB
DAEMON_MEMORY = 6*GIB
BUILDER_MEMORY = 4*GIB
HOST_RESERVE = 2*GIB


def need(ok, why):
    if not ok:
        raise ValueError(why)


def physical_policy(policy, workflow, resources):
    """Verify the entire memory-accounting boundary and derive the reviewed successor."""
    need(policy['controller'] == PREDECESSOR_CONTROLLER
         and policy['owner']['memory_bytes'] == OWNER_MEMORY
         and policy['daemon']['memory_bytes'] == DAEMON_MEMORY
         and policy['host_reserve_bytes'] == HOST_RESERVE
         and policy['minimum_available_bytes'] == OWNER_MEMORY + DAEMON_MEMORY + HOST_RESERVE
         and resources['builder_memory_bytes'] == resources['builder_memory_swap_bytes'] == BUILDER_MEMORY
         and resources['host_reserve_bytes'] == HOST_RESERVE
         and policy['docker_cli_address_space']['normal_controller_AS_bytes'] == PREDECESSOR_CONTROLLER['AS_bytes'],
         'exact inherited controller AS, owner, daemon, inner builder and reserve budgets')
    memory_property = f'--property=MemoryMax={CONTROLLER_MEMORY} '.encode()
    need(workflow.count(memory_property)==workflow.count(b'--property=MemoryMax=')==1
         and workflow.count(b'--property=MemorySwapMax=0 --property=CPUQuota=100%')==1
         and workflow.count(b'--property=CPUQuotaPeriodSec=100ms --property=TasksMax=64 --property=RuntimeMaxSec=3540s')==1,
         'exact reviewed workflow scope, swap, CPU, PID and time limits')
    # The 4 GiB OCI builder belongs to the 6 GiB daemon domain.
    required = CONTROLLER_MEMORY + OWNER_MEMORY + DAEMON_MEMORY + HOST_RESERVE
    need(required == HOST_AVAILABLE, 'whole physical host memory budget')
    return dict(policy, controller=dict(PREDECESSOR_CONTROLLER, memory_bytes=CONTROLLER_MEMORY),
                minimum_available_bytes=required)
