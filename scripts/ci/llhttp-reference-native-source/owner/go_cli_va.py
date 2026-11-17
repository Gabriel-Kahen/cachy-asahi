# SPDX-License-Identifier: MIT
"""Finite address-space selection for the already-observed host Docker CLI only."""
import resource

NORMAL_AS=536870912
DOCKER_AS=2147483648
DECLARATION=dict(kind='OBSERVED_DOCKER_CLI_FINITE_VA_V1',normal_controller_AS_bytes=NORMAL_AS,
                 normal_child_AS_bytes=NORMAL_AS,docker_cli_AS_bytes=DOCKER_AS,
                 allowed_canonical_paths=['/usr/bin/docker','/usr/sbin/docker'],
                 executable_observation_required=True,physical_cgroup_limits_unchanged=True)

def need(ok,why):
    if not ok:raise ValueError(why)

def controller_limit(policy):
    need(policy.get('docker_cli_address_space')==DECLARATION and policy['controller']['AS_bytes']==NORMAL_AS,
         'exact separately reviewed finite Docker-only VA declaration')
    return NORMAL_AS,DOCKER_AS

def child_plan(argv,tools,policy):
    controller_limit(policy)
    need(type(argv)is list and argv and type(argv[0])is str and
         any(type(row)is dict and row.get('path')==argv[0] for row in tools.values()),
         'only existing observed absolute host executable')
    docker=tools.get('docker')
    selected=type(docker)is dict and argv[0]==docker.get('path')
    if selected:
        need(argv[0] in DECLARATION['allowed_canonical_paths'],'only exact observed canonical Docker executable gets Go VA')
    value=DOCKER_AS if selected else NORMAL_AS
    return dict(kind='GO_DOCKER_CLI' if selected else 'NORMAL_HOST_CHILD',soft_bytes=value,hard_bytes=value)

def child_limits(plan):
    need(plan in (dict(kind='GO_DOCKER_CLI',soft_bytes=DOCKER_AS,hard_bytes=DOCKER_AS),
                  dict(kind='NORMAL_HOST_CHILD',soft_bytes=NORMAL_AS,hard_bytes=NORMAL_AS)),
         'only two finite exact child AS plans')
    def apply():
        pair=plan['soft_bytes'],plan['hard_bytes']
        resource.setrlimit(resource.RLIMIT_AS,pair)
        need(resource.getrlimit(resource.RLIMIT_AS)==pair,'actual child finite AS limit must match before exec')
    return apply
