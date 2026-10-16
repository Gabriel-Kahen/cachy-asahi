#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source-selected link identities; actual87 selection is still empty."""
from collections import ChainMap
import posixpath

import aux_checkpoint as aux
import full_root as roots
import root_path

# Root fills these only after joining the complete actual list to held literal
# package/builder identities. No CLI/config input, wildcard, class or prefix grant.
CHAIN_PATHS = ()
LINK_NODES = {}
RESOLVED_ENDPOINTS = {}
DATA_ONLY_ENDPOINTS = {}


def _overrides(nodes):
    return {name:dict(nodes[name],target=posixpath.relpath(nodes[name]['target'].lstrip('/'),posixpath.dirname(name) or '.'))
            for name in LINK_NODES if nodes[name]['target'].startswith('/')}


def _data_endpoint(nodes,name):
    aux.need(nodes.get(name)==LINK_NODES[name] and nodes[name]['type']=='symlink','selected-data-link-drift')
    endpoint=roots.installer.resolve_nodes(ChainMap(_overrides(nodes),nodes),name)
    aux.need(endpoint==DATA_ONLY_ENDPOINTS[name] and endpoint not in nodes,'selected-data-endpoint-drift')
    roots.installer.relative(endpoint)
    parts=endpoint.split('/')
    for index in range(1,len(parts)):
        parent=nodes.get('/'.join(parts[:index]))
        aux.need(parent is None or parent['type']=='directory','selected-data-parent-shape')
    return endpoint


def check(observation,limits):
    """Validate the full bounded map, never the truncated public examples."""
    limits.tick(); nodes=observation['nodes']
    aux.need(observation.get('complete') is True and len(nodes)<=limits.max_nodes,'complete-link-observation')
    aux.need(type(CHAIN_PATHS) is tuple and CHAIN_PATHS==tuple(sorted(set(CHAIN_PATHS)))
             and len(LINK_NODES)<=4096 and set(CHAIN_PATHS)<=LINK_NODES.keys()
             and not (RESOLVED_ENDPOINTS.keys() & DATA_ONLY_ENDPOINTS.keys())
             and RESOLVED_ENDPOINTS.keys() | DATA_ONLY_ENDPOINTS.keys()==LINK_NODES.keys(),'finite-source-link-selection')
    for name,expected in LINK_NODES.items():
        limits.tick(); roots.installer.relative(name)
        aux.need(type(expected) is dict and expected.get('type')=='symlink' and nodes.get(name)==expected,'selected-literal-link-drift')
    actual=[]
    for name,node in nodes.items():
        limits.tick()
        if node.get('type')!='symlink': continue
        if node['target'].startswith('/'):
            aux.need(name in LINK_NODES,'unselected-absolute-link'); actual.append(name)
        else:
            try: roots.installer.resolve_nodes(nodes,name)
            except ValueError as error:
                aux.need(str(error)=='absolute payload link','unsupported-link-chain'); actual.append(name)
    aux.need(tuple(sorted(actual))==CHAIN_PATHS,'complete-absolute-chain-set-differs')
    expected_counts={'auxiliary-present':3}
    if actual: expected_counts['absolute-symlink']=len(actual)
    aux.need(observation['unsupported_counts']==expected_counts,'unselected-root-shape')
    for name,endpoint in RESOLVED_ENDPOINTS.items():
        limits.tick(); resolved,_trace=root_path.resolve(nodes,name,limits=limits)
        aux.need(resolved==endpoint and nodes[resolved]['type'] in ('file','directory'),'selected-link-endpoint-drift')
    for name in DATA_ONLY_ENDPOINTS:
        limits.tick(); _data_endpoint(nodes,name)
    return nodes


def view(observation,limits):
    """Private hardlink-validator view; preserve every literal in raw maps."""
    nodes=check(observation,limits)
    projected=dict(nodes); projected.update(_overrides(nodes)); projected.pop(aux.HELPER_NODE,None)
    return dict(observation,nodes=projected,eligible=True,unsupported_counts={})


def protection_endpoint(nodes,name,limits):
    # Data-only endpoints are names for protected-write comparison, never paths
    # granted to Reader, node(), archive extraction or helper execution.
    if name in DATA_ONLY_ENDPOINTS:
        for path,expected in LINK_NODES.items():
            limits.tick(); aux.need(nodes.get(path)==expected,'selected-literal-link-drift')
        return _data_endpoint(nodes,name)
    return root_path.resolve(nodes,name,limits=limits)[0]


def restore_literals(projected,seed):
    for name in LINK_NODES: projected[name]=seed[name]
    projected[aux.HELPER_NODE]=seed[aux.HELPER_NODE]
    return projected
