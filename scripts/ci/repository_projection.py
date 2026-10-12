#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project one authoritative repository result field; retain every other field.

The caller must bind the receipt to its accepted image/source and run the result
through the unchanged generic exporter. This module neither filters credentials
from unknown fields nor changes signing command/log evidence.
"""
import copy
import importlib.util
import json
from pathlib import Path

PURPOSE = 'disposable-generic-repository-test'
LIMIT = 4 * 1024**2
CONTRACT_FIELDS = ('nonce', 'image_id', 'daemon_arch', 'script_sha256', 'upgrade_kind')
SPEC = importlib.util.spec_from_file_location('repository_inventory_validation', Path(__file__).with_name('lifecycle_inventory.py'))
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def validate_contract(value, contract):
    """Bind a parsed receipt to the caller's accepted generated manifest."""
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or value.get('purpose') != PURPOSE):
        raise ValueError('repository receipt requires known schema1/purpose')
    if not isinstance(contract, dict) or value.get('source_commit') != contract.get('source_commit'):
        raise ValueError('repository receipt source differs from accepted contract')
    if 'source_commit' not in contract or any(key not in contract for key in CONTRACT_FIELDS):
        raise ValueError('complete accepted repository contract required')
    observed = value.get('input_contract')
    expected = {key: contract[key] for key in CONTRACT_FIELDS}
    if not isinstance(observed, dict) or set(observed) != set(CONTRACT_FIELDS) or observed != expected:
        raise ValueError('repository receipt input contract differs from exact accepted manifest')


def project_result(value, base):
    """Return a deepcopy, transforming only known, complete base_versions maps.

    Other purposes and early failure receipts without base_versions are copied
    unchanged. A malformed present field under this purpose fails; it cannot be
    encoded into a permissive representation. Unknown fields always survive for
    the generic exporter's independent refusal checks.
    """
    if not isinstance(value, dict):
        raise ValueError('repository result must be a JSON object')
    result = copy.deepcopy(value)
    if result.get('purpose') != PURPOSE:
        return result
    if type(result.get('schema_version')) is not int or result['schema_version'] != 1:
        raise ValueError('repository projection requires exact known schema1')
    if 'base_versions' not in result:
        return result
    expected = inventory.validate_map(base)
    observed = inventory.validate_map(result['base_versions'])
    if observed != expected:
        raise ValueError('repository base inventory differs from complete accepted authority')
    result['base_versions'] = [{'name': name, 'version': observed[name]} for name in sorted(observed)]
    return result


def project(data, base, contract=None):
    """Parse bounded original bytes strictly, then return the projected object.

    Use this entry point rather than an ordinary json.loads call, which would
    discard duplicate-key evidence. Original bytes are never changed or hashed
    here; the caller may publish their hash/count only after this validation.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= LIMIT:
        raise ValueError('bounded nonempty repository result bytes required')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate repository result JSON key')
            result[key] = value
        return result

    def constant(_value):
        raise ValueError('nonfinite repository result JSON refused')

    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=constant)
        if contract is not None:
            validate_contract(value, contract)
        return project_result(value, base)
    except RecursionError:
        raise ValueError('repository result exceeds JSON nesting bound') from None
