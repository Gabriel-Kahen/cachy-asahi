# SPDX-License-Identifier: MIT
"""Adapt the qualified Build Tools image actor and tools from frozen bytes."""

import hashlib
import re


ACTOR_SHA256 = "8a071d7755d2dd311550d096bfc0dd8183582b288a46ad46adef20c5ede813bd"
TOOLS_SHA256 = "2978acabbb2dce2e075e0bfb0f8515e15dccac1e39bc9fa5c3a8e1ac316d5f84"
RELEASE_COUNTS = {
    "0.1.1-2": (15, 11, 8, False),
    "0.2.0-2": (16, 12, 11, True),
}


def _read(raw, expected):
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("qualified predecessor actor or tools digest differs")
    return raw.decode("utf-8")


def _replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"expected one frozen Build Tools source seam: {old!r}")
    return text.replace(old, new, 1)


def _line(text, pattern):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"expected one frozen Build Tools source line: {pattern!r}")
    return matches[0]


def _counts(spec):
    counts = RELEASE_COUNTS[spec["version"]]
    names = spec["test_names"]
    if (spec["source_count"], spec["payload_count"], len(names), spec["consistency"]) != counts:
        raise ValueError("release counts differ from the reviewed Build Tools cases")
    if names != sorted(set(names)) or any(not re.fullmatch(r"test_[A-Za-z0-9_]+", name) for name in names):
        raise ValueError("expected exact sorted unique Build Tools test names")
    return counts


def adapt_actor(raw: bytes, spec: dict) -> bytes:
    """Bind the observed check log and native page size without moving lifecycle gates."""
    text = _read(raw, ACTOR_SHA256)
    _counts(spec)
    text = _replace(text, _line(text, r"^    expected=\['test_consistency_imports[^\n]*\]$"),
                    "    expected=list(T.TEST_NAMES)")
    seams = (
        ("len(rows)==len(set(rows))==11,'all eleven actual package checks exactly once and in order'",
         "len(rows)==len(set(rows))==len(expected),'all expected package checks exactly once and in order'"),
        ("r'^Ran 11 tests in ", "rf'^Ran {len(expected)} tests in "),
        ("'eleven positive tests without skip/failure'", "'positive package checks without skip or failure'"),
        ("tests=11,names=rows", "tests=len(rows),names=rows"),
        ("item['check_tests']=11;item['check_result']",
         "item['check_tests']=check['tests'];item['check_result']"),
        ("  policy,base=T.source_policy(source)",
         "  need(report['native']['page_bytes']==4096,'actual native 4 KiB image build stage required')\n"
         "  policy,base=T.source_policy(source)"),
        ("'17 payload paths initially absent'", "'all pinned payload paths initially absent'"),
    )
    for old, new in seams:
        text = _replace(text, old, new)
    return text.encode("utf-8")


def adapt_tools(raw: bytes, spec: dict) -> bytes:
    """Bind one release's recipe membership, check names and installed probe scope."""
    text = _read(raw, TOOLS_SHA256)
    source_count, payload_count, _, consistency = _counts(spec)
    names = spec["source_names"]
    if len(names) != source_count or names != sorted(set(names)):
        raise ValueError("expected sorted unique recipe source membership")
    observations, commands = (9, 6) if consistency else (6, 5)
    exact_names = "\n".join(f"    {name!r}," for name in names)
    exact_tests = "\n".join(f"    {name!r}," for name in spec["test_names"])
    text = _replace(text, _line(text, r"^SOURCE_FILES = frozenset\(\(.*\)\)$"),
                    f"SOURCE_FILES = frozenset((\n{exact_names}\n))\n"
                    f"TEST_NAMES = (\n{exact_tests}\n)\n"
                    f"PAYLOAD_COUNT = {payload_count}")
    seams = (
        ("VERSION = '0.2.0-1'", f"VERSION = {spec['version']!r}"),
        ("recipe['expected_test_count'] == 11 and type(recipe['expected_test_count']) is int",
         "recipe.get('version') == VERSION and recipe['expected_test_count'] == len(TEST_NAMES)\n"
         "         and type(recipe['expected_test_count']) is int and recipe.get('expected_test_names') == list(TEST_NAMES)"),
        ("len(recipe['payload_files']) == 12", "len(recipe['payload_files']) == PAYLOAD_COUNT"),
        ("'exact0.2.0 pinned check-inputs archive required'", "'exact pinned check-inputs archive required'"),
        ("'pinned 17-file package payload'", "'pinned finite package payload'"),
        ("bundle['members'] == 16", "bundle['members'] == len(SOURCE_FILES)"),
        ("'finite 13-member source delivery'", "'finite exact recipe source delivery'"),
        ("len(result) == 16, 'complete 13-file recipe bundle'",
         "len(result) == len(SOURCE_FILES), 'complete exact recipe bundle'"),
        ("'exact ALPM 17-file and ancestor directory ownership'",
         "'exact ALPM payload and ancestor directory ownership'"),
        ("dict(version=VERSION, count=12", "dict(version=VERSION, count=PAYLOAD_COUNT"),
        ("payload_files=12, base_inventory_count", "payload_files=PAYLOAD_COUNT, base_inventory_count"),
        ('"""Six actual offline commands; nine bounded observations, no namespace claim."""',
         '"""Run the release-pinned offline commands and bounded observations."""'),
        ("result['controls']==9 and result['commands_covered']==6,'all six commands/nine original observations'",
         f"result['controls']=={observations} and result['commands_covered']=={commands},"
         "'all release-specific commands and observations'"),
    )
    for old, new in seams:
        text = _replace(text, old, new)
    return text.encode("utf-8")
